#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""捕获成功后：字典全量爆破放到独立终端/后台（类 airgeddon）。

主流程只负责抓 PMKID/握手；大字典不再被 path_deadline 截成 2~3% 就报「未命中」。
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Any

from ..config import Configuration
from ..util.color import Color
from ..util.i18n import t
from ..util.process import Process


class BgCrack(object):
    '''管理后台/新窗口爆破任务。'''

    jobs: list[dict[str, Any]] = []

    # 常见桌面终端（Kali），类似 airgeddon 开新窗
    _TERMINALS = (
        ('x-terminal-emulator', ['-e']),
        ('gnome-terminal', ['--']),
        ('xfce4-terminal', ['-e']),
        ('konsole', ['-e']),
        ('mate-terminal', ['-e']),
        ('lxterminal', ['-e']),
        ('qterminal', ['-e']),
        ('xterm', ['-e']),
    )

    @classmethod
    def enabled(cls) -> bool:
        return bool(getattr(Configuration, 'bg_crack', True))

    @classmethod
    def _safe_name(cls, s: str | None, fallback: str = 'ap') -> str:
        raw = re.sub(r'[^a-zA-Z0-9._-]+', '_', (s or fallback).strip())
        return (raw[:48] or fallback)

    @classmethod
    def _hs_dir(cls) -> str:
        d = Configuration.wpa_handshake_dir or 'hs'
        if not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        return d

    @classmethod
    def _find_terminal(cls) -> tuple[str, list[str]] | None:
        if not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY'):
            return None
        for name, args in cls._TERMINALS:
            path = shutil.which(name)
            if path:
                return path, list(args)
        return None

    @classmethod
    def _write_script(cls, path: str, body: str) -> None:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.chmod(path, 0o755)

    @classmethod
    def _launch(cls, script_path: str) -> dict[str, Any]:
        log = script_path + '.log'
        term = cls._find_terminal()
        env = os.environ.copy()
        meta: dict[str, Any] = {
            'script': script_path,
            'log': log,
            'pid': None,
            'mode': None,
            'started': time.time(),
        }
        if term:
            exe, args = term
            cmd = [exe] + args + ['bash', script_path]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    env=env,
                )
                meta['pid'] = proc.pid
                meta['mode'] = 'terminal:%s' % os.path.basename(exe)
                return meta
            except OSError:
                pass

        with open(log, 'ab') as logfh:
            proc = subprocess.Popen(
                ['bash', script_path],
                stdout=logfh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=env,
            )
        meta['pid'] = proc.pid
        meta['mode'] = 'nohup'
        return meta

    @classmethod
    def _hashcat_cmd(cls, hash_file: str, wordlist: str) -> str:
        parts = [
            'hashcat', '--quiet', '-m', '22000', '--self-test-disable',
            '-a', '0',
        ]
        try:
            from .hashcat import Hashcat
            if Hashcat.should_use_force():
                parts.append('--force')
        except Exception:
            parts.append('--force')
        # 故意不设 --runtime：全量字典
        rules = getattr(Configuration, 'hashcat_rules', None)
        if rules and os.path.isfile(rules):
            parts.extend(['-r', rules])
        parts.extend([hash_file, wordlist])
        return ' '.join(shlex.quote(p) for p in parts)

    @classmethod
    def _aircrack_cmd(cls, capfile: str, wordlist: str, bssid: str, key_file: str) -> str:
        parts = [
            'aircrack-ng', '-a', '2',
            '-w', wordlist,
            '--bssid', bssid,
            '-l', key_file,
            capfile,
        ]
        return ' '.join(shlex.quote(p) for p in parts)

    @classmethod
    def _script_body(
        cls,
        title: str,
        essid: str,
        bssid: str,
        hash_file: str | None,
        hashcat_line: str | None,
        aircrack_line: str | None,
        key_file: str,
        cracked_file: str,
    ) -> str:
        # 纯拼接，避免 bash ${} 与 str.format 花括号冲突
        parts: list[str] = [
            '#!/usr/bin/env bash\n',
            'set +e\n',
            'ESSID=%s\n' % shlex.quote(essid or ''),
            'BSSID=%s\n' % shlex.quote(bssid or ''),
            'KEY_FILE=%s\n' % shlex.quote(key_file),
            'CRACKED=%s\n' % shlex.quote(cracked_file),
            'echo "[+] ck-wifikiller bg crack: %s"\n' % shlex.quote(title),
            'echo "[+] ESSID=$ESSID  BSSID=$BSSID"\n',
            'echo "[+] full wordlist (no path slice / --runtime)"\n',
            'echo\n',
        ]
        if hashcat_line:
            parts.append('if command -v hashcat >/dev/null 2>&1; then\n')
            parts.append('  echo "[+] hashcat -m 22000 full dict ..."\n')
            parts.append('  %s\n' % hashcat_line)
            if hash_file:
                parts.append(
                    '  SHOW=$(hashcat --quiet -m 22000 --show %s 2>/dev/null | tail -n 1)\n'
                    % shlex.quote(hash_file)
                )
                parts.append(
                    '  if [ -n "$SHOW" ]; then\n'
                    '    KEY=${SHOW##*:}\n'
                    '    printf \'%s\\n\' "$KEY" > "$KEY_FILE"\n'
                    '    echo "[+] CRACKED: $KEY"\n'
                    '    printf \'%s\\t%s\\t%s\\thashcat\\n\' "$ESSID" "$BSSID" "$KEY" >> "$CRACKED"\n'
                    '  fi\n'
                )
            parts.append('fi\n')
        if aircrack_line:
            parts.append(
                'if [ ! -s "$KEY_FILE" ] && command -v aircrack-ng >/dev/null 2>&1; then\n'
                '  echo "[+] aircrack-ng fallback ..."\n'
            )
            parts.append('  %s\n' % aircrack_line)
            parts.append(
                '  if [ -s "$KEY_FILE" ]; then\n'
                '    KEY=$(cat "$KEY_FILE")\n'
                '    echo "[+] CRACKED: $KEY"\n'
                '    printf \'%s\\t%s\\t%s\\taircrack\\n\' "$ESSID" "$BSSID" "$KEY" >> "$CRACKED"\n'
                '  fi\n'
                'fi\n'
            )
        parts.append(
            'if [ -s "$KEY_FILE" ]; then\n'
            '  echo; echo "[+] done — key in $KEY_FILE"\n'
            'else\n'
            '  echo; echo "[!] not in wordlist (full pass finished)"\n'
            'fi\n'
            'if [ -t 0 ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then\n'
            '  echo; read -r -p "Press Enter to close..." _\n'
            'fi\n'
        )
        return ''.join(parts)

    @classmethod
    def spawn_handshake(cls, handshake, wordlist: str | None = None) -> dict[str, Any] | None:
        if not cls.enabled():
            return None
        wordlist = wordlist or Configuration.wordlist
        if not wordlist or not os.path.isfile(wordlist):
            Color.pl('{!} {O}%s{W}' % t('wpa.no_wordlist'))
            return None
        if not handshake or not getattr(handshake, 'capfile', None):
            return None
        if not os.path.isfile(handshake.capfile):
            return None

        from ..util.capture_select import (
            select_handshake_cap, is_valid_handshake_cap,
        )
        essid = getattr(handshake, 'essid', None) or 'unknown'
        bssid = getattr(handshake, 'bssid', None) or 'unknown'
        # 同 AP 多 cap：有效 + 最新
        best = select_handshake_cap(cls._hs_dir(), bssid, essid)
        if best:
            handshake.capfile = best
        if not is_valid_handshake_cap(handshake.capfile, bssid=bssid, essid=essid):
            Color.pl('{!} {R}%s{W}' % t('cap.invalid_no_crack'))
            return None

        hs_dir = cls._hs_dir()
        stamp = time.strftime('%Y%m%d-%H%M%S')
        tag = '%s_%s_%s' % (
            cls._safe_name(essid),
            cls._safe_name(bssid.replace(':', '')),
            stamp,
        )

        hash_file = os.path.join(hs_dir, 'bg_%s.hc22000' % tag)
        key_file = os.path.join(hs_dir, 'bg_%s.key' % tag)
        script_path = os.path.join(hs_dir, 'bg_%s.sh' % tag)
        cracked_file = os.path.abspath(Configuration.cracked_file or 'cracked.txt')

        hashcat_line = None
        if Process.exists('hashcat') and (
                Process.exists('hcxpcapngtool') or Process.exists('hcxpcaptool')):
            try:
                from .hashcat import HcxPcapTool
                tmp = HcxPcapTool.generate_hc22000_file(handshake.capfile)
                shutil.copy2(tmp, hash_file)
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
                    from ..util.capture_select import read_valid_hc22000_lines
                    valid_lines = read_valid_hc22000_lines(hash_file, want_bssid=bssid)
                    if not valid_lines:
                        Color.pl('{!} {R}%s{W}' % t('cap.invalid_no_crack'))
                        try:
                            os.remove(hash_file)
                        except OSError:
                            pass
                        hash_file = None
                    else:
                        with open(hash_file, 'w', encoding='utf-8') as fh:
                            fh.write('\n'.join(valid_lines) + '\n')
                        hashcat_line = cls._hashcat_cmd(hash_file, wordlist)
            except Exception as e:
                Color.pl('{!} {O}hc22000: %s{W}' % e)
                hash_file = None

        aircrack_line = None
        if Process.exists('aircrack-ng'):
            aircrack_line = cls._aircrack_cmd(
                handshake.capfile, wordlist, bssid, key_file)

        # 无有效 hc22000 时 aircrack 可作兜底，但 cap 必须已通过有效性检查
        if not hashcat_line and not aircrack_line:
            Color.pl('{!} {O}%s{W}' % t('bg.no_tool'))
            return None

        body = cls._script_body(
            title='WPA %s' % essid,
            essid=essid,
            bssid=bssid,
            hash_file=hash_file if hashcat_line else None,
            hashcat_line=hashcat_line,
            aircrack_line=aircrack_line,
            key_file=key_file,
            cracked_file=cracked_file,
        )
        cls._write_script(script_path, body)
        meta = cls._launch(script_path)
        meta.update({
            'kind': 'handshake',
            'essid': essid,
            'bssid': bssid,
            'hash_file': hash_file if hashcat_line else None,
            'capfile': handshake.capfile,
            'key_file': key_file,
            'wordlist': wordlist,
        })
        cls.jobs.append(meta)
        Color.pl('{+} {G}%s{W}' % t(
            'bg.spawned', essid, meta.get('mode') or '?', script_path))
        if meta.get('mode') == 'nohup':
            Color.pl('{+} {D}%s{W}' % t('bg.nohup_log', meta['log']))
        return meta

    @classmethod
    def spawn_pmkid(cls, pmkid_file: str, essid: str | None, bssid: str | None,
                    wordlist: str | None = None) -> dict[str, Any] | None:
        if not cls.enabled():
            return None
        wordlist = wordlist or Configuration.wordlist
        if not wordlist or not os.path.isfile(wordlist):
            Color.pl('{!} {O}%s{W}' % t('wpa.no_wordlist'))
            return None
        if not pmkid_file or not os.path.isfile(pmkid_file):
            return None
        if not Process.exists('hashcat'):
            Color.pl('{!} {O}%s{W}' % t('bg.no_tool'))
            return None

        from ..util.capture_select import (
            select_pmkid_file, is_valid_pmkid_file, read_valid_hc22000_lines,
        )
        hs_dir = cls._hs_dir()
        essid = essid or 'unknown'
        bssid = bssid or 'unknown'
        best = select_pmkid_file(hs_dir, bssid)
        if best:
            pmkid_file = best
        if not is_valid_pmkid_file(pmkid_file, want_bssid=bssid):
            Color.pl('{!} {R}%s{W}' % t('cap.invalid_no_crack'))
            return None

        stamp = time.strftime('%Y%m%d-%H%M%S')
        tag = 'pmkid_%s_%s_%s' % (
            cls._safe_name(essid),
            cls._safe_name(bssid.replace(':', '')),
            stamp,
        )
        hash_file = os.path.join(hs_dir, 'bg_%s.hc22000' % tag)
        valid_lines = read_valid_hc22000_lines(pmkid_file, want_bssid=bssid)
        if not valid_lines:
            Color.pl('{!} {R}%s{W}' % t('cap.invalid_no_crack'))
            return None
        with open(hash_file, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(valid_lines) + '\n')

        key_file = os.path.join(hs_dir, 'bg_%s.key' % tag)
        script_path = os.path.join(hs_dir, 'bg_%s.sh' % tag)
        cracked_file = os.path.abspath(Configuration.cracked_file or 'cracked.txt')
        hashcat_line = cls._hashcat_cmd(hash_file, wordlist)

        body = cls._script_body(
            title='PMKID %s' % essid,
            essid=essid,
            bssid=bssid,
            hash_file=hash_file,
            hashcat_line=hashcat_line,
            aircrack_line=None,
            key_file=key_file,
            cracked_file=cracked_file,
        )
        cls._write_script(script_path, body)
        meta = cls._launch(script_path)
        meta.update({
            'kind': 'pmkid',
            'essid': essid,
            'bssid': bssid,
            'hash_file': hash_file,
            'key_file': key_file,
            'wordlist': wordlist,
        })
        cls.jobs.append(meta)
        Color.pl('{+} {G}%s{W}' % t(
            'bg.spawned', essid, meta.get('mode') or '?', script_path))
        if meta.get('mode') == 'nohup':
            Color.pl('{+} {D}%s{W}' % t('bg.nohup_log', meta['log']))
        return meta

    @classmethod
    def potfile_check_handshake(cls, handshake) -> str | None:
        if not Process.exists('hashcat'):
            return None
        if not handshake or not getattr(handshake, 'capfile', None):
            return None
        try:
            from .hashcat import HcxPcapTool, Hashcat
            hc = HcxPcapTool.generate_hc22000_file(handshake.capfile)
            try:
                cmd = ['hashcat', '--quiet', '-m', '22000', '--show', hc]
                if Hashcat.should_use_force():
                    cmd.insert(-1, '--force')
                proc = Process(cmd)
                proc.wait()
                return Hashcat._extract_key(proc.stdout() or '')
            finally:
                try:
                    os.remove(hc)
                except OSError:
                    pass
        except Exception:
            return None

    @classmethod
    def potfile_check_pmkid(cls, pmkid_file: str) -> str | None:
        if not Process.exists('hashcat') or not pmkid_file:
            return None
        try:
            from .hashcat import Hashcat
            cmd = ['hashcat', '--quiet', '-m', '22000', '--show', pmkid_file]
            if Hashcat.should_use_force():
                cmd.insert(-1, '--force')
            proc = Process(cmd)
            proc.wait()
            return Hashcat._extract_key(proc.stdout() or '')
        except Exception:
            return None

    @classmethod
    def summarize(cls) -> None:
        if not cls.jobs:
            return
        Color.pl('\n{+} {C}%s{W}' % t('bg.summary', len(cls.jobs)))
        for j in cls.jobs:
            Color.pl('    {D}- {W}{C}%s{W} ({G}%s{W}) %s  {D}%s{W}' % (
                j.get('essid') or '?',
                j.get('kind') or '?',
                j.get('mode') or '?',
                j.get('log') or j.get('script') or '',
            ))
        Color.pl('{+} {D}%s{W}' % t('bg.summary_hint'))
