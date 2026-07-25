#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashcat / hcxtools 封装 — 兼容 2024–2026 Kali

权威链路 (hashcat wiki + Kali hcxtools):
  hcxdumptool -i IFACE -w dump.pcapng [--bpf=filter.bpf] [-c CHa]
  hcxpcapngtool -o hash.hc22000 -E essid.list dump.pcapng
  hashcat -m 22000 hash.hc22000 wordlist

已废弃: -m 2500/.hccapx, -m 16800, 命令名 hcxpcaptool
"""

from __future__ import annotations

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import re
import shlex
import shutil
import subprocess
import tempfile


def _which_first(*names: str) -> str | None:
    for n in names:
        path = shutil.which(n)
        if path:
            return n
    return None


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'
    # 统一现代模式
    MODE_WPA = '22000'

    @staticmethod
    def should_use_force() -> bool:
        command = ['hashcat', '-I']
        try:
            process = Process(command)
            stdout, stderr = process.get_output()
            stdout = stdout or ''
            stderr = stderr or ''
            blob = stderr + stdout
            return 'No devices found/left' in blob or 'No devices found' in blob
        except Exception:
            return False

    @staticmethod
    def _extract_key(stdout: str) -> str | None:
        if not stdout or ':' not in stdout:
            return None
        # 22000 pot/show: hash:password 或 multi-field
        line = stdout.strip().splitlines()[-1]
        if ':' not in line:
            return None
        return line.rsplit(':', 1)[-1].strip() or None

    @staticmethod
    def _extra_attack_args(is_mask: bool = False) -> list[str]:
        """按攻击模式构建 hashcat 附加参数，避免组合无效选项。"""
        extra: list[str] = []
        rules = getattr(Configuration, 'hashcat_rules', None)
        if not is_mask and rules and os.path.isfile(rules):
            extra.extend(['-r', rules])

        # WPA/WPA2 口令最短 8 位；increment 只允许用于掩码模式 -a 3。
        if is_mask and getattr(Configuration, 'hashcat_increment', False):
            try:
                increment_max = int(getattr(Configuration, 'hashcat_increment_max', 8))
            except (TypeError, ValueError):
                increment_max = 8
            increment_max = max(8, increment_max)
            extra.append('--increment')
            extra.extend(['--increment-min', '8'])
            extra.extend(['--increment-max', str(increment_max)])

        raw = getattr(Configuration, 'hashcat_extra_args', None)
        if raw:
            if isinstance(raw, str):
                extra.extend(shlex.split(raw))
            else:
                extra.extend([str(x) for x in raw])
        return extra

    @staticmethod
    def crack_hc22000(hash_file: str, verbose: bool = False) -> str | None:
        """对 hashcat -m 22000 文件跑字典（握手+PMKID 通用）。

        2026 增强：支持 rules 变换、掩码爆破(-a 3)、增量、透传参数。
        """
        if Configuration.wordlist is None and Configuration.hashcat_mask is None:
            return None
        if not os.path.isfile(hash_file):
            return None

        mask = getattr(Configuration, 'hashcat_mask', None)

        # 两阶段：先字典(-a 0)，再掩码(-a 3)（若提供 mask）
        phases: list[tuple[list[str], bool]] = []
        if Configuration.wordlist is not None:
            phases.append((['-a', '0', hash_file, Configuration.wordlist], False))
        if mask:
            phases.append((['-a', '3', hash_file, mask], True))

        for base, is_mask in phases:
            for additional_arg in ([], ['--show']):
                command = [
                    'hashcat',
                    '--quiet',
                    '-m', Hashcat.MODE_WPA,
                    '--self-test-disable',
                ]
                command.extend(base)
                command.extend(Hashcat._extra_attack_args(is_mask=is_mask))
                if Hashcat.should_use_force():
                    command.append('--force')
                command.extend(additional_arg)
                if verbose and not additional_arg:
                    Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
                proc = Process(command)
                proc.wait()
                key = Hashcat._extract_key(proc.stdout() or '')
                if key:
                    return key
        return None

    @staticmethod
    def crack_hc22000_mask(hash_file: str, mask: str, verbose: bool = False) -> str | None:
        """对 hc22000 文件跑单个掩码爆破（-a 3），供国内优化管线复用。"""
        if not mask or not os.path.isfile(hash_file):
            return None
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat', '--quiet',
                '-m', Hashcat.MODE_WPA,
                '--self-test-disable',
                '-a', '3',
                hash_file, mask,
            ]
            command.extend(Hashcat._extra_attack_args(is_mask=True))
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and not additional_arg:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            proc = Process(command)
            proc.wait()
            key = Hashcat._extract_key(proc.stdout() or '')
            if key:
                return key
        return None

    @staticmethod
    def crack_handshake(handshake, show_command: bool = False) -> str | None:
        """cap/pcap/pcapng → hc22000 → hashcat -m 22000"""
        hc_file = HcxPcapTool.generate_hc22000_file(
            handshake.capfile, show_command=show_command)
        try:
            return Hashcat.crack_hc22000(hc_file, verbose=show_command)
        finally:
            if hc_file and os.path.exists(hc_file):
                try:
                    os.remove(hc_file)
                except OSError:
                    pass

    @staticmethod
    def crack_pmkid(pmkid_file: str, verbose: bool = False) -> str | None:
        """
        破解 PMKID/EAPOL 文本哈希。
        支持: *.hc22000 / *.22000 / 旧 *.16800（统一用 -m 22000 解析）。

        hashcat 6.x 已移除 -m 16800；旧 16800 星号格式需用 hcxpcapngtool
        从原始 pcapng 重新生成 .hc22000，这里不再尝试已废弃的模式。
        """
        path = pmkid_file
        if path.endswith('.16800'):
            Color.pl('{!} {O}检测到废弃的 .16800 格式，统一用 -m 22000 解析；'
                     '若失败请用 hcxpcapngtool 从原始 pcapng 重新生成 .hc22000{W}')
        return Hashcat.crack_hc22000(path, verbose=verbose)


class HcxDumpTool(Dependency):
    """
    现代 hcxdumptool (v6.3+ / Kali 2024+) 使用:
      -w dump.pcapng
      --bpf=filter.bpf  (旧 --filterlist 已移除)
      -c <channel>a     (如 6a)
    若探测到旧版 CLI，回退 --filterlist / -o。
    """
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, target, pcapng_file: str):
        self.target = target
        self.pcapng_file = pcapng_file
        if os.path.exists(pcapng_file):
            try:
                os.remove(pcapng_file)
            except OSError:
                pass

        iface = Configuration.interface
        bssid = target.bssid.replace(':', '').lower()
        bssid_colon = target.bssid.lower()
        ch = str(target.channel).strip()
        # 现代信道写法: 6 -> 6a (2.4G 默认 a)
        ch_arg = ch if ch.endswith(('a', 'b', 'c', 'd', 'e', 'f')) else f'{ch}a'

        help_out = ''
        try:
            help_out = Process(['hcxdumptool', '-h']).stdout() or ''
            help_out += Process(['hcxdumptool', '-h']).stderr() or ''
        except Exception:
            pass
        modern = ('--bpf' in help_out) or ('-w ' in help_out) or ('bpf=' in help_out.lower())

        command: list[str]
        if modern or _which_first('hcxdumptool'):
            # BPF: 目标 BSSID + 广播（保留 undirected probe，减少 hcxpcapngtool 警告）
            bpf_path = Configuration.temp(f'pmkid-{bssid}.bpf')
            bpf_ok = self._build_bpf(bpf_path, bssid_colon)
            command = [
                'hcxdumptool',
                '-i', iface,
                '-w', pcapng_file,
                '-c', ch_arg,
            ]
            if bpf_ok:
                command.extend(['--bpf', bpf_path])
            # 前沿高效捕获：收到 PMKID(1)+EAPOL M2(2)+M3(4) 任一即自动退出，
            # 避免冗余采集（hcxdumptool v6.0+ 官方推荐用法）。
            if '--exitoneapol' in help_out:
                command.extend(['--exitoneapol', '7'])
            # 旧版兼容探测
            if '--filterlist' in help_out and not bpf_ok:
                fl = Configuration.temp(f'pmkid-{bssid}.filterlist')
                with open(fl, 'w', encoding='utf-8') as fh:
                    fh.write(bssid + '\n')
                command = [
                    'hcxdumptool', '-i', iface,
                    '--filterlist', fl, '--filtermode', '2',
                    '-c', ch, '-o', pcapng_file,
                ]
        else:
            fl = Configuration.temp(f'pmkid-{bssid}.filterlist')
            with open(fl, 'w', encoding='utf-8') as fh:
                fh.write(bssid + '\n')
            command = [
                'hcxdumptool', '-i', iface,
                '--filterlist', fl, '--filtermode', '2',
                '-c', ch, '-o', pcapng_file,
            ]

        self.proc = Process(command)

    @staticmethod
    def _build_bpf(bpf_path: str, bssid_colon: str) -> bool:
        """优先 hcxdumptool --bpfc；失败则 tcpdump -ddd。"""
        expr = (
            f'wlan addr3 {bssid_colon} or wlan addr3 ff:ff:ff:ff:ff:ff'
        )
        # 内置编译器
        p = Process(['hcxdumptool', f'--bpfc={expr}'])
        p.wait()
        out = (p.stdout() or '') + (p.stderr() or '')
        # --bpfc 通常写 stdout
        if out.strip() and 'error' not in out.lower()[:80]:
            try:
                with open(bpf_path, 'w', encoding='utf-8') as f:
                    f.write(out if out.endswith('\n') else out + '\n')
                if os.path.getsize(bpf_path) > 4:
                    return True
            except OSError:
                pass
        # tcpdump 回退：参数数组执行 + Python 文件对象重定向，杜绝 shell 注入
        if shutil.which('tcpdump'):
            try:
                with open(bpf_path, 'w', encoding='utf-8') as fh:
                    subprocess.run(
                        ['tcpdump', '-s', '1024', '-y', 'IEEE802_11_RADIO',
                         expr, '-ddd'],
                        stdout=fh, stderr=subprocess.DEVNULL,
                        check=False,
                    )
                return os.path.isfile(bpf_path) and os.path.getsize(bpf_path) > 4
            except OSError:
                return False
        return False

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        self.proc.interrupt()


class HcxPcapTool(Dependency):
    """
    现代工具名: hcxpcapngtool（Kali 包 hcxtools）
    旧名 hcxpcaptool 仅作回退。
    """
    dependency_required = False
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.hash_file = Configuration.temp(f'pmkid-{self.bssid}.hc22000')

    @classmethod
    def exists(cls) -> bool:
        from ..util.process import Process
        return Process.exists('hcxpcapngtool') or Process.exists('hcxpcaptool')

    @classmethod
    def fails_dependency_check(cls) -> bool:
        from ..util.color import Color
        if cls.exists():
            return False
        Color.p('{!} {O}Warning: Recommended app {R}hcxpcapngtool{O} was not found')
        Color.pl('. {W}install @ {C}%s{W} (Kali: apt install hcxtools)' % cls.dependency_url)
        return False

    @staticmethod
    def _tool() -> str:
        return _which_first('hcxpcapngtool', 'hcxpcaptool') or 'hcxpcapngtool'

    @staticmethod
    def generate_hc22000_file(capfile: str, show_command: bool = False) -> str:
        """任意 cap/pcap/pcapng → hashcat -m 22000 文本。"""
        out = Configuration.temp('generated.hc22000')
        if os.path.exists(out):
            os.remove(out)
        tool = HcxPcapTool._tool()
        command = [tool, '-o', out, capfile]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(out) or os.path.getsize(out) == 0:
            raise ValueError(
                'Failed to generate hc22000 file with %s\n%s\n%s' % (tool, stdout, stderr)
            )
        return out

    # 旧 API 兼容名
    @staticmethod
    def generate_hccapx_file(handshake, show_command: bool = False) -> str:
        Color.pl('{!} {O}hccapx/2500 已废弃，自动改用 hc22000 / -m 22000{W}')
        return HcxPcapTool.generate_hc22000_file(handshake.capfile, show_command)

    @staticmethod
    def generate_john_file(handshake, show_command: bool = False) -> str:
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)
        tool = HcxPcapTool._tool()
        # 现代 hcxpcapngtool 用 --john=
        command = [tool, f'--john={john_file}', handshake.capfile]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            # 旧 -j
            command = [tool, '-j', john_file, handshake.capfile]
            process = Process(command)
            stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file: %s\n%s' % (stdout, stderr))
        return john_file

    def get_pmkid_hash(self, pcapng_file: str) -> str | None:
        """从 pcapng 提取匹配目标 BSSID 的 WPA*01* 或任意 WPA* 行。"""
        if not os.path.exists(pcapng_file):
            return None
        if os.path.exists(self.hash_file):
            try:
                os.remove(self.hash_file)
            except OSError:
                pass

        tool = HcxPcapTool._tool()
        command = [tool, '-o', self.hash_file, pcapng_file]
        proc = Process(command)
        proc.wait()

        if not os.path.exists(self.hash_file):
            return None

        matching = None
        try:
            with open(self.hash_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith('WPA*'):
                        continue
                    fields = line.split('*')
                    # WPA*01*pmkid*macap*macclient*essid...
                    if len(fields) >= 5 and fields[3].lower() == self.bssid:
                        matching = line
                        break
                    if len(fields) >= 4 and fields[2].lower() == self.bssid:
                        # 极旧格式容错
                        matching = line
                        break
        finally:
            try:
                os.remove(self.hash_file)
            except OSError:
                pass
        return matching
