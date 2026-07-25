#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..util.color import Color

import re


class WPSState:
    NONE, UNLOCKED, LOCKED, UNKNOWN = range(0, 4)


class Target(object):
    '''
        Holds details for a 'Target' aka Access Point (e.g. router).
    '''

    def __init__(self, fields):
        '''
            Initializes & stores target info based on fields.
            Args:
                Fields - List of strings
                INDEX KEY             EXAMPLE
                    0 BSSID           (00:1D:D5:9B:11:00)
                    1 First time seen (2015-05-27 19:28:43)
                    2 Last time seen  (2015-05-27 19:28:46)
                    3 channel         (6)
                    4 Speed           (54)
                    5 Privacy         (WPA2)
                    6 Cipher          (CCMP TKIP)
                    7 Authentication  (PSK)
                    8 Power           (-62)
                    9 beacons         (2)
                    10 # IV           (0)
                    11 LAN IP         (0.  0.  0.  0)
                    12 ID-length      (9)
                    13 ESSID          (HOME-ABCD)
                    14 Key            ()
        '''
        self.bssid      =     fields[0].strip()
        self.channel    =     fields[3].strip()

        self.encryption =     fields[5].strip()
        if 'WPA' in self.encryption:
            self.encryption = 'WPA'
        elif 'WEP' in self.encryption:
            self.encryption = 'WEP'
        if len(self.encryption) > 4:
            self.encryption = self.encryption[0:4].strip()

        # 保留原始认证/加密信息，用于 WPA3 SAE / Transition Mode 检测（2026 前沿）
        # airodump-ng 现代版 Authentication 列可能含 SAE / PSK / SAE+PSK
        try:
            self.auth_raw = fields[7].strip() if len(fields) > 7 else ''
        except Exception:
            self.auth_raw = ''
        try:
            self.privacy_raw = fields[5].strip() if len(fields) > 5 else ''
        except Exception:
            self.privacy_raw = ''

        self.power      = int(fields[8].strip())
        if self.power < 0:
            self.power += 100

        self.beacons    = int(fields[9].strip())
        self.ivs        = int(fields[10].strip())

        self.essid_known = True
        self.essid_len   = int(fields[12].strip())
        self.essid       =     fields[13]
        if self.essid == '\\x00' * self.essid_len or \
                self.essid == 'x00' * self.essid_len or \
                self.essid.strip() == '':
            # Don't display '\x00...' for hidden ESSIDs
            self.essid = None # '(%s)' % self.bssid
            self.essid_known = False

        self.wps = WPSState.UNKNOWN

        self.decloaked = False # If ESSID was hidden but we decloaked it.

        self.clients = []

        self.validate()

    def validate(self):
        ''' Checks that the target is valid. '''
        if self.channel == '-1':
            raise Exception('Ignoring target with Negative-One (-1) channel')

        # 扫描结果会进入文件名和外部工具参数，必须先验证完整 MAC 格式。
        bssid_pattern = re.compile(
            r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$',
            re.IGNORECASE,
        )
        if not bssid_pattern.fullmatch(self.bssid):
            raise ValueError('Ignoring target with Invalid BSSID (%s)' % self.bssid)

        if self.bssid.lower() in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
            raise ValueError('Ignoring target with Broadcast BSSID (%s)' % self.bssid)

        # 首字节最低位为 1 即组播地址，覆盖所有组播前缀。
        if int(self.bssid.split(':', 1)[0], 16) & 1:
            raise ValueError('Ignoring target with Multicast BSSID (%s)' % self.bssid)

    def is_wpa3_sae(self) -> bool:
        '''是否纯 WPA3-SAE（无 PSK），离线爆破不可行，仅在线爆破(Wacker)。'''
        raw = (self.auth_raw + ' ' + self.privacy_raw).upper()
        return 'SAE' in raw and 'PSK' not in raw

    def is_wpa3_transition(self) -> bool:
        '''是否 WPA3 Transition Mode（SAE+PSK 并存），可降级抓 WPA2 握手。

        前沿 PoC 检测: Dragonblood 降级攻击前提条件之一。
        仅检测、不攻击；MFP 状态需 Wireshark 进一步确认。
        '''
        raw = (self.auth_raw + ' ' + self.privacy_raw).upper()
        return 'SAE' in raw and 'PSK' in raw

    def to_str(self, show_bssid=False, essid_width=24):
        '''
            扫描表一行。ESSID 等列按终端显示宽度对齐（中文占 2 列）。
        '''
        from ..util.term_layout import pad

        raw = self.essid if self.essid_known else '(%s)' % self.bssid
        essid_plain = pad(raw, essid_width)
        if self.essid_known:
            essid = Color.s('{C}%s' % essid_plain)
        else:
            essid = Color.s('{O}%s' % essid_plain)
        if self.decloaked:
            essid += Color.s('{P}*{W}')
        else:
            essid += ' '

        bssid = Color.s('{O}%s{W}  ' % self.bssid) if show_bssid else ''

        try:
            ch_num = int(str(self.channel).strip() or '0')
        except ValueError:
            ch_num = 0
        channel_color = '{C}' if ch_num > 14 else '{G}'
        channel = Color.s('%s%s{W}' % (channel_color, pad(str(self.channel), 3, align='right')))

        enc_plain = pad(self.encryption[:4], 4)
        if 'WEP' in self.encryption:
            encryption = Color.s('{G}%s{W}' % enc_plain)
        elif 'WPA' in self.encryption:
            encryption = Color.s('{O}%s{W}' % enc_plain)
        else:
            encryption = Color.s('{W}%s{W}' % enc_plain)

        power_plain = pad('%sdb' % self.power, 5, align='right')
        if self.power > 50:
            pcolor = 'G'
        elif self.power > 35:
            pcolor = 'O'
        else:
            pcolor = 'R'
        power = Color.s('{%s}%s{W}' % (pcolor, power_plain))

        if self.wps == WPSState.UNLOCKED:
            wps = Color.s('{G}%s{W}' % pad('yes', 4))
        elif self.wps == WPSState.NONE:
            wps = Color.s('{O}%s{W}' % pad('no', 4))
        elif self.wps == WPSState.LOCKED:
            wps = Color.s('{R}%s{W}' % pad('lock', 4))
        else:
            wps = Color.s('{O}%s{W}' % pad('n/a', 4))

        n_clients = len(self.clients)
        if n_clients > 0:
            clients = Color.s('{G}%s{W}' % pad(str(n_clients), 4, align='right'))
        else:
            clients = pad('', 4)

        return '%s %s%s  %s  %s  %s  %s%s' % (
            essid, bssid, channel, encryption, power, wps, clients, Color.s('{W}'))


if __name__ == '__main__':
    fields = 'AA:BB:CC:DD:EE:FF,2015-05-27 19:28:44,2015-05-27 19:28:46,1,54,WPA2,CCMP TKIP,PSK,-58,2,0,0.0.0.0,9,HOME-ABCD,'.split(',')
    t = Target(fields)
    t.clients.append('asdf')
    t.clients.append('asdf')
    print(t.to_str())
