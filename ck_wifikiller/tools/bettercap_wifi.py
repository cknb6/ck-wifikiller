#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bettercap WiFi 模块编排（第二选择的主动侦察/PMKID）

bettercap v2.41+ (2026): wifi.recon / wifi.assoc(PMKID) / deauth / handshakes
Kali: sudo apt install bettercap
文档: https://www.bettercap.org/modules/wifi/
"""

from __future__ import annotations

import os
import textwrap

from .dependency import Dependency
from ..util.color import Color
from ..config import Configuration


class BettercapWifi(Dependency):
    dependency_required = False
    dependency_name = 'bettercap'
    dependency_url = 'https://www.bettercap.org/'

    @classmethod
    def package_hint(cls) -> str:
        return 'sudo apt install -y bettercap'

    @classmethod
    def write_caplet(cls, path: str | None = None, iface: str | None = None) -> str:
        """生成 recon+PMKID 采集 caplet，供: sudo bettercap -iface wlan0 -caplet ck-wifi.cap"""
        iface = iface or Configuration.interface or 'wlan0'
        path = path or os.path.join(os.getcwd(), 'ck-wifi-recon.cap')
        body = textwrap.dedent(f'''\
            # ck-wifikiller bettercap recon caplet (authorized testing only)
            # Usage: sudo bettercap -iface {iface} -caplet {os.path.basename(path)}
            set wifi.clear-history true
            set wifi.handshakes.file ./ck-bettercap-handshakes.pcap
            set wifi.handshakes.aggregate true
            wifi.recon on
            # PMKID clientless association probes (all APs):
            # wifi.assoc all
            ticker on
            set ticker.period 5
            set ticker.commands "clear; wifi.show"
        ''')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(body)
        Color.pl('{+} bettercap caplet: {C}%s{W}' % path)
        Color.pl('{+} run: {C}sudo bettercap -iface %s -caplet %s{W}' % (iface, path))
        return path
