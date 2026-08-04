#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""--recon clients 扫描报告测试：排序、行格式、OUI 厂商、报告落盘。"""

import os
import tempfile
import unittest
from unittest.mock import patch

from ck_wifikiller.model.client import Client
from ck_wifikiller.model.target import Target
from ck_wifikiller.recon.clients import ClientsScan, _client_vendor, _strip_tags


def _mk_target(bssid, essid='TestWifi', clients=0, power='-58'):
    """构造带 clients 的 Target。"""
    fields = [
        bssid, '2015-05-27 19:28:44', '2015-05-27 19:28:46',
        '6', '54', 'WPA2', 'CCMP', 'PSK', power, '2', '0',
        '0.0.0.0', '8', essid, '',
    ]
    target = Target(fields)
    target.clients = [
        Client(['AA:BB:CC:DD:EE:%02X' % (i + 1), 't1', 't2', '-60', '2', bssid, 'X'])
        for i in range(clients)
    ]
    return target


class TestClientsScanSort(unittest.TestCase):
    def test_online_aps_first_desc(self):
        scan = ClientsScan(scan_time=3)
        two = _mk_target('AA:BB:CC:DD:EE:01', clients=2)
        one = _mk_target('AA:BB:CC:DD:EE:02', clients=1)
        idle = _mk_target('AA:BB:CC:DD:EE:03', clients=0)
        scan.targets = [idle, one, two]
        online, rest = scan._targets_sorted()
        self.assertEqual(online, [two, one])
        self.assertEqual(rest, [idle])

    def test_ap_row_contains_bssid_and_clients(self):
        scan = ClientsScan(scan_time=3)
        target = _mk_target('AA:BB:CC:DD:EE:01', clients=3)
        row = scan._ap_row(1, target)
        self.assertIn('AA:BB:CC:DD:EE:01', row)
        self.assertIn('3', row)
        self.assertIn('TestWifi', row)


class TestClientVendor(unittest.TestCase):
    def test_brand_normalized_vendor(self):
        with patch('ck_wifikiller.recon.clients.identify_vendor', return_value='Xiaomi'):
            self.assertEqual(_client_vendor('AA:BB:CC:DD:EE:FF'), 'Xiaomi')

    def test_oui_raw_fallback(self):
        with patch('ck_wifikiller.recon.clients.identify_vendor', return_value=None), \
             patch('ck_wifikiller.recon.clients._load_oui_database',
                   return_value={'aabbcc': 'Apple, Inc.'}):
            self.assertEqual(_client_vendor('AA:BB:CC:DD:EE:FF'), 'Apple, Inc.')

    def test_unknown_returns_none(self):
        with patch('ck_wifikiller.recon.clients.identify_vendor', return_value=None), \
             patch('ck_wifikiller.recon.clients._load_oui_database', return_value={}):
            self.assertIsNone(_client_vendor('AA:BB:CC:DD:EE:FF'))

    def test_invalid_mac_returns_none(self):
        self.assertIsNone(_client_vendor('not-a-mac'))


class TestClientsReportFile(unittest.TestCase):
    def test_report_writes_plain_text(self):
        scan = ClientsScan(scan_time=3)
        scan.targets = [
            _mk_target('AA:BB:CC:DD:EE:01', clients=1),
            _mk_target('AA:BB:CC:DD:EE:02', clients=0),
        ]
        with tempfile.TemporaryDirectory() as d:
            with patch('ck_wifikiller.recon.clients.os.getcwd', return_value=d):
                scan._report()
            path = os.path.join(d, ClientsScan.REPORT_NAME)
            self.assertTrue(os.path.exists(path))
            with open(path, encoding='utf-8') as f:
                content = f.read()
            self.assertIn('AA:BB:CC:DD:EE:01', content)
            # 纯文本：不含颜色标记
            self.assertNotIn('{G}', content)


class TestStripTags(unittest.TestCase):
    def test_strip_tags_removes_color_codes(self):
        line = '{G}hello{W} {C}world{W}'
        self.assertEqual(_strip_tags(line), 'hello world')


if __name__ == '__main__':
    unittest.main()
