#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全与健壮性回归：路径穿越、deauth 客户端 MAC、cracked 文件损坏等。"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ck_wifikiller.config import Configuration
from ck_wifikiller.model.result import CrackResult
from ck_wifikiller.tools.airodump import Airodump
from ck_wifikiller.util.process import Process
from ck_wifikiller.util.validate import (
    is_mac_address,
    is_safe_channel,
    is_safe_iface,
)


class TestValidate(unittest.TestCase):
    def test_iface_rejects_path_traversal(self):
        for bad in ('../etc', 'wlan0/../lo', 'wlan0;id', 'wlan0 mon', '/wlan0', ''):
            with self.subTest(iface=bad):
                self.assertFalse(is_safe_iface(bad))

    def test_iface_accepts_normal_names(self):
        for good in ('wlan0', 'wlan0mon', 'wlp3s0', 'wlx00c0ca'):
            with self.subTest(iface=good):
                self.assertTrue(is_safe_iface(good))

    def test_channel_bounds(self):
        self.assertTrue(is_safe_channel(1))
        self.assertTrue(is_safe_channel(36))
        self.assertTrue(is_safe_channel(196))
        self.assertFalse(is_safe_channel(0))
        self.assertFalse(is_safe_channel(300))
        self.assertFalse(is_safe_channel('6;rm'))

    def test_mac_format(self):
        self.assertTrue(is_mac_address('AA:BB:CC:DD:EE:FF'))
        self.assertFalse(is_mac_address('AA:BB:CC:DD:EE'))
        self.assertFalse(is_mac_address('AA-BB-CC-DD-EE-FF'))


class TestTempPathSafety(unittest.TestCase):
    def setUp(self):
        Configuration.temp_dir = None

    def tearDown(self):
        Configuration.delete_temp()

    def test_temp_strips_directory_components(self):
        path = Configuration.temp('../../etc/passwd')
        self.assertTrue(path.startswith(Configuration.temp_dir))
        self.assertEqual(os.path.basename(path), 'passwd')
        self.assertNotIn('..', path)

    def test_delete_temp_removes_tree(self):
        base = Configuration.temp()
        nested = os.path.join(base, 'sub')
        os.makedirs(nested, exist_ok=True)
        with open(os.path.join(nested, 'x.txt'), 'w') as fh:
            fh.write('x')
        Configuration.delete_temp()
        self.assertFalse(os.path.exists(base.rstrip(os.sep)))


class TestDeauthUsesStationMac(unittest.TestCase):
    def test_decloak_deauth_targets_client_station(self):
        '''隐藏 SSID deauth 必须打 station MAC，不能打 AP BSSID。'''
        calls = []

        def fake_send_deauth(bssid, client_mac=None, essid=None, timeout=2):
            calls.append({'bssid': bssid, 'client': client_mac})
            return {'scapy': 0, 'aireplay': True}

        target = SimpleNamespace(
            bssid='AA:BB:CC:DD:EE:FE',
            essid_known=False,
            clients=[
                SimpleNamespace(station='11:22:33:44:55:66', bssid='AA:BB:CC:DD:EE:FE'),
            ],
        )
        dump = object.__new__(Airodump)
        dump.targets = [target]
        dump.channel = 6
        dump.decloaking = False
        dump.decloaked_times = {}

        with patch.object(Configuration, 'no_deauth', False, create=True), \
                patch.object(Configuration, 'interface', 'wlan0mon', create=True), \
                patch.object(Configuration, 'verbose', 0, create=True), \
                patch('ck_wifikiller.tools.deauth.send_deauth', fake_send_deauth), \
                patch('ck_wifikiller.tools.airodump.time.time', return_value=1000):
            dump.deauth_hidden_targets()

        self.assertGreaterEqual(len(calls), 2)
        # 广播 + 客户端
        clients = [c['client'] for c in calls if c['client']]
        self.assertIn('11:22:33:44:55:66', clients)
        self.assertNotIn(target.bssid, clients)


class TestCrackResultRobustness(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix='ck-crack-')
        self._path = os.path.join(self._tmpdir, 'cracked.txt')
        self._had = hasattr(Configuration, 'cracked_file')
        self._old = getattr(Configuration, 'cracked_file', None)
        Configuration.cracked_file = self._path

    def tearDown(self):
        if self._had:
            Configuration.cracked_file = self._old
        elif hasattr(Configuration, 'cracked_file'):
            delattr(Configuration, 'cracked_file')
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_load_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            CrackResult.load({'type': 'NOPE', 'date': 1})

    def test_read_results_ignores_non_list(self):
        with open(self._path, 'w') as fh:
            fh.write('{"not":"a list"}')
        self.assertEqual(CrackResult._read_results_list(self._path), [])

    def test_read_results_ignores_malformed_json(self):
        with open(self._path, 'w') as fh:
            fh.write('{broken')
        self.assertEqual(CrackResult._read_results_list(self._path), [])


class TestProcessDevnull(unittest.TestCase):
    def test_devnull_is_subprocess_constant(self):
        from subprocess import DEVNULL
        self.assertIs(Process.devnull(), DEVNULL)


if __name__ == '__main__':
    unittest.main()
