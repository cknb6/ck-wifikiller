#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from ck_wifikiller.config import Configuration
from ck_wifikiller.tools import deauth as deauth_mod
from ck_wifikiller.tools.scapy_deauth import ScapyDeauth


class TestScapyDeauth(unittest.TestCase):
    def tearDown(self):
        ScapyDeauth._checked = False
        ScapyDeauth._scapy = None

    def test_invalid_mac_returns_zero(self):
        ScapyDeauth._checked = True
        ScapyDeauth._scapy = {'x': 1}
        with patch.object(Configuration, 'interface', 'wlan0mon', create=True):
            self.assertEqual(ScapyDeauth.deauth('not-a-mac'), 0)
            self.assertEqual(
                ScapyDeauth.deauth('AA:BB:CC:DD:EE:FF', client_mac='bad'), 0)

    def test_unavailable_returns_zero(self):
        ScapyDeauth._checked = True
        ScapyDeauth._scapy = None
        self.assertEqual(ScapyDeauth.deauth('AA:BB:CC:DD:EE:FF'), 0)

    def test_burst_layout_matches_auto_attack(self):
        '''精准 4×16=64；广播 2×32=64；reason 分向。'''
        class RT:
            def __truediv__(self, other):
                return other

        class D11:
            def __init__(self, **kw):
                self.kw = kw

            def __truediv__(self, other):
                other._dot11 = self
                return other

        class Deauth:
            def __init__(self, reason=0):
                self.reason = reason
                self.kind = 'deauth'

        class Disas:
            def __init__(self, reason=0):
                self.reason = reason
                self.kind = 'disas'

        ScapyDeauth._checked = True
        ScapyDeauth._scapy = {
            'RadioTap': RT,
            'Dot11': D11,
            'Dot11Deauth': Deauth,
            'Dot11Disas': Disas,
            'sendp': lambda *a, **k: None,
        }

        burst = ScapyDeauth.build_burst(
            'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66', 16)
        self.assertEqual(len(burst), 64)
        # 前 16 deauth reason7, 次 16 deauth reason1, 后 32 disas reason8
        self.assertTrue(all(getattr(p, 'reason', None) == 7 for p in burst[:16]))
        self.assertTrue(all(getattr(p, 'reason', None) == 1 for p in burst[16:32]))
        self.assertTrue(all(getattr(p, 'reason', None) == 8 for p in burst[32:]))

        bc = ScapyDeauth.build_burst('aa:bb:cc:dd:ee:ff', None, 32)
        self.assertEqual(len(bc), 64)
        self.assertTrue(all(getattr(p, 'reason', None) == 7 for p in bc[:32]))
        self.assertTrue(all(getattr(p, 'reason', None) == 8 for p in bc[32:]))

    def test_sendp_burst_rounds(self):
        sent = []

        def fake_sendp(burst, iface=None, inter=0, verbose=0, **kw):
            sent.append({
                'n': len(burst) if hasattr(burst, '__len__') else 1,
                'iface': iface,
                'inter': inter,
            })

        class RT:
            def __truediv__(self, other):
                return other

        class D11:
            def __init__(self, **kw):
                pass

            def __truediv__(self, other):
                return other

        ScapyDeauth._checked = True
        ScapyDeauth._scapy = {
            'RadioTap': RT,
            'Dot11': D11,
            'Dot11Deauth': lambda **k: object(),
            'Dot11Disas': lambda **k: object(),
            'sendp': fake_sendp,
        }
        with patch.object(Configuration, 'interface', 'wlan0mon', create=True), \
                patch.object(Configuration, 'scapy_deauth_count', 0, create=True), \
                patch.object(Configuration, 'scapy_deauth_rounds', 4, create=True), \
                patch.object(Configuration, 'scapy_deauth_inter', 0.003, create=True):
            n = ScapyDeauth.deauth(
                'AA:BB:CC:DD:EE:FF',
                client_mac='11:22:33:44:55:66',
            )
        # 默认精准每向 64 → 4 向 × 64 = 256 帧/轮；4 轮 → 1024 帧
        self.assertEqual(n, 1024)
        self.assertEqual(len(sent), 4)
        self.assertTrue(all(s['n'] == 256 and s['inter'] == 0.003 for s in sent))


class TestDeauthEngine(unittest.TestCase):
    def setUp(self):
        Configuration.no_deauth = False
        Configuration.deauth_engine = 'auto'
        Configuration.num_deauths = 8
        Configuration.interface = 'wlan0mon'

    def test_no_deauth_skips(self):
        Configuration.no_deauth = True
        r = deauth_mod.send_deauth('AA:BB:CC:DD:EE:FF')
        self.assertTrue(r.get('skipped'))

    def test_auto_uses_scapy_then_aireplay(self):
        Configuration.deauth_engine = 'auto'
        with patch.object(ScapyDeauth, 'available', return_value=True), \
                patch.object(ScapyDeauth, 'deauth', return_value=256) as sc, \
                patch('ck_wifikiller.tools.deauth.Aireplay.deauth') as ar, \
                patch('ck_wifikiller.tools.deauth.get_deauth_profile') as gp:
            from ck_wifikiller.tools.nic_profile import DeauthProfile
            gp.return_value = DeauthProfile(
                name='test', engine='both', per_dir=0, rounds=4, inter=0.003,
                aireplay_count=16, aireplay_after_scapy=True, note='t')
            r = deauth_mod.send_deauth(
                'AA:BB:CC:DD:EE:FF', client_mac='11:22:33:44:55:66')
        self.assertEqual(r['scapy'], 256)
        self.assertTrue(r['aireplay'])
        sc.assert_called_once()
        ar.assert_called_once()
        # Scapy 成功后 aireplay 补刀：按 profile.aireplay_count 满包数
        n = ar.call_args.kwargs.get('num_deauths')
        if n is not None:
            self.assertEqual(n, 16)

    def test_aireplay_only(self):
        Configuration.deauth_engine = 'aireplay'
        with patch.object(ScapyDeauth, 'available', return_value=True), \
                patch.object(ScapyDeauth, 'deauth') as sc, \
                patch('ck_wifikiller.tools.deauth.Aireplay.deauth') as ar:
            r = deauth_mod.send_deauth('AA:BB:CC:DD:EE:FF')
        sc.assert_not_called()
        ar.assert_called_once()
        self.assertTrue(r['aireplay'])
        self.assertEqual(r['scapy'], 0)


if __name__ == '__main__':
    unittest.main()
