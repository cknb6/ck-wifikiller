#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch, MagicMock

from ck_wifikiller.config import Configuration
from ck_wifikiller.tools import deauth as deauth_mod
from ck_wifikiller.tools.scapy_deauth import ScapyDeauth


class TestScapyDeauth(unittest.TestCase):
    def test_invalid_mac_returns_zero(self):
        ScapyDeauth._checked = True
        ScapyDeauth._scapy = {'x': 1}  # pretend available
        with patch.object(Configuration, 'interface', 'wlan0mon', create=True):
            self.assertEqual(ScapyDeauth.deauth('not-a-mac'), 0)
            self.assertEqual(ScapyDeauth.deauth('AA:BB:CC:DD:EE:FF', client_mac='bad'), 0)

    def test_unavailable_returns_zero(self):
        ScapyDeauth._checked = True
        ScapyDeauth._scapy = None
        self.assertEqual(ScapyDeauth.deauth('AA:BB:CC:DD:EE:FF'), 0)

    def test_builds_and_sends_bidirectional(self):
        sent_calls = []

        def fake_sendp(pkt, iface=None, count=1, inter=0, verbose=0):
            sent_calls.append({'count': count, 'iface': iface})

        # Minimal fakes for scapy constructors
        class RT:
            def __truediv__(self, other):
                return other

        class D11:
            def __init__(self, **kw):
                self.kw = kw

            def __truediv__(self, other):
                return self

        ScapyDeauth._checked = True
        ScapyDeauth._scapy = {
            'RadioTap': RT,
            'Dot11': D11,
            'Dot11Deauth': lambda **k: 'deauth',
            'Dot11Disas': lambda **k: 'disas',
            'sendp': fake_sendp,
        }
        with patch.object(Configuration, 'interface', 'wlan0mon', create=True), \
                patch.object(Configuration, 'scapy_deauth_count', 8, create=True), \
                patch.object(Configuration, 'scapy_deauth_inter', 0.0, create=True):
            n = ScapyDeauth.deauth(
                'AA:BB:CC:DD:EE:FF',
                client_mac='11:22:33:44:55:66',
            )
        # 4 directions (2 deauth + 2 disas) * 8
        self.assertEqual(n, 32)
        self.assertEqual(len(sent_calls), 4)
        self.assertTrue(all(c['count'] == 8 for c in sent_calls))


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
                patch.object(ScapyDeauth, 'deauth', return_value=64) as sc, \
                patch('ck_wifikiller.tools.deauth.Aireplay.deauth') as ar:
            r = deauth_mod.send_deauth('AA:BB:CC:DD:EE:FF', client_mac='11:22:33:44:55:66')
        self.assertEqual(r['scapy'], 64)
        self.assertTrue(r['aireplay'])
        sc.assert_called_once()
        ar.assert_called_once()
        # scapy 已发时 aireplay 包数应被压低
        kwargs = ar.call_args
        n = kwargs.kwargs.get('num_deauths') if kwargs.kwargs else None
        if n is None and kwargs.args:
            # positional after bssid
            pass
        else:
            self.assertLessEqual(n, 4)

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
