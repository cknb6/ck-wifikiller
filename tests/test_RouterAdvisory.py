#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from ck_wifikiller.util.router_advisory import (
    fingerprint_router,
    get_advisory,
    identify_vendor,
    normalize_oui,
)


class RouterAdvisoryTest(unittest.TestCase):
    def test_rejects_malformed_bssid(self):
        self.assertEqual(normalize_oui('AA:BB;touch /tmp/x'), '')
        self.assertIsNone(identify_vendor('not-a-bssid'))

    def test_reads_nmap_style_oui_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database = os.path.join(directory, 'nmap-mac-prefixes')
            with open(database, 'w', encoding='utf-8') as handle:
                handle.write('AABBCC New H3C Technologies Co., Ltd\n')
            self.assertEqual(
                identify_vendor('AA:BB:CC:00:11:22', [database]),
                'H3C',
            )

    def test_operator_ssid_is_not_device_vendor(self):
        result = fingerprint_router('AA:BB:CC:00:11:22', 'ChinaNet-ABCD')
        self.assertIsNone(result['vendor'])
        self.assertEqual(result['operator'], 'China Telecom')
        self.assertEqual(result['confidence'], 'low')

    def test_conflicting_evidence_is_reported(self):
        result = fingerprint_router('34:F7:16:00:11:22', 'HUAWEI-ABCD')
        self.assertTrue(result['conflict'])
        self.assertIsNone(result['vendor'])

    def test_advisory_is_attack_path_only(self):
        advisory = get_advisory('34:F7:16:00:11:22', 'TP-LINK_ABCD')
        self.assertEqual(advisory['vendor'], 'TP-Link')
        self.assertTrue(advisory.get('recommended_paths'))
        self.assertNotIn('audit_checks', advisory)


if __name__ == '__main__':
    unittest.main()
