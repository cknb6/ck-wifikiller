#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from ck_wifikiller.util.region import (
    detect_timezone,
    is_mainland_china_timezone,
    normalize_timezone,
    resolve_cn_mode,
)


class RegionTest(unittest.TestCase):
    def test_normalize_zoneinfo_path(self):
        self.assertEqual(
            normalize_timezone('/usr/share/zoneinfo/Asia/Shanghai'),
            'Asia/Shanghai',
        )

    def test_cn_timezone_does_not_use_utc_offset(self):
        self.assertTrue(is_mainland_china_timezone('Asia/Shanghai'))
        self.assertTrue(is_mainland_china_timezone('Asia/Urumqi'))
        self.assertFalse(is_mainland_china_timezone('Asia/Singapore'))
        self.assertFalse(is_mainland_china_timezone('CST'))
        self.assertFalse(is_mainland_china_timezone('+08:00'))

    def test_cli_override_wins(self):
        self.assertEqual(resolve_cn_mode(False, {'CK_WIFI_REGION': 'cn'}), (False, 'cli'))
        self.assertEqual(resolve_cn_mode(True, {'CK_WIFI_REGION': 'global'}), (True, 'cli'))

    def test_environment_override_and_auto(self):
        self.assertEqual(resolve_cn_mode(None, {'CK_WIFI_REGION': 'cn'}),
                         (True, 'CK_WIFI_REGION'))
        self.assertEqual(resolve_cn_mode(None, {'CK_WIFI_REGION': 'global'}),
                         (False, 'CK_WIFI_REGION'))
        enabled, source = resolve_cn_mode(
            None,
            {'CK_WIFI_REGION': 'auto', 'TZ': 'Asia/Shanghai'},
        )
        self.assertTrue(enabled)
        self.assertIn('Asia/Shanghai', source)

    def test_detect_timezone_file(self):
        with tempfile.TemporaryDirectory() as directory:
            timezone_file = os.path.join(directory, 'timezone')
            with open(timezone_file, 'w', encoding='utf-8') as handle:
                handle.write('Asia/Shanghai\n')
            zone, source = detect_timezone(
                environ={},
                timezone_file=timezone_file,
                localtime_path=os.path.join(directory, 'missing'),
                tzinfo='UTC',
            )
        self.assertEqual(zone, 'Asia/Shanghai')
        self.assertEqual(source, timezone_file)


if __name__ == '__main__':
    unittest.main()
