#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import unittest
from unittest.mock import patch

from ck_wifikiller.attack.all import AttackAll
from ck_wifikiller.config import Configuration
from ck_wifikiller.tools.hashcat import Hashcat


class TestAttackSchedule(unittest.TestCase):
    def test_path_mins_pmkid_60_others_45(self):
        names = ['pmkid', 'wps_pixie', 'wps_pin', 'handshake']
        with patch.object(Configuration, 'target_timeout', 100, create=True), \
                patch.object(Configuration, 'attack_min_slice', 45, create=True):
            slices = AttackAll._allocate_time_slices(names)
        by = dict(zip(names, slices))
        self.assertGreaterEqual(by['pmkid'], 60)
        self.assertGreaterEqual(by['wps_pixie'], 45)
        self.assertGreaterEqual(by['wps_pin'], 45)
        self.assertGreaterEqual(by['handshake'], 45)
        # 100 < 60+45*3 → 抬高到下限和
        self.assertEqual(sum(slices), 60 + 45 * 3)

    def test_expands_budget_when_needed(self):
        with patch.object(Configuration, 'target_timeout', 40, create=True), \
                patch.object(Configuration, 'attack_min_slice', 45, create=True):
            slices = AttackAll._allocate_time_slices(2)
        self.assertEqual(sum(slices), 90)
        self.assertTrue(all(s >= 45 for s in slices))

    def test_two_paths_split_equal_mins(self):
        with patch.object(Configuration, 'target_timeout', 90, create=True), \
                patch.object(Configuration, 'attack_min_slice', 45, create=True):
            slices = AttackAll._allocate_time_slices(2)
        self.assertEqual(slices, [45, 45])

    def test_weighted_paths_prefer_capture(self):
        names = ['pmkid', 'wps_pixie', 'wps_pin', 'handshake']
        with patch.object(Configuration, 'target_timeout', 210, create=True), \
                patch.object(Configuration, 'attack_min_slice', 45, create=True):
            slices = AttackAll._allocate_time_slices(names)
        self.assertEqual(len(slices), 4)
        self.assertEqual(sum(slices), 210)
        by = dict(zip(names, slices))
        self.assertGreaterEqual(by['pmkid'], 60)
        self.assertGreaterEqual(by['handshake'], by['wps_pin'])
        self.assertGreaterEqual(by['pmkid'], by['wps_pin'])

    def test_apply_timeouts_capture_full_slice(self):
        deadline = time.time() + 60
        AttackAll._apply_timeouts('pmkid', 60, deadline)
        self.assertEqual(Configuration.path_deadline, deadline)
        self.assertEqual(Configuration.pmkid_timeout, 60)
        self.assertEqual(Configuration.hashcat_runtime, 0)

        AttackAll._apply_timeouts('handshake', 45, deadline)
        self.assertEqual(Configuration.wpa_attack_timeout, 45)
        # 静默监听约 8~15s（默认 10），且必须短于捕获窗口
        self.assertLess(Configuration.wpa_deauth_listen, Configuration.wpa_attack_timeout)
        self.assertGreaterEqual(Configuration.wpa_deauth_listen, 6)
        self.assertLessEqual(Configuration.wpa_deauth_listen, 15)
        self.assertEqual(Configuration.wpa_deauth_timeout, Configuration.wpa_deauth_listen)

    def test_hashcat_runtime_from_deadline(self):
        Configuration.path_deadline = time.time() + 12
        Configuration.hashcat_runtime = 0
        rt = Hashcat._runtime_seconds()
        self.assertGreaterEqual(rt, 10)
        self.assertLessEqual(rt, 12)
        Configuration.path_deadline = None

    def test_hashcat_runtime_zero_when_expired(self):
        Configuration.path_deadline = time.time() - 2
        self.assertEqual(Hashcat._runtime_seconds(), 0)
        self.assertTrue(Hashcat.budget_exhausted())
        Configuration.path_deadline = None
        self.assertFalse(Hashcat.budget_exhausted())

    def test_hashcat_extra_includes_runtime(self):
        Configuration.path_deadline = time.time() + 8
        Configuration.hashcat_rules = None
        Configuration.hashcat_increment = False
        Configuration.hashcat_extra_args = None
        args = Hashcat._extra_attack_args(is_mask=False)
        self.assertIn('--runtime', args)
        idx = args.index('--runtime')
        self.assertGreater(int(args[idx + 1]), 0)
        Configuration.path_deadline = None

    def test_hashcat_extra_no_runtime_when_exhausted(self):
        Configuration.path_deadline = time.time() - 1
        Configuration.hashcat_rules = None
        Configuration.hashcat_increment = False
        Configuration.hashcat_extra_args = None
        args = Hashcat._extra_attack_args(is_mask=False)
        self.assertNotIn('--runtime', args)
        Configuration.path_deadline = None


if __name__ == '__main__':
    unittest.main()
