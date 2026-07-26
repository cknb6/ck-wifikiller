#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import unittest
from unittest.mock import patch

from ck_wifikiller.attack.all import AttackAll
from ck_wifikiller.config import Configuration
from ck_wifikiller.tools.hashcat import Hashcat


class TestAttackSchedule(unittest.TestCase):
    def test_min_slice_at_least_15(self):
        with patch.object(Configuration, 'target_timeout', 60, create=True), \
                patch.object(Configuration, 'attack_min_slice', 15, create=True):
            slices = AttackAll._allocate_time_slices(4)
        self.assertEqual(len(slices), 4)
        self.assertTrue(all(s >= 15 for s in slices))
        self.assertEqual(sum(slices), 60)

    def test_expands_budget_when_needed(self):
        with patch.object(Configuration, 'target_timeout', 40, create=True), \
                patch.object(Configuration, 'attack_min_slice', 15, create=True):
            slices = AttackAll._allocate_time_slices(4)
        # 4*15=60 > 40 → 抬高
        self.assertEqual(sum(slices), 60)
        self.assertTrue(all(s >= 15 for s in slices))

    def test_two_paths_split_60(self):
        with patch.object(Configuration, 'target_timeout', 60, create=True), \
                patch.object(Configuration, 'attack_min_slice', 15, create=True):
            slices = AttackAll._allocate_time_slices(2)
        self.assertEqual(slices, [30, 30])

    def test_apply_timeouts_sets_path_deadline_and_runtime(self):
        deadline = time.time() + 30
        AttackAll._apply_timeouts('pmkid', 30, deadline)
        self.assertEqual(Configuration.path_deadline, deadline)
        self.assertGreater(Configuration.hashcat_runtime, 0)
        self.assertLessEqual(Configuration.pmkid_timeout, 30)
        # 爆破预算 + 捕获 <= 切片
        self.assertLessEqual(
            Configuration.pmkid_timeout + Configuration.hashcat_runtime, 30)

    def test_hashcat_runtime_from_deadline(self):
        Configuration.path_deadline = time.time() + 12
        Configuration.hashcat_runtime = 0
        rt = Hashcat._runtime_seconds()
        self.assertGreaterEqual(rt, 10)
        self.assertLessEqual(rt, 12)
        Configuration.path_deadline = None

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


if __name__ == '__main__':
    unittest.main()
