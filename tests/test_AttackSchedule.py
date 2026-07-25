#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from ck_wifikiller.attack.all import AttackAll
from ck_wifikiller.config import Configuration


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


if __name__ == '__main__':
    unittest.main()
