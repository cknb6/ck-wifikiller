#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from types import SimpleNamespace

from ck_wifikiller.util.scanner import Scanner


class TestScannerRefreshMath(unittest.TestCase):
    '''就地刷新：上移行数 = 表行 + 状态行。'''

    def test_cursor_up_includes_status(self):
        s = Scanner.__new__(Scanner)
        s._printed_rows = 2 + 10  # header+sep+10 targets
        s._has_status = True
        lines_up = s._printed_rows + (1 if s._has_status else 0)
        self.assertEqual(lines_up, 13)

    def test_cursor_up_no_status(self):
        s = Scanner.__new__(Scanner)
        s._printed_rows = 2 + 5
        s._has_status = False
        lines_up = s._printed_rows + (1 if s._has_status else 0)
        self.assertEqual(lines_up, 7)


class TestTargetSelectParse(unittest.TestCase):
    def setUp(self):
        self.s = Scanner.__new__(Scanner)
        self.s.targets = [
            SimpleNamespace(essid='a'),
            SimpleNamespace(essid='b'),
            SimpleNamespace(essid='c'),
            SimpleNamespace(essid='d'),
            SimpleNamespace(essid='e'),
        ]

    def test_space_separated(self):
        chosen = self.s._parse_target_selection('1 3 5')
        self.assertEqual([c.essid for c in chosen], ['a', 'c', 'e'])

    def test_comma_separated(self):
        chosen = self.s._parse_target_selection('1,3,5')
        self.assertEqual([c.essid for c in chosen], ['a', 'c', 'e'])

    def test_mixed_space_comma(self):
        chosen = self.s._parse_target_selection('1, 3 5')
        self.assertEqual([c.essid for c in chosen], ['a', 'c', 'e'])

    def test_range(self):
        chosen = self.s._parse_target_selection('2-4')
        self.assertEqual([c.essid for c in chosen], ['b', 'c', 'd'])

    def test_range_and_single(self):
        chosen = self.s._parse_target_selection('1-2 5')
        self.assertEqual([c.essid for c in chosen], ['a', 'b', 'e'])

    def test_all(self):
        chosen = self.s._parse_target_selection('all')
        self.assertEqual(len(chosen), 5)

    def test_dedupe(self):
        chosen = self.s._parse_target_selection('1 1 2')
        self.assertEqual([c.essid for c in chosen], ['a', 'b'])

    def test_out_of_range_ignored(self):
        chosen = self.s._parse_target_selection('1 99')
        self.assertEqual([c.essid for c in chosen], ['a'])

    def test_empty(self):
        self.assertEqual(self.s._parse_target_selection(''), [])
        self.assertEqual(self.s._parse_target_selection('   '), [])


if __name__ == '__main__':
    unittest.main()
