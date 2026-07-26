#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, '..')

from ck_wifikiller.util.capture_select import (
    is_valid_hc22000_line,
    pick_best_candidate,
    CaptureCandidate,
    line_fingerprint,
    select_pmkid_file,
    read_valid_hc22000_lines,
)


class TestCaptureSelect(unittest.TestCase):
    def test_valid_pmkid_line(self):
        # 典型 WPA*01* PMKID 行
        line = (
            'WPA*01*0123456789abcdef0123456789abcdef*'
            'aabbccddeeff*112233445566*54657374***'
        )
        self.assertTrue(is_valid_hc22000_line(line, want_bssid='AA:BB:CC:DD:EE:FF'))
        self.assertFalse(is_valid_hc22000_line(line, want_bssid='00:11:22:33:44:55'))
        self.assertFalse(is_valid_hc22000_line('not-a-hash'))
        self.assertFalse(is_valid_hc22000_line('WPA*01*short*aabbccddeeff*112233445566**'))

    def test_pick_prefers_valid_latest(self):
        a = CaptureCandidate('a', mtime=1, fingerprint='f1', valid=True, kind='pmkid')
        b = CaptureCandidate('b', mtime=3, fingerprint='f2', valid=True, kind='pmkid')
        bad = CaptureCandidate('bad', mtime=99, fingerprint='', valid=False, kind='pmkid')
        best = pick_best_candidate([a, b, bad])
        self.assertEqual(best.path, 'b')

    def test_pick_same_fingerprint_keeps_newest(self):
        a = CaptureCandidate('old', mtime=1, fingerprint='same', valid=True, kind='pmkid')
        b = CaptureCandidate('new', mtime=5, fingerprint='same', valid=True, kind='pmkid')
        best = pick_best_candidate([a, b])
        self.assertEqual(best.path, 'new')
        self.assertEqual(line_fingerprint('x'), line_fingerprint('x'))

    def test_select_pmkid_file_latest_valid(self):
        with tempfile.TemporaryDirectory() as d:
            bssid = 'AA:BB:CC:DD:EE:FF'
            good1 = (
                'WPA*01*0123456789abcdef0123456789abcdef*'
                'aabbccddeeff*112233445566*54657374***\n'
            )
            good2 = (
                'WPA*01*fedcba9876543210fedcba9876543210*'
                'aabbccddeeff*112233445566*54657374***\n'
            )
            bad = 'garbage\n'
            p1 = os.path.join(d, 'pmkid_A_AA-BB-CC-DD-EE-FF_2020-01-01T00-00-00.hc22000')
            p2 = os.path.join(d, 'pmkid_A_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.hc22000')
            pbad = os.path.join(d, 'pmkid_A_AA-BB-CC-DD-EE-FF_2026-06-01T00-00-00.hc22000')
            with open(p1, 'w') as fh:
                fh.write(good1)
            time.sleep(0.05)
            with open(p2, 'w') as fh:
                fh.write(good2)
            with open(pbad, 'w') as fh:
                fh.write(bad)
            # 触碰 p2 更新 mtime
            time.sleep(0.05)
            os.utime(p2, None)
            best = select_pmkid_file(d, bssid)
            self.assertEqual(os.path.basename(best), os.path.basename(p2))
            self.assertEqual(len(read_valid_hc22000_lines(best, want_bssid=bssid)), 1)

    def test_same_content_dedupe_pick(self):
        with tempfile.TemporaryDirectory() as d:
            bssid = 'AA:BB:CC:DD:EE:FF'
            good = (
                'WPA*01*0123456789abcdef0123456789abcdef*'
                'aabbccddeeff*112233445566*54657374***\n'
            )
            p1 = os.path.join(d, 'pmkid_A_AA-BB-CC-DD-EE-FF_2020-01-01T00-00-00.hc22000')
            p2 = os.path.join(d, 'pmkid_A_AA-BB-CC-DD-EE-FF_2026-01-01T00-00-00.hc22000')
            with open(p1, 'w') as fh:
                fh.write(good)
            with open(p2, 'w') as fh:
                fh.write(good)
            os.utime(p2, None)
            best = select_pmkid_file(d, bssid)
            # 相同内容只留最新 mtime 那份
            self.assertEqual(best, p2)


if __name__ == '__main__':
    unittest.main()
