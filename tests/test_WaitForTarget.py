#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wait_for_target 不得长时间卡死；refresh 失败保留旧 target。"""

import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, '..')

from ck_wifikiller.model.attack import Attack
from ck_wifikiller.config import Configuration


class _FakePid:
    def __init__(self, alive=True, code=1):
        self._alive = alive
        self._code = code

    def poll(self):
        return None if self._alive else self._code


class _FakeAirodump:
    def __init__(self, batches, alive=True):
        """batches: 每次 get_targets 返回的列表序列。"""
        self._batches = list(batches)
        self._i = 0
        self.pid = _FakePid(alive=alive)

    def get_targets(self, apply_filter=True):
        if self._i < len(self._batches):
            batch = self._batches[self._i]
            self._i += 1
            return batch
        return self._batches[-1] if self._batches else []


def _ap(bssid='BC:1A:E4:02:77:38', essid='Changdoudounew'):
    return SimpleNamespace(
        bssid=bssid,
        essid=essid,
        essid_known=True,
        channel='6',
        power=25,
        wps=1,
        clients=[],
    )


class TestWaitForTarget(unittest.TestCase):
    def setUp(self):
        self.atk = Attack(_ap())
        self._old_deadline = getattr(Configuration, 'path_deadline', None)

    def tearDown(self):
        Configuration.path_deadline = self._old_deadline

    def test_finds_target_case_insensitive(self):
        dump = _FakeAirodump([
            [],
            [_ap(bssid='bc:1a:e4:02:77:38')],
        ])
        Configuration.path_deadline = time.time() + 30
        got = self.atk.wait_for_target(dump, timeout=5)
        self.assertEqual(got.bssid.lower(), 'bc:1a:e4:02:77:38')

    def test_timeout_raises_quickly(self):
        dump = _FakeAirodump([[], [], [], []])
        Configuration.path_deadline = time.time() + 100
        t0 = time.time()
        with self.assertRaises(Exception) as cm:
            self.atk.wait_for_target(dump, timeout=2)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 5.0, 'must not hang near old 60s target_wait')
        self.assertIn('did not appear', str(cm.exception))

    def test_path_deadline_caps_wait(self):
        dump = _FakeAirodump([[]] * 50)
        Configuration.path_deadline = time.time() + 2.2
        t0 = time.time()
        with self.assertRaises(Exception):
            self.atk.wait_for_target(dump, timeout=60)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 5.0)

    def test_refresh_keeps_old_on_miss(self):
        old = self.atk.target
        dump = _FakeAirodump([[], []])  # never appears
        Configuration.path_deadline = time.time() + 30
        got = self.atk.wait_for_target(dump, refresh=True, timeout=1)
        self.assertIs(got, old)

    def test_airodump_dead_fails_fast(self):
        dump = _FakeAirodump([[]], alive=False)
        Configuration.path_deadline = time.time() + 30
        t0 = time.time()
        with self.assertRaises(Exception) as cm:
            self.atk.wait_for_target(dump, timeout=20)
        self.assertLess(time.time() - t0, 3.0)
        self.assertIn('airodump-ng exited', str(cm.exception))

    def test_on_wait_callback(self):
        seen = []
        dump = _FakeAirodump([
            [],
            [_ap()],
        ])
        Configuration.path_deadline = time.time() + 30
        self.atk.wait_for_target(dump, timeout=5, on_wait=lambda r: seen.append(r))
        self.assertTrue(len(seen) >= 1)


if __name__ == '__main__':
    unittest.main()
