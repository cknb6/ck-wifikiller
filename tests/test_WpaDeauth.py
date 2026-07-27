#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPA deauth 客户端回填回归测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ck_wifikiller.attack.wpa import AttackWPA


class _FakeClient(object):
    def __init__(self, station):
        self.station = station


class _FakeTarget(object):
    def __init__(self, clients):
        self.clients = clients


class TestSeedClients(unittest.TestCase):
    '''首轮爆发前必须回填 airodump 扫描到的关联客户端。

    回归：旧代码 self.clients = [] 在 wait_for_target 之后直接清空，
    丢弃 airodump_target.clients，导致首轮 deauth 只剩广播——现代手机
    忽略广播 deauth，表现为"踢不下人"。
    '''

    def test_seeds_valid_clients(self):
        tgt = _FakeTarget([
            _FakeClient('AA:BB:CC:DD:EE:01'),
            _FakeClient('aa:bb:cc:dd:ee:02'),  # 小写应归一
        ])
        seeded = AttackWPA._seed_clients(tgt)
        self.assertEqual(seeded, ['AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02'])

    def test_dedup(self):
        tgt = _FakeTarget([
            _FakeClient('AA:BB:CC:DD:EE:01'),
            _FakeClient('AA:BB:CC:DD:EE:01'),
        ])
        self.assertEqual(AttackWPA._seed_clients(tgt),
                         ['AA:BB:CC:DD:EE:01'])

    def test_filters_broadcast_and_multicast(self):
        tgt = _FakeTarget([
            _FakeClient('FF:FF:FF:FF:FF:FF'),  # 广播
            _FakeClient('00:00:00:00:00:00'),  # 全零
            _FakeClient('01:22:33:44:55:66'),  # 组播(首字节最低位1)
            _FakeClient('02:22:33:44:55:66'),  # 合法单播
            _FakeClient(''),                    # 空
            _FakeClient(None),                 # None
        ])
        self.assertEqual(AttackWPA._seed_clients(tgt),
                         ['02:22:33:44:55:66'])

    def test_no_clients(self):
        self.assertEqual(AttackWPA._seed_clients(_FakeTarget([])), [])
        self.assertEqual(AttackWPA._seed_clients(_FakeTarget(None)), [])

    def test_missing_clients_attr(self):
        class NoClients(object):
            pass
        self.assertEqual(AttackWPA._seed_clients(NoClients()), [])


if __name__ == '__main__':
    unittest.main()
