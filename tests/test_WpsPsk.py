#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPS PIN->PSK 自动获取回归测试。"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ck_wifikiller.tools.reaver import Reaver
from ck_wifikiller.config import Configuration


class _Target:
    def __init__(self, bssid='AA:BB:CC:DD:EE:FF', channel='6'):
        self.bssid = bssid
        self.channel = channel


class TestExtractPsk(unittest.TestCase):
    '''_extract_psk 必须覆盖 reaver/bully 多种输出格式。'''

    def test_reaver_wpa_psk(self):
        out = "[+] WPA PSK: 'password123'"
        self.assertEqual(Reaver._extract_psk(out), 'password123')

    def test_reaver_wpa_psk_no_quotes(self):
        # 部分 reaver fork 不带引号
        out = "[+] WPA PSK: Test123"
        self.assertEqual(Reaver._extract_psk(out), 'Test123')

    def test_bully_key(self):
        out = "  KEY   : 'mywifikey'\n  PIN   : '12345670'"
        self.assertEqual(Reaver._extract_psk(out), 'mywifikey')

    def test_pin_key_is(self):
        out = "[*] Pin is '12345670', key is 'secretpass'"
        self.assertEqual(Reaver._extract_psk(out), 'secretpass')

    def test_none(self):
        self.assertIsNone(Reaver._extract_psk('no psk here'))
        self.assertIsNone(Reaver._extract_psk(''))
        self.assertIsNone(Reaver._extract_psk(None))


class TestGetPskFromPin(unittest.TestCase):
    '''get_psk_from_pin: reaver 成功则返回，失败回退 bully，全失败返回 None。
    不应因工具未装/异常而冒泡（原 bug：只捕获 KeyboardInterrupt）。
    '''

    def setUp(self):
        Configuration.interface = 'wlan0mon'

    def test_reaver_success(self):
        fake_proc = MagicMock()
        fake_proc.poll.side_effect = [None, 0]  # 第一轮未结束，第二轮结束
        fake_proc.stdout.return_value = "[+] WPA PSK: 'reaver_psk'"
        fake_proc.stderr.return_value = ''
        fake_proc.interrupt = MagicMock()
        with patch.object(Reaver, 'exists', return_value=True), \
                patch('ck_wifikiller.tools.reaver.Process', return_value=fake_proc):
            psk = Reaver.get_psk_from_pin(_Target(), '12345670', timeout=5)
        self.assertEqual(psk, 'reaver_psk')

    def test_reaver_fail_fallback_bully(self):
        fake_proc = MagicMock()
        fake_proc.poll.side_effect = [None, 0]
        fake_proc.stdout.return_value = 'no psk'
        fake_proc.stderr.return_value = ''
        fake_proc.interrupt = MagicMock()
        with patch.object(Reaver, 'exists', return_value=True), \
                patch('ck_wifikiller.tools.reaver.Process', return_value=fake_proc), \
                patch('ck_wifikiller.tools.bully.Bully.exists', return_value=True), \
                patch('ck_wifikiller.tools.bully.Bully.get_psk_from_pin',
                      return_value='bully_psk') as bk:
            psk = Reaver.get_psk_from_pin(_Target(), '12345670', timeout=5)
        self.assertEqual(psk, 'bully_psk')
        bk.assert_called_once()

    def test_all_fail_returns_none(self):
        fake_proc = MagicMock()
        fake_proc.poll.side_effect = [None, 0]
        fake_proc.stdout.return_value = ''
        fake_proc.stderr.return_value = ''
        fake_proc.interrupt = MagicMock()
        with patch.object(Reaver, 'exists', return_value=True), \
                patch('ck_wifikiller.tools.reaver.Process', return_value=fake_proc), \
                patch('ck_wifikiller.tools.bully.Bully.exists', return_value=False):
            psk = Reaver.get_psk_from_pin(_Target(), '12345670', timeout=5)
        self.assertIsNone(psk)

    def test_reaver_missing_no_crash(self):
        '''reaver 未装时不应冒泡异常（原 bug：Process 抛异常未捕获）。'''
        with patch.object(Reaver, 'exists', return_value=False), \
                patch('ck_wifikiller.tools.bully.Bully.exists', return_value=False):
            psk = Reaver.get_psk_from_pin(_Target(), '12345670', timeout=5)
        self.assertIsNone(psk)

    def test_timeout_interrupts(self):
        '''超时必须中断 reaver，不能干等。'''
        fake_proc = MagicMock()
        # 永不自行退出
        fake_proc.poll.return_value = None
        fake_proc.stdout.return_value = ''
        fake_proc.stderr.return_value = ''
        fake_proc.interrupt = MagicMock()
        with patch.object(Reaver, 'exists', return_value=True), \
                patch('ck_wifikiller.tools.reaver.Process', return_value=fake_proc), \
                patch('ck_wifikiller.tools.bully.Bully.exists', return_value=False):
            import time as _t
            t0 = _t.time()
            psk = Reaver.get_psk_from_pin(_Target(), '12345670', timeout=2)
        # 应在 ~2s 内返回（允许 polling 误差）
        self.assertLess(_t.time() - t0, 5)
        self.assertIsNone(psk)
        fake_proc.interrupt.assert_called()


if __name__ == '__main__':
    unittest.main()
