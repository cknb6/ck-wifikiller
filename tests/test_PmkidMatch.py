#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PMKID 捕获匹配回归测试：hcxpcapngtool 输出的 MAC 带冒号也能命中。"""

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, '..')

from ck_wifikiller.tools.hashcat import HcxPcapTool


class _FakeProc:
    def __init__(self):
        self.done = False

    def wait(self):
        self.done = True

    def get_output(self):
        return ('', '')


def _write_line(path, line):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(line + '\n')


class TestPmkidMatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pcapng = os.path.join(self.tmp.name, 'cap.pcapng')
        _write_line(self.pcapng, 'dummy')

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, out_line, bssid='ac:9e:17:8e:22:3b'):
        target = SimpleNamespace(bssid=bssid)
        tool = HcxPcapTool(target)
        hash_path = os.path.join(self.tmp.name, 'out.hc22000')

        def fake_run(cmd, **kw):
            if 'hcxpcapngtool' in cmd[0] and cmd[1] == '-o':
                _write_line(cmd[2], out_line)
            return _FakeProc()

        with patch('ck_wifikiller.tools.hashcat.Process', side_effect=fake_run) as _:
            with patch.object(HcxPcapTool, '_tool', return_value='hcxpcapngtool'):
                # hash_file 使用 Configuration.temp，测试中不可写，改指临时目录
                tool.hash_file = hash_path
                return tool.get_pmkid_hash(self.pcapng)

    def test_matches_colon_mac(self):
        line = ('WPA*01*0123456789abcdef0123456789abcdef*'
                'ac:9e:17:8e:22:3b*001122334455*TestWifi***')
        self.assertEqual(self._run(line), line)

    def test_matches_plain_mac(self):
        line = ('WPA*01*0123456789abcdef0123456789abcdef*'
                'ac9e178e223b*001122334455*TestWifi***')
        self.assertEqual(self._run(line), line)

    def test_rejects_other_bssid(self):
        line = ('WPA*01*0123456789abcdef0123456789abcdef*'
                '001122334455*ac9e178e223b*TestWifi***')
        self.assertIsNone(self._run(line))

    def test_eapol_line_accepted_when_bssid_matches(self):
        # WPA*02* EAPOL 行同样可爆破（hashcat -m 22000），BSSID 匹配即算捕获成功
        line = ('WPA*02*0123456789abcdef*ac9e178e223b*001122334455*'
                'TestWifi*00000000000000000000000000000000*'
                '0000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000*00')
        self.assertEqual(self._run(line), line)

    def test_eapol_line_rejected_for_other_bssid(self):
        line = ('WPA*02*0123456789abcdef*001122334455*ac9e178e223b*'
                'TestWifi*00000000000000000000000000000000*'
                '0000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000*00')
        self.assertIsNone(self._run(line))


if __name__ == '__main__':
    unittest.main()
