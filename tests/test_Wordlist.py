#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""字典解析测试：--dict 文件/目录/环境变量链路。"""

import os
import sys
import tempfile
import unittest

from ck_wifikiller.config import Configuration


class TestWordlistResolution(unittest.TestCase):
    """resolve_wordlist：文件、目录搜索、缺失路径。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _touch(self, name):
        path = os.path.join(self.dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write('password123\n')
        return path

    def test_file_path_returns_as_is(self):
        p = self._touch('mylist.txt')
        resolved, how = Configuration.resolve_wordlist(p)
        self.assertEqual((resolved, how), (p, 'file'))

    def test_dir_prefers_common_names(self):
        p = self._touch('other.txt')
        rock = self._touch('rockyou.txt')
        resolved, how = Configuration.resolve_wordlist(self.dir)
        self.assertEqual((resolved, how), (rock, 'dir'))

    def test_dir_combined_priority_over_other(self):
        self._touch('zzz.txt')
        combined = self._touch('wifi_cn_combined.txt')
        resolved, _ = Configuration.resolve_wordlist(self.dir)
        self.assertEqual(resolved, combined)

    def test_dir_pattern_fallback(self):
        p = self._touch('mypass.txt')
        resolved, how = Configuration.resolve_wordlist(self.dir)
        self.assertEqual((resolved, how), (p, 'dir'))

    def test_dir_empty_reports_dir_empty(self):
        resolved, how = Configuration.resolve_wordlist(self.dir)
        self.assertEqual((resolved, how), (None, 'dir_empty'))

    def test_missing_path(self):
        resolved, how = Configuration.resolve_wordlist('/no/such/file.txt')
        self.assertEqual((resolved, how), (None, 'missing'))

    def test_empty_path(self):
        resolved, how = Configuration.resolve_wordlist('')
        self.assertEqual((resolved, how), (None, 'empty'))

    def test_dir_lst_pattern(self):
        p = self._touch('word.lst')
        resolved, how = Configuration.resolve_wordlist(self.dir)
        self.assertEqual((resolved, how), (p, 'dir'))


class TestWordlistCandidateSelection(unittest.TestCase):
    """initialize 候选列表：环境变量优先、目录也可命中。"""

    def test_env_wordlist_wins(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as d:
            wl = os.path.join(d, 'rockyou.txt')
            with open(wl, 'w', encoding='utf-8') as f:
                f.write('abc\n')
            with patch.dict(os.environ, {'CK_WIFI_WORDLIST': wl}, clear=False):
                # unittest 环境下 sys.argv 残留 discover/tests 等参数，
                # 会触发 parse_args 报错；这里固定为纯程序名。
                with patch.object(sys, 'argv', ['ck-wifikiller']):
                    Configuration.initialize(load_interface=False)
                self.assertEqual(Configuration.wordlist, wl)


if __name__ == '__main__':
    unittest.main()
