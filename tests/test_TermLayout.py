#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from ck_wifikiller.util.i18n import set_lang, t
from ck_wifikiller.util.term_layout import (
    display_width, pad, truncate, scan_col_widths,
)


class TestTermLayout(unittest.TestCase):
    def test_cjk_width(self):
        self.assertEqual(display_width('AB'), 2)
        self.assertEqual(display_width('小米'), 4)
        self.assertEqual(display_width('小米AB'), 6)

    def test_pad_aligns_mixed(self):
        a = pad('CK-Neo', 12)
        b = pad('小米共享', 12)
        self.assertEqual(display_width(a), 12)
        self.assertEqual(display_width(b), 12)

    def test_truncate(self):
        s = truncate('小米共享WiFi_4E2F', 10)
        self.assertLessEqual(display_width(s), 10)

    def test_zh_headers_not_ellipsis(self):
        '''中文表头不得被截成「信」或「…」。'''
        set_lang('zh')
        col = scan_col_widths(False)
        for key, hdr in [
            ('num', t('scan.hdr_num')),
            ('essid', t('scan.hdr_essid')),
            ('ch', t('scan.hdr_ch')),
            ('encr', t('scan.hdr_encr')),
            ('pwr', t('scan.hdr_power')),
            ('wps', t('scan.hdr_wps')),
            ('cli', t('scan.hdr_cli')),
        ]:
            p = pad(hdr, col[key], align='right' if key in ('num', 'ch', 'pwr', 'cli') else 'left')
            self.assertNotIn('…', p)
            self.assertNotIn('...', p)
            self.assertEqual(display_width(p), col[key])
            # 表头全文应在列内（pad 后仍含原文字）
            self.assertIn(hdr[0], p)
        set_lang('en')

    def test_cli_header_is_client_not_dots(self):
        set_lang('zh')
        col = scan_col_widths(False)
        p = pad(t('scan.hdr_cli'), col['cli'], align='right')
        self.assertEqual(p.strip(), '客户')
        set_lang('en')
        col = scan_col_widths(False)
        p = pad(t('scan.hdr_cli'), col['cli'], align='right')
        self.assertIn('CLI', p)


if __name__ == '__main__':
    unittest.main()
