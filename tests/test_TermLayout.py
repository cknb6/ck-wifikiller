#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from ck_wifikiller.util.term_layout import display_width, pad, truncate


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


if __name__ == '__main__':
    unittest.main()
