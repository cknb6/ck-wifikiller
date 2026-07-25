#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""启动界面：精简、单语言、按显示宽度对齐。"""

from .color import Color
from .i18n import t
from .term_layout import pad, term_cols, truncate

GITHUB_REPO = 'https://github.com/cknb6/ck-wifikiller'
GITHUB_AUTHOR = 'https://github.com/1837620622'
WECHAT = '1837620622'
EMAIL_CONTACT = '2040168455@qq.com'
HANDLE = '传康Kk'


def _box(lines: list[str], min_inner: int = 48) -> None:
    cols = term_cols()
    inner = max(min_inner, min(cols - 4, 64))
    body = [truncate(line, inner) for line in lines]
    top = '╔' + ('═' * (inner + 2)) + '╗'
    mid = '╠' + ('═' * (inner + 2)) + '╣'
    bot = '╚' + ('═' * (inner + 2)) + '╝'
    Color.pl('{G}%s{W}' % top)
    for i, line in enumerate(body):
        Color.pl('{G}║{W} %s {G}║{W}' % pad(line, inner))
        if i in (1, 5, 8):
            Color.pl('{G}%s{W}' % mid)
    Color.pl('{G}%s{W}' % bot)


def show_splash(version: str) -> None:
    lines = [
        t('splash.title'),
        t('splash.sub'),
        t('splash.version', version),
        t('splash.author', HANDLE),
        t('splash.github', GITHUB_REPO),
        t('splash.profile', GITHUB_AUTHOR),
        t('splash.sponsor', WECHAT),
        t('splash.email', EMAIL_CONTACT),
        t('splash.biz'),
        t('splash.legal'),
    ]
    Color.pl('')
    _box(lines)
    Color.pl('')
