#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""启动界面：精简、按显示宽度对齐。"""

from .color import Color
from .term_layout import display_width, pad, term_cols, truncate

GITHUB_REPO = 'https://github.com/cknb6/ck-wifikiller'
GITHUB_AUTHOR = 'https://github.com/1837620622'
WECHAT = '1837620622'
EMAIL_CONTACT = '2040168455@qq.com'
HANDLE = '传康Kk / 万能程序员'


def _box(lines: list[str], min_inner: int = 52) -> None:
    """绘制边框；inner 宽度按显示列数，随终端自动伸缩。"""
    cols = term_cols()
    # 边框占用 4 列：║ + 空格 + 内容 + 空格 + ║
    inner = max(min_inner, min(cols - 4, 72))
    # 内容先截到 inner
    body = [truncate(line, inner) for line in lines]
    # 统一按 pad 到 inner
    top = '╔' + ('═' * (inner + 2)) + '╗'
    mid = '╠' + ('═' * (inner + 2)) + '╣'
    bot = '╚' + ('═' * (inner + 2)) + '╝'
    Color.pl('{G}%s{W}' % top)
    for i, line in enumerate(body):
        Color.pl('{G}║{W} %s {G}║{W}' % pad(line, inner))
        # 分隔：标题后 / 元信息后 / 赞助后
        if i in (1, 5, 8):
            Color.pl('{G}%s{W}' % mid)
    Color.pl('{G}%s{W}' % bot)


def show_splash(version: str) -> None:
    lines = [
        'ck-wifikiller · Wireless Auditor',
        'wifite2 fork · PMKID · hashcat -m 22000',
        'Version  %s' % version,
        'Author   %s' % HANDLE,
        'GitHub   %s' % GITHUB_REPO,
        'Profile  %s' % GITHUB_AUTHOR,
        '赞助  微信 %s  备注 wifi赞助' % WECHAT,
        '邮箱  %s' % EMAIL_CONTACT,
        '商务  微信备注「商务合作」',
        '仅限授权测试 · Unauthorized use may be illegal',
    ]
    Color.pl('')
    _box(lines)
    Color.pl('')
