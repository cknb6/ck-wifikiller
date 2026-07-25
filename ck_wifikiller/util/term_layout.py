#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""终端显示宽度工具：中文等宽字符占 2 列，用于表格/边框对齐。"""

from __future__ import annotations

import shutil
import unicodedata


def term_cols(default: int = 80) -> int:
    try:
        return max(40, shutil.get_terminal_size((default, 24)).columns)
    except Exception:
        return default


def display_width(text: str) -> int:
    """返回字符串在终端中的显示列数（全角/宽字符=2）。"""
    if not text:
        return 0
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        # East Asian fullwidth / wide
        if unicodedata.east_asian_width(ch) in ('F', 'W'):
            width += 2
        else:
            width += 1
    return width


def truncate(text: str, width: int, ellipsis: str = '...') -> str:
    """按显示宽度截断；ellipsis 占显示宽度计入上限。"""
    if width <= 0:
        return ''
    if display_width(text) <= width:
        return text
    ell_w = display_width(ellipsis)
    if width <= ell_w:
        # 极窄时只返回能放下的内容
        return _fit(text, width)
    body = _fit(text, width - ell_w)
    return body + ellipsis


def _fit(text: str, width: int) -> str:
    out = []
    used = 0
    for ch in text:
        cw = 2 if unicodedata.east_asian_width(ch) in ('F', 'W') else 1
        if unicodedata.combining(ch):
            out.append(ch)
            continue
        if used + cw > width:
            break
        out.append(ch)
        used += cw
    return ''.join(out)


def pad(text: str, width: int, align: str = 'left') -> str:
    """按显示宽度填充空格到固定列宽。"""
    text = text or ''
    tw = display_width(text)
    if tw > width:
        text = truncate(text, width)
        tw = display_width(text)
    pad_n = max(0, width - tw)
    if align == 'right':
        return (' ' * pad_n) + text
    if align == 'center':
        left = pad_n // 2
        right = pad_n - left
        return (' ' * left) + text + (' ' * right)
    return text + (' ' * pad_n)
