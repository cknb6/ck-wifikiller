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


def scan_col_widths(show_bssid: bool = False) -> dict:
    """扫描表列宽：列宽 >= 表头显示宽度，避免中文被截成「信」「…」。

    返回 keys: num, essid, bssid, ch, encr, pwr, wps, cli, gap
    """
    # 延迟导入，避免 i18n ↔ term_layout 环依赖
    from .i18n import t

    gap = 2
    num = max(4, display_width(t('scan.hdr_num')))
    ch = max(4, display_width(t('scan.hdr_ch')))      # 信道=4
    encr = max(4, display_width(t('scan.hdr_encr')))  # 加密=4
    pwr = max(5, display_width(t('scan.hdr_power')))  # 信号=4, 数据如 39db=4
    wps = max(4, display_width(t('scan.hdr_wps')))
    cli = max(4, display_width(t('scan.hdr_cli')))    # 客户=4

    fixed = num + gap + ch + gap + encr + gap + pwr + gap + wps + gap + cli
    bssid_w = 0
    if show_bssid:
        bssid_w = max(17, display_width(t('scan.hdr_bssid')))
        fixed += gap + bssid_w

    cols = term_cols()
    # ESSID 吃剩余宽度，限制在 12–36
    essid = max(12, min(36, cols - fixed - gap - 2))
    # 极窄终端：压缩 ESSID，保证右侧列完整显示
    if essid < 12:
        essid = max(8, cols - fixed - gap - 2)

    return {
        'num': num,
        'essid': essid,
        'bssid': bssid_w,
        'ch': ch,
        'encr': encr,
        'pwr': pwr,
        'wps': wps,
        'cli': cli,
        'gap': gap,
    }
