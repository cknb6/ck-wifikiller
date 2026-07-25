#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""输入校验：接口名、信道、MAC —— 防止路径穿越与异常参数进入外部工具。"""

from __future__ import annotations

import re
from typing import Optional

# Linux 网卡名常见字符集；禁止 / .. 与空白，避免 /sys/class/net 路径穿越。
_IFACE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9._-]{0,15}$')

# 数字信道或 hcxdumptool 风格 6a/36a
_CHANNEL_RE = re.compile(r'^(?:[1-9]|[1-9][0-9]|1[0-9]{2}|[1-9][0-9]{0,2}[a-fA-F])$')

_BSSID_RE = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def is_safe_iface(name: Optional[str]) -> bool:
    if not name or not isinstance(name, str):
        return False
    if '/' in name or '\\' in name or '..' in name or ' ' in name:
        return False
    return bool(_IFACE_RE.fullmatch(name))


def is_safe_channel(channel) -> bool:
    if channel is None:
        return False
    if isinstance(channel, int):
        return 1 <= channel <= 196
    text = str(channel).strip()
    if not text:
        return False
    if text.isdigit():
        return 1 <= int(text) <= 196
    return bool(_CHANNEL_RE.fullmatch(text))


def is_mac_address(value: Optional[str]) -> bool:
    if not value or not isinstance(value, str):
        return False
    return bool(_BSSID_RE.fullmatch(value.strip()))


def require_safe_iface(name: str) -> str:
    if not is_safe_iface(name):
        raise ValueError('invalid wireless interface name: %r' % (name,))
    return name


def require_mac(value: str, label: str = 'MAC') -> str:
    if not is_mac_address(value):
        raise ValueError('invalid %s: %r' % (label, value))
    return value.strip()
