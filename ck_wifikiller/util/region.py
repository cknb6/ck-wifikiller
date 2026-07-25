#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""区域策略检测。

区域检测只依据明确的 IANA 时区名称，不使用 ``CST`` 或 UTC+8 偏移量，
避免把新加坡、马来西亚等地区误判为中国大陆。CLI 显式选项始终优先。
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Mapping, Optional, Tuple


MAINLAND_CHINA_TIMEZONES = frozenset({
    'Asia/Shanghai',
    'Asia/Chongqing',
    'Asia/Harbin',
    'Asia/Urumqi',
    'PRC',
})


def normalize_timezone(value: object) -> Optional[str]:
    """把环境变量、zoneinfo 对象或 ``/zoneinfo/...`` 路径归一化。"""
    if value is None:
        return None
    key = getattr(value, 'key', None)
    text = str(key if key else value).strip()
    if not text:
        return None
    if text.startswith(':'):
        text = text[1:]
    marker = '/zoneinfo/'
    if marker in text:
        text = text.split(marker, 1)[1]
    return text or None


def detect_timezone(
    environ: Optional[Mapping[str, str]] = None,
    timezone_file: str = '/etc/timezone',
    localtime_path: str = '/etc/localtime',
    tzinfo: object = None,
) -> Tuple[Optional[str], str]:
    """返回 ``(IANA 时区, 证据来源)``；无法判断时返回 ``(None, ...)``。"""
    env = os.environ if environ is None else environ
    zone = normalize_timezone(env.get('TZ'))
    if zone:
        return zone, 'TZ'

    try:
        with open(timezone_file, 'r', encoding='utf-8') as handle:
            zone = normalize_timezone(handle.readline())
        if zone:
            return zone, timezone_file
    except OSError:
        pass

    try:
        if os.path.islink(localtime_path):
            zone = normalize_timezone(os.path.realpath(localtime_path))
            if zone:
                return zone, localtime_path
    except OSError:
        pass

    current_tz = tzinfo
    if current_tz is None:
        try:
            current_tz = datetime.now().astimezone().tzinfo
        except (OSError, ValueError):
            current_tz = None
    zone = normalize_timezone(current_tz)
    if zone and '/' in zone:
        return zone, 'system-tzinfo'
    return None, 'unknown'


def is_mainland_china_timezone(timezone_name: object) -> bool:
    """仅在时区名称明确属于中国大陆时返回 ``True``。"""
    return normalize_timezone(timezone_name) in MAINLAND_CHINA_TIMEZONES


def resolve_cn_mode(
    cli_value: Optional[bool],
    environ: Optional[Mapping[str, str]] = None,
    timezone_name: object = None,
) -> Tuple[bool, str]:
    """解析 CN 策略三态。

    优先级为：``--cn/--no-cn`` > ``CK_WIFI_REGION`` > 明确 IANA 时区。
    ``CK_WIFI_REGION`` 支持 ``cn``、``global`` 和 ``auto``。
    """
    if cli_value is not None:
        return bool(cli_value), 'cli'

    env = os.environ if environ is None else environ
    region = str(env.get('CK_WIFI_REGION', 'auto')).strip().lower()
    if region in ('cn', 'china', 'mainland'):
        return True, 'CK_WIFI_REGION'
    if region in ('global', 'intl', 'international', 'off'):
        return False, 'CK_WIFI_REGION'

    zone = normalize_timezone(timezone_name)
    source = 'provided-timezone'
    if zone is None:
        zone, source = detect_timezone(environ=env)
    return is_mainland_china_timezone(zone), '%s:%s' % (source, zone or 'unknown')
