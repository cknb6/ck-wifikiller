#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中国常见无线设备的被动指纹与审计建议。

OUI 只能说明 MAC 地址块的登记组织，SSID 也可以被用户修改；二者都不能
单独证明设备型号、固件版本或漏洞状态。本模块因此只产生带证据等级的
候选指纹，并把进一步动作限制为固件与配置核查。
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Iterable, Optional


OUI_DATABASE_PATHS = (
    '/usr/share/ieee-data/oui.txt',
    '/var/lib/ieee-data/oui.txt',
    '/usr/share/wireshark/manuf',
    '/usr/share/nmap/nmap-mac-prefixes',
)

# 这些少量后备项来自 IEEE 登记表；完整识别优先读取系统 ieee-data。
OUI_FALLBACK = {
    '34f716': 'TP-Link',
    '54a703': 'TP-Link',
    'cceb5e': 'Xiaomi',
    'b8ea98': 'Xiaomi',
    'e00630': 'Huawei',
    'd8daf1': 'Huawei',
    'f01b24': 'ZTE',
    '98ee8c': 'ZTE',
    '78465f': 'FiberHome',
    '3086f1': 'FiberHome',
    '04a959': 'H3C',
    '708185': 'H3C',
    'f0748d': 'Ruijie',
    '10823d': 'Ruijie',
}

VENDOR_ALIASES = (
    (('tp-link', 'tplink'), 'TP-Link'),
    (('mercury', '水星'), 'Mercury'),
    (('fast hi-tech', 'fast technologies', '迅捷'), 'Fast'),
    (('xiaomi', 'beijing xiaomi'), 'Xiaomi'),
    (('huawei',), 'Huawei'),
    (('zte',), 'ZTE'),
    (('fiberhome', 'fiber home', '烽火'), 'FiberHome'),
    (('tenda',), 'Tenda'),
    (('new h3c', 'h3c'), 'H3C'),
    (('ruijie', 'reyee'), 'Ruijie/Reyee'),
)

SSID_VENDOR_PATTERNS = (
    (re.compile(r'^TP[-_ ]?LINK', re.I), 'TP-Link'),
    (re.compile(r'^(MERCURY|MERCURY_)', re.I), 'Mercury'),
    (re.compile(r'^(FAST|FAST_)', re.I), 'Fast'),
    (re.compile(r'^(MIWIFI|MI[-_]|XIAOMI|REDMI)', re.I), 'Xiaomi'),
    (re.compile(r'^HUAWEI[-_]', re.I), 'Huawei'),
    (re.compile(r'^ZTE[-_]', re.I), 'ZTE'),
    (re.compile(r'^TENDA[-_]', re.I), 'Tenda'),
    (re.compile(r'^H3C[-_]', re.I), 'H3C'),
    (re.compile(r'^(RUIJIE|REYEE)[-_]', re.I), 'Ruijie/Reyee'),
)

OPERATOR_PATTERNS = (
    (re.compile(r'^CHINANET[-_]', re.I), 'China Telecom'),
    (re.compile(r'^(CMCC|MERCURY-CMCC)[-_]?', re.I), 'China Mobile'),
    (re.compile(r'^(CHINAUNICOM|CU)[-_]', re.I), 'China Unicom'),
)

CHINA_ROUTER_PROFILES = {
    'TP-Link': {'segment': '家用/中小企业', 'family': 'TP-Link / 易展'},
    'Mercury': {'segment': '家用', 'family': '水星网络'},
    'Fast': {'segment': '家用', 'family': '迅捷网络'},
    'Xiaomi': {'segment': '家用/智能家居', 'family': '小米 / Redmi'},
    'Huawei': {'segment': '家用/运营商/企业', 'family': '华为路由 / 家庭网关'},
    'ZTE': {'segment': '运营商家庭网关', 'family': '中兴家庭网关'},
    'FiberHome': {'segment': '运营商家庭网关', 'family': '烽火家庭网关'},
    'Tenda': {'segment': '家用/中小企业', 'family': '腾达'},
    'H3C': {'segment': '企业/中小企业/家用', 'family': 'H3C / Magic'},
    'Ruijie/Reyee': {'segment': '企业/中小企业', 'family': '锐捷 / Reyee'},
}

# 厂商 → 攻击路径优先级（全保留，只排序不跳过）
VENDOR_ATTACK_PATHS = {
    'TP-Link': ['PMKID', 'handshake', 'WPS Pixie-Dust', 'WPS PIN'],
    'Mercury': ['PMKID', 'handshake', 'WPS Pixie-Dust', 'WPS PIN'],
    'Fast': ['PMKID', 'handshake', 'WPS Pixie-Dust', 'WPS PIN'],
    'Xiaomi': ['PMKID', 'handshake', 'WPS Pixie-Dust', 'WPS PIN'],
    'Tenda': ['PMKID', 'handshake', 'WPS Pixie-Dust', 'WPS PIN'],
    'H3C': ['PMKID', 'handshake', 'WPS Pixie-Dust', 'WPS PIN'],
    'Huawei': ['WPS Pixie-Dust', 'WPS PIN', 'handshake', 'PMKID'],
    'ZTE': ['WPS Pixie-Dust', 'WPS PIN', 'handshake', 'PMKID'],
    'FiberHome': ['WPS Pixie-Dust', 'WPS PIN', 'handshake', 'PMKID'],
    'Ruijie/Reyee': ['handshake', 'PMKID', 'WPS Pixie-Dust', 'WPS PIN'],
}


def normalize_oui(bssid: str) -> str:
    """合法 BSSID 转为小写无分隔 OUI；格式不合法时返回空字符串。"""
    text = (bssid or '').strip()
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', text):
        return ''
    return text.replace(':', '').lower()[:6]


def canonical_vendor(raw_name: str) -> Optional[str]:
    """将系统 OUI 数据库的登记组织名归一化为产品家族名。"""
    low = (raw_name or '').strip().lower()
    for needles, canonical in VENDOR_ALIASES:
        if any(needle in low for needle in needles):
            return canonical
    return None


def _parse_oui_line(line: str) -> tuple[Optional[str], Optional[str]]:
    """兼容 ieee-data、Wireshark manuf 与 Nmap MAC prefix 三种格式。"""
    text = line.strip()
    if not text or text.startswith('#'):
        return None, None
    match = re.match(
        r'^([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){2}|[0-9A-Fa-f]{6})'
        r'(?:\s+\(hex\))?\s+(.+)$',
        text,
    )
    if not match:
        return None, None
    prefix = re.sub(r'[^0-9A-Fa-f]', '', match.group(1)).lower()
    return (prefix, match.group(2).strip()) if len(prefix) == 6 else (None, None)


def _database_paths(paths: Optional[Iterable[str]] = None) -> tuple[str, ...]:
    if paths is not None:
        return tuple(paths)
    override = os.environ.get('CK_WIFI_OUI_DB', '').strip()
    if override:
        return (override,) + OUI_DATABASE_PATHS
    return OUI_DATABASE_PATHS


@lru_cache(maxsize=16)
def _load_oui_database(paths: tuple[str, ...]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for path in paths:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    prefix, raw_name = _parse_oui_line(line)
                    if prefix and raw_name and prefix not in entries:
                        entries[prefix] = raw_name
        except OSError:
            continue
    return entries


def identify_vendor(bssid: str, database_paths: Optional[Iterable[str]] = None) -> Optional[str]:
    """按系统 OUI 库识别登记组织；未知或非目标厂商返回 ``None``。"""
    oui = normalize_oui(bssid)
    if not oui:
        return None
    raw_name = _load_oui_database(_database_paths(database_paths)).get(oui)
    vendor = canonical_vendor(raw_name or '')
    return vendor or OUI_FALLBACK.get(oui)


def fingerprint_router(bssid: str, essid: str = '') -> dict:
    """组合 OUI 与 SSID 的被动证据，返回保守的候选指纹。"""
    evidence = []
    oui_vendor = identify_vendor(bssid)
    ssid_vendor = None
    operator = None
    name = essid or ''

    if oui_vendor:
        evidence.append('OUI 登记组织映射为 %s' % oui_vendor)
    for pattern, candidate in SSID_VENDOR_PATTERNS:
        if pattern.search(name):
            ssid_vendor = candidate
            evidence.append('SSID 命中可修改的 %s 命名特征' % candidate)
            break
    for pattern, candidate in OPERATOR_PATTERNS:
        if pattern.search(name):
            operator = candidate
            evidence.append('SSID 命中 %s 接入场景特征' % candidate)
            break

    conflict = bool(oui_vendor and ssid_vendor and oui_vendor != ssid_vendor)
    vendor = None if conflict else (oui_vendor or ssid_vendor)
    if conflict:
        evidence.append('OUI 与 SSID 证据冲突，不推断厂商')
    confidence = 'medium' if oui_vendor and not conflict else ('low' if vendor or operator else 'none')
    return {
        'vendor': vendor,
        'operator': operator,
        'confidence': confidence,
        'evidence': evidence,
        'conflict': conflict,
        'limitations': '被动特征不能确认型号、固件或漏洞状态',
    }


def get_advisory(bssid: str, essid: str = '') -> Optional[dict]:
    """厂商指纹 + 攻击路径排序；无防御清单。"""
    fingerprint = fingerprint_router(bssid, essid)
    if fingerprint['confidence'] == 'none':
        return None
    vendor = fingerprint.get('vendor')
    profile = CHINA_ROUTER_PROFILES.get(vendor)
    return {
        **fingerprint,
        'segment': profile.get('segment') if profile else None,
        'family': profile.get('family') if profile else None,
        'recommended_paths': VENDOR_ATTACK_PATHS.get(vendor) if vendor else None,
    }
