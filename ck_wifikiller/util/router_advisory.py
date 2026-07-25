#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路由器厂商识别 + 已知默认凭证 / 漏洞咨询（2026）

设计原则:
  - 不内置任何利用代码，只做「识别 + 建议」，合规且最小侵入
  - 基于 OUI 前缀（BSSID 前 3 字节）推断厂商
  - 给出该厂商常见默认 SSID/密码模式、历史 CVE 提示、推荐攻击路径

数据来源: 公开 OUI 表 + 厂商默认配置常识 + CVE 公告摘要
（仅用于授权审计时的优先级排序，非利用）
"""

from __future__ import annotations

import re
from typing import Optional


# OUI 前缀（小写无分隔）→ 厂商
# 仅收录消费级路由器/AP 常见前缀，非完整 OUI 库
OUI_VENDORS: dict[str, str] = {
    # TP-Link
    '503e5d': 'TP-Link', 'f48f1c': 'TP-Link', 'ec086b': 'TP-Link',
    '5cceee': 'TP-Link', 'c0c5e8': 'TP-Link', '98dac4': 'TP-Link',
    '6032b1': 'TP-Link', '18a6f7': 'TP-Link',
    # Xiaomi / Redmi
    '8ceaf6': 'Xiaomi', '64cc2e': 'Xiaomi', '94d9b3': 'Xiaomi',
    'f8a463': 'Xiaomi', 'd49e2c': 'Xiaomi', '7811dcd2': 'Xiaomi',
    # Huawei
    '8cA47a': 'Huawei', '04f9e8': 'Huawei', '487db4': 'Huawei',
    'cc81da': 'Huawei', '800060': 'Huawei',
    # Tenda
    'c83a35': 'Tenda', '14660a': 'Tenda', '00b3fa': 'Tenda',
    'd8328f': 'Tenda',
    # Mercury
    '00b217': 'Mercury', 'a04e49': 'Mercury',
    # Fast
    '0050fc': 'Fast', '00ba55': 'Fast',
    # Netgear
    '000fb5': 'Netgear', '001e2a': 'Netgear', '0024b2': 'Netgear',
    'c03f0e': 'Netgear', '9c3dcf': 'Netgear', '204e7c': 'Netgear',
    # ASUS
    '000c6e': 'ASUS', '00112233': 'ASUS', 'f46d04': 'ASUS',
    'ac220b': 'ASUS', '38d547': 'ASUS',
    # D-Link
    '00055d': 'D-Link', '001195': 'D-Link', 'b8a386': 'D-Link',
    'f07d68': 'D-Link', '905ef4': 'D-Link',
    # Cisco / Linksys
    '000625': 'Linksys', '0017e6': 'Linksys', '001310': 'Linksys',
    'c86a2f': 'Linksys', '001f33': 'Cisco',
    # Ruijie / Reyee
    'd8cb8a': 'Ruijie', '48b09e': 'Ruijie', 'a0f849': 'Reyee',
    # H3C
    '000fe2': 'H3C', 'd05a4f': 'H3C',
    # ZTE
    'c86414': 'ZTE', 'f4efcd': 'ZTE', 'd8328f': 'ZTE',
    # Realtek (常见 USB 网卡/软 AP)
    '00e04c': 'Realtek', 'd8eb97': 'Realtek',
    # Ralink / MediaTek
    '0017c2': 'Ralink', '000ee8': 'MediaTek', '00e04c': 'MediaTek',
    # Apple (AirPort)
    '000a95': 'Apple', '0017f2': 'Apple', 'a4b197': 'Apple',
    # Broadcom (软 AP)
    '000f94': 'Broadcom',
}


# 厂商 → 审计建议（默认凭证模式 / 历史 CVE 提示 / 推荐路径）
VENDOR_ADVISORY: dict[str, dict] = {
    'TP-Link': {
        'default_ssid_patterns': ['TP-LINK_%(hex)s', 'TP-LINK_%(mac4)s'],
        'default_pin_patterns': ['12345670', '00000000', '厂商印于贴纸'],
        'common_defaults': ['admin/admin', 'admin/空', '贴纸密码'],
        'historical_cves': [
            'CVE-2023-1389 (TP-Link Archer AX21 命令注入)',
            '多款型号 WPS PIN = 贴纸明文，Pixie-Dust 成功率高',
        ],
        'recommended_paths': ['WPS Pixie-Dust 优先', 'PMKID (无客户端)', '默认词典 + 8 位数字掩码'],
    },
    'Xiaomi': {
        'default_ssid_patterns': ['Mi-%(mac4)s', 'Redmi-%(mac4)s', 'Xiaomi_%(mac4)s'],
        'default_pin_patterns': ['随机 8 位，贴纸可见'],
        'common_defaults': ['admin/空（Web 后台）', '随机密码（贴纸）'],
        'historical_cves': [
            '小米路由器历史命令注入 / 信息泄露多个 CVE',
            '部分固件 WPS 可被 Pixie-Dust',
        ],
        'recommended_paths': ['PMKID 优先', '8 位纯数字掩码 --mask ?d?d?d?d?d?d?d?d', '手机号词典'],
    },
    'Huawei': {
        'default_ssid_patterns': ['HUAWEI-%(mac4)s', 'HUAWEI-%(hex)s'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/空或贴纸', '随机密码（贴纸）'],
        'historical_cves': ['HG 系列历史 UPnP / TR-069 漏洞'],
        'recommended_paths': ['PMKID', '8 位数字掩码', '默认词典'],
    },
    'Tenda': {
        'default_ssid_patterns': ['Tenda_%(mac4)s'],
        'default_pin_patterns': ['12345670（历史默认）'],
        'common_defaults': ['admin/admin', 'admin/空'],
        'historical_cves': ['Tenda 多款命令注入 CVE（AC 系列）'],
        'recommended_paths': ['WPS Pixie-Dust（默认 PIN 常见）', 'PMKID', '默认词典'],
    },
    'Netgear': {
        'default_ssid_patterns': ['NETGEAR', 'NETGEAR%(model)s'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/password', 'admin/贴纸'],
        'historical_cves': ['Netgear 多款认证绕过 / 命令注入 CVE'],
        'recommended_paths': ['PMKID', '默认词典 + rules', 'WPS PIN'],
    },
    'ASUS': {
        'default_ssid_patterns': ['ASUS_%(mac4)s'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/admin'],
        'historical_cves': ['ASUS 路由器历史信息泄露 CVE'],
        'recommended_paths': ['PMKID', '默认词典', 'WPS Pixie-Dust'],
    },
    'D-Link': {
        'default_ssid_patterns': ['dlink-%(mac4)s', 'D-Link'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/空', 'admin/admin'],
        'historical_cves': ['D-Link 多款命令注入 / 认证绕过 CVE'],
        'recommended_paths': ['PMKID', '默认词典', 'WPS'],
    },
    'Linksys': {
        'default_ssid_patterns': ['linksys%(n)s', 'Linksys%(n)s'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/admin'],
        'historical_cves': ['Linksys EA/Velop 历史漏洞'],
        'recommended_paths': ['PMKID', '默认词典', 'WPS'],
    },
    'Ruijie': {
        'default_ssid_patterns': ['Ruijie_%(mac4)s', 'Reyee_%(mac4)s'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/admin'],
        'historical_cves': ['锐捷 EG/EGW 系列命令注入 CVE（企业级）'],
        'recommended_paths': ['PMKID', '默认词典', 'WPS'],
    },
    'ZTE': {
        'default_ssid_patterns': ['ChinaNet-%(mac4)s', 'ZTE-%(mac4)s'],
        'default_pin_patterns': ['贴纸随机'],
        'common_defaults': ['admin/admin', 'useradmin/useradmin'],
        'historical_cves': ['中兴 F 系列 UPnP / 命令注入 CVE'],
        'recommended_paths': ['PMKID', '8 位数字掩码', '默认词典'],
    },
}


def normalize_oui(bssid: str) -> str:
    """BSSID → 小写无分隔前 6 位。"""
    return re.sub(r'[^0-9a-f]', '', (bssid or '').lower())[:6]


def identify_vendor(bssid: str) -> Optional[str]:
    """根据 BSSID OUI 前缀识别厂商，未知返回 None。"""
    oui = normalize_oui(bssid)
    return OUI_VENDORS.get(oui)


def get_advisory(bssid: str) -> Optional[dict]:
    """返回该 BSSID 对应厂商的审计建议 dict；未知返回 None。"""
    vendor = identify_vendor(bssid)
    if not vendor:
        return None
    adv = VENDOR_ADVISORY.get(vendor)
    if not adv:
        return {'vendor': vendor, 'note': '已知厂商，暂无专项建议'}
    return {'vendor': vendor, **adv}
