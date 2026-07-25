#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中国大陆场景的授权口令强度核查策略。

这些掩码是有界测试模板，不代表任何品牌或运营商的默认口令规律。只有在
用户拥有目标且已获取可离线验证的握手材料时才应启用；程序不生成针对
特定设备的默认凭据，也不执行固件漏洞利用。
"""

from __future__ import annotations

from typing import List


CN_TOP_WEAK = [
    '12345678', '123456789', '88888888', '00000000',
    '1234567890', '11223344', '66666666', '11111111',
    '87654321', '12341234', 'admin123', 'password',
]

# WPA/WPA2 PSK 合法长度从 8 开始；顺序只表达计算成本，不表达命中率。
CN_MASK_PIPELINE: List[str] = [
    '?d?d?d?d?d?d?d?d',
    '?d?d?d?d?d?d?d?d?d',
    '?d?d?d?d?d?d?d?d?d?d',
    '?d?d?d?d?d?d?d?d?d?d?d',
    '?l?l?l?d?d?d?d?d?d?d?d',
    '?d?d?d?d?d?d?d?d?l',
    '?l?d?d?d?d?d?d?d?d',
    '?d?d?d?d?d?d?d?d?d?d?d?d',
]

ISP_ESSID_HINTS = {
    'chinanet': 'China Telecom',
    'cmcc': 'China Mobile',
    'chinaunicom': 'China Unicom',
    'cu-': 'China Unicom',
}


def essid_matches_isp(essid: str) -> str | None:
    """返回运营商场景标签；结果不用于推断设备厂商或默认口令。"""
    low = (essid or '').lower()
    for marker, operator in ISP_ESSID_HINTS.items():
        if marker in low:
            return operator
    return None


def recommend_masks(essid: str = '', vendor: str = '', limit: int = 4) -> List[str]:
    """返回有界、去重的弱口令强度测试模板。

    ``essid`` 与 ``vendor`` 为兼容现有调用保留；不会据此生成设备口令。
    """
    del essid, vendor
    bounded = max(0, min(8, int(limit)))
    return list(dict.fromkeys(CN_MASK_PIPELINE))[:bounded]


def top_weak_words() -> List[str]:
    """返回用于自有网络口令基线审计的最小弱口令集。"""
    return list(CN_TOP_WEAK)


if __name__ == '__main__':
    print('[cn_strategy] bounded masks:', recommend_masks(limit=4))
    print('[cn_strategy] weak baseline:', top_weak_words()[:5])
