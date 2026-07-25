#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
国内 WiFi 密码智能策略（2026 前沿优化）

基于公开统计调研（CERNET 国内 WiFi 密码规律研究、运营商默认密码规律）：
  - 国内 WiFi 密码 8~11 位占比约 76%，其中 8 位与 11 位最高
  - 8 位密码中纯数字约占 73%（生日 YYYYMMDD、QQ 号、连续数字）
  - 11 位密码中手机号约占 71%（11 位纯数字）
  - 常见弱口令 TOP: 12345678 / 123456789 / 88888888 / 00000000
  - 运营商光猫(ChinaNet/CMCC/CU)存在默认密码规律

本模块只做「策略推荐 + hashcat 掩码生成」，不包含任何利用代码。
闭环方式: 在 Hashcat.crack_hc22000 字典阶段失败后，自动按优先级
追加国内常用掩码序列，体现自动化工具特点，无需用户手动指定。
"""

from __future__ import annotations

from typing import List


# 国内常用弱口令（8 位起步，WPA 最低 8 位）
CN_TOP_WEAK = [
    '12345678', '123456789', '88888888', '00000000',
    '1234567890', '11223344', '66666666', '11111111',
    '87654321', '12341234', 'admin123', 'password',
]


# 国内常用掩码（按成功率优先级排序，hashcat -a 3 语法）
# ?d 数字 ?l 小写字母 ?u 大写字母 ?s 特殊字符
CN_MASK_PIPELINE: List[str] = [
    # 1) 8 位纯数字（生日/QQ/连续，命中率最高，keyspace 1e8 GPU 秒级）
    '?d?d?d?d?d?d?d?d',
    # 2) 11 位手机号（纯数字，keyspace 1e11，可配合号段词典缩减）
    '?d?d?d?d?d?d?d?d?d?d?d',
    # 3) 10 位纯数字（部分老密码）
    '?d?d?d?d?d?d?d?d?d?d',
    # 4) 9 位纯数字
    '?d?d?d?d?d?d?d?d?d',
    # 5) 字母+数字常见组合: 3字母+8数字（姓名缩写+生日）
    '?l?l?l?d?d?d?d?d?d?d?d',
    # 6) 8 位数字+1 字母后缀
    '?d?d?d?d?d?d?d?d?l',
    # 7) 1 字母前缀+8 位数字
    '?l?d?d?d?d?d?d?d?d',
    # 8) 12 位纯数字（部分长密码）
    '?d?d?d?d?d?d?d?d?d?d?d?d',
]


# 运营商光猫 ESSID 特征 → 默认密码规律提示
ISP_ESSID_HINTS = {
    'chinanet': {
        'hint': '电信光猫常见默认密码: 8 位数字(贴纸/手机号后8位)',
        'masks': ['?d?d?d?d?d?d?d?d'],
    },
    'cmcc': {
        'hint': '移动光猫常见默认密码: 贴纸明文 / 手机号',
        'masks': ['?d?d?d?d?d?d?d?d', '?d?d?d?d?d?d?d?d?d?d?d'],
    },
    'cu': {
        'hint': '联通光猫常见默认密码: 贴纸明文 / 8 位数字',
        'masks': ['?d?d?d?d?d?d?d?d'],
    },
    'chinaunicom': {
        'hint': '联通光猫常见默认密码: 贴纸明文 / 8 位数字',
        'masks': ['?d?d?d?d?d?d?d?d'],
    },
}


def essid_matches_isp(essid: str) -> str | None:
    '''ESSID 匹配运营商特征，返回 ISP key 或 None。'''
    if not essid:
        return None
    low = essid.lower()
    for key in ISP_ESSID_HINTS:
        if key in low:
            return key
    return None


def recommend_masks(essid: str = '', vendor: str = '', limit: int = 4) -> List[str]:
    '''根据 ESSID/厂商推荐掩码序列（去重，按优先级，限制数量）。

    闭环: 被 Hashcat.crack_hc22000 在字典失败后自动调用。
    '''
    picked: List[str] = []

    # 运营商光猫优先
    isp = essid_matches_isp(essid)
    if isp:
        picked.extend(ISP_ESSID_HINTS[isp]['masks'])

    # 厂商特化: 小米/中兴常 8 位数字，华为常 8 位数字
    if vendor in ('Xiaomi', 'Huawei', 'ZTE', 'Tenda'):
        for m in ('?d?d?d?d?d?d?d?d', '?d?d?d?d?d?d?d?d?d?d?d'):
            if m not in picked:
                picked.append(m)

    # 补齐通用国内掩码管线
    for m in CN_MASK_PIPELINE:
        if m not in picked:
            picked.append(m)

    return picked[:limit]


def top_weak_words() -> List[str]:
    '''返回国内常用弱口令列表（供字典阶段补充）。'''
    return list(CN_TOP_WEAK)


if __name__ == '__main__':
    # 自检
    print('[cn_strategy] masks for Xiaomi/Mi-ABCD:', recommend_masks('Mi-ABCD', 'Xiaomi'))
    print('[cn_strategy] masks for ChinaNet-xx:', recommend_masks('ChinaNet-AB12', ''))
    print('[cn_strategy] top weak:', top_weak_words()[:5])
