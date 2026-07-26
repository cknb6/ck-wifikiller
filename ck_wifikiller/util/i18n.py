#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""界面语言：中文或英文二选一，不混用。

优先级:
  1) 环境变量 CK_WIFI_LANG=zh|en|cn|zh_CN|en_US
  2) LANG / LC_ALL / LC_MESSAGES
  3) 默认英文
"""

from __future__ import annotations

import os
from typing import Any

_LANG: str | None = None  # 'zh' | 'en'


def _detect() -> str:
    raw = (os.environ.get('CK_WIFI_LANG')
           or os.environ.get('LANG')
           or os.environ.get('LC_ALL')
           or os.environ.get('LC_MESSAGES')
           or 'en').strip().lower()
    if raw in ('zh', 'cn', 'chinese') or raw.startswith('zh'):
        return 'zh'
    return 'en'


def lang() -> str:
    global _LANG
    if _LANG is None:
        _LANG = _detect()
    return _LANG


def is_zh() -> bool:
    return lang() == 'zh'


def set_lang(code: str | None) -> None:
    """测试或 CLI 覆盖。code: zh/en/None(重新检测)。"""
    global _LANG
    if code is None:
        _LANG = None
        return
    c = code.strip().lower()
    _LANG = 'zh' if c in ('zh', 'cn') or c.startswith('zh') else 'en'


# 文案表：key -> (en, zh)
_S: dict[str, tuple[str, str]] = {
    # splash
    'splash.title': (
        'ck-wifikiller  ·  wireless auditor',
        'ck-wifikiller  ·  无线审计',
    ),
    'splash.sub': (
        'PMKID · handshake · WPS · hashcat 22000',
        'PMKID · 握手 · WPS · hashcat 22000',
    ),
    'splash.version': ('Version  %s', '版本    %s'),
    'splash.author': ('Author   %s', '作者    %s'),
    'splash.github': ('GitHub   %s', '仓库    %s'),
    'splash.profile': ('Profile  %s', '主页    %s'),
    'splash.sponsor': (
        'Sponsor  WeChat %s  note: wifi赞助',
        '赞助    微信 %s  备注: wifi赞助',
    ),
    'splash.email': ('Email    %s', '邮箱    %s'),
    'splash.biz': (
        'Business WeChat note: 商务合作',
        '商务    微信备注: 商务合作',
    ),
    'splash.legal': (
        'Authorized testing only',
        '仅限授权测试',
    ),

    # main
    'need_root': (
        'must run as root (sudo)',
        '需要 root 权限 (sudo)',
    ),
    'need_root_recon': (
        'Kismet/bettercap usually need root',
        'Kismet/bettercap 通常需要 root',
    ),
    'attack_done': (
        'finished %d target(s)',
        '完成 %d 个目标',
    ),
    'exiting': ('exiting', '退出'),
    'interrupted': ('interrupted', '已中断'),

    # scanner
    'scan.progress': (
        'scanning%s · %d AP · %d client · Ctrl+C when ready',
        '扫描中%s · %d 个 AP · %d 个客户端 · 就绪后 Ctrl+C',
    ),
    'scan.decloak': (' + decloak', ' + 去隐藏'),
    'scan.select': (
        'select targets (1-%d; space/comma e.g. 1 3 5; range 1-3; all): ',
        '选择目标 (1-%d；空格/逗号如 1 3 5；区间 1-3；all): ',
    ),
    'scan.empty_select': (
        'empty input, try again',
        '输入为空，请重新选择',
    ),
    'scan.invalid_select': (
        'invalid selection, try again',
        '选择无效，请重新输入',
    ),
    'scan.none': (
        'no targets found',
        '未发现目标',
    ),
    'scan.none_selected': (
        'no targets selected',
        '未选择目标',
    ),

    # 表头：中文须与列宽匹配（全角占 2 列）；过长会在 pad 时被截成「…」
    'scan.hdr_num': ('NUM', '序号'),
    'scan.hdr_essid': ('ESSID', '名称'),
    'scan.hdr_bssid': ('BSSID', 'BSSID'),
    'scan.hdr_ch': ('CH', '信道'),
    'scan.hdr_encr': ('ENCR', '加密'),
    'scan.hdr_power': ('PWR', '信号'),
    'scan.hdr_wps': ('WPS', 'WPS'),
    'scan.hdr_cli': ('CLI', '客户'),  # 2 字=4 列，避免「客户端」被截成 ...

    # attack
    'atk.none': (
        'no attack available',
        '无可用攻击',
    ),
    'atk.skip_hidden': (
        'skip %d hidden/unnamed AP(s)',
        '跳过 %d 个隐藏/无名称 AP',
    ),
    'atk.none_named': (
        'no named APs left to attack',
        '没有带名称的 AP 可攻击',
    ),
    'atk.wpa3_trans': (
        'WPA3 transition — may use WPA2 path',
        'WPA3 过渡模式 — 可走 WPA2',
    ),
    'atk.wpa3_sae': (
        'WPA3-SAE only — offline crack N/A',
        '纯 WPA3-SAE — 无法离线爆破',
    ),
    'atk.start': (
        '(%d/%d) attack %s (%s)',
        '(%d/%d) 攻击 %s (%s)',
    ),
    'atk.wps_note': (
        'WPS tools missing (reaver/bully)',
        '缺少 WPS 工具 (reaver/bully)',
    ),
    'atk.cont': (
        '%s left — [c]ontinue [s]kip [e]xit? ',
        '剩余 %s — 继续[c] 跳过[s] 退出[e]? ',
    ),
    'atk.plan': (
        'plan: %s',
        '计划: %s',
    ),
    'atk.budget_done': (
        'target budget used, next AP',
        '目标预算用尽，下一 AP',
    ),

    # wpa/pmkid brief
    'wpa.skip_wps_only': (
        'skip handshake (--wps-only)',
        '跳过握手 (--wps-only)',
    ),
    'wpa.no_wordlist': (
        'no wordlist, skip crack',
        '无字典，跳过爆破',
    ),
    'wpa.wordlist_missing': (
        'wordlist not found: %s',
        '字典不存在: %s',
    ),
    'wpa.crack': (
        'cracking with %s ...',
        '爆破中 %s ...',
    ),
    'wpa.fail': (
        'not in wordlist',
        '字典未命中',
    ),
    'wpa.ok': (
        'cracked: %s',
        '已破解: %s',
    ),
    'wpa.cn_skip': (
        'skip CN masks (need hashcat/hcxpcapngtool)',
        '跳过国内掩码（缺 hashcat/hcxpcapngtool）',
    ),
    'wpa.cn_fail': (
        'CN mask convert failed: %s',
        '国内掩码转换失败: %s',
    ),
    'wpa.cn_run': (
        'CN masks: %d stage(s)',
        '国内掩码: %d 阶段',
    ),
    'wpa.capture_fail': (
        'handshake timeout (%ds)',
        '握手超时 (%ds)',
    ),
    'wpa.save': (
        'saved %s',
        '已保存 %s',
    ),
    'wpa.analyze': (
        'analysis of captured handshake:',
        '分析已捕获握手:',
    ),
    'wpa.hs_ok': (
        '%s.cap contains a valid handshake for',
        '%s.cap 含有效握手:',
    ),
    'wpa.hs_no': (
        '%s.cap does not contain a valid handshake',
        '%s.cap 未检出有效握手',
    ),
    'wpa.hs_ok_note': (
        '(other tools confirmed; aircrack can disagree)',
        '（其他工具已确认；aircrack 判定更严，可忽略）',
    ),
    'wpa.capturing': (
        'listening (clients:%d, deauth:%s, timeout:%s)',
        '监听中 (客户:%d, 断连:%s, 超时:%s)',
    ),
    'wpa.wait_target': (
        'waiting for target...',
        '等待目标出现...',
    ),
    'wpa.exist_hs': (
        'found existing handshake for %s',
        '发现已有握手 %s',
    ),
    'wpa.use_hs': (
        'using handshake from %s',
        '使用握手文件 %s',
    ),
    'wpa.captured': (
        'captured handshake',
        '已捕获握手',
    ),
    'wpa.new_client': (
        'new client: %s',
        '发现客户端: %s',
    ),
    'wpa.crack_prog': (
        'cracking WPA: %0.2f%% ETA:%s @ %0.1fkps (key: %s)',
        '爆破 WPA: %0.2f%% 剩余:%s @ %0.1fkps (当前: %s)',
    ),
    'pmkid.skip': (
        'skip PMKID (missing: %s)',
        '跳过 PMKID（缺少: %s）',
    ),
    'pmkid.install': (
        'Kali: sudo apt install hashcat hcxdumptool hcxtools',
        'Kali: sudo apt install hashcat hcxdumptool hcxtools',
    ),
    'pmkid.exist': (
        'use existing hash %s',
        '使用已有哈希 %s',
    ),
    'pmkid.wait': (
        'waiting PMKID (%s)',
        '等待 PMKID (%s)',
    ),
    'pmkid.fail': (
        'PMKID capture failed',
        'PMKID 捕获失败',
    ),
    'pmkid.hint': (
        'some APs need client probe traffic',
        '部分 AP 需客户端探测流量',
    ),
    'pmkid.ok': (
        'PMKID captured',
        '已捕获 PMKID',
    ),
    'pmkid.crack_fail': (
        'PMKID not cracked',
        'PMKID 未破解',
    ),
    'pmkid.interrupted': (
        'PMKID crack interrupted',
        'PMKID 爆破已中断',
    ),
    'pmkid.no_wordlist': (
        'no wordlist, skip PMKID crack (--dict)',
        '无字典，跳过 PMKID 爆破 (--dict)',
    ),
    'pmkid.save': (
        'saving hc22000 hash to %s',
        '保存 hc22000 哈希到 %s',
    ),

    # update
    'upd.found': (
        'update: %s -> %s',
        '有新版本: %s -> %s',
    ),
    'upd.how': (
        'upgrade: git pull  or  apt install ./ck-wifikiller_*.deb',
        '升级: git pull  或  apt install ./ck-wifikiller_*.deb',
    ),

    # monitor / airmon common
    'mon.looking': (
        'looking for wireless interfaces...',
        '正在查找无线网卡...',
    ),
    'mon.checking': (
        'checking airmon-ng...',
        '正在检查 airmon-ng...',
    ),
    'mon.none': (
        'no wireless interfaces found',
        '未发现无线网卡',
    ),
    'mon.none_hint': (
        'connect a Wi-Fi adapter and retry',
        '请插入无线网卡后重试',
    ),
    'mon.auto_one': (
        'only one interface, auto-using %s',
        '仅一块网卡，自动使用 %s',
    ),
    'mon.use_existing': (
        'using %s (already monitor mode)',
        '使用 %s（已是监听模式）',
    ),
    'mon.multi_mon': (
        'multiple monitor interfaces, choose one:',
        '检测到多块监听网卡，请选择:',
    ),
    'mon.select': (
        'select wireless interface (1-%d): ',
        '选择无线网卡 (1-%d): ',
    ),
    'mon.selected': (
        'selected %s',
        '已选择 %s',
    ),
    'mon.invalid': (
        'invalid choice, try again',
        '选择无效，请重新输入',
    ),
    'mon.enable': (
        'monitor mode on %s ... %s',
        '开启监听模式 %s ... %s',
    ),
    'mon.enabled': ('ok %s', '完成 %s'),
    'mon.fail': ('failed', '失败'),
    'conflict': (
        'conflicting processes: %s',
        '冲突进程: %s',
    ),
    'conflict.hint': (
        'use --kill or stop them manually',
        '可用 --kill 或手动停止',
    ),

    # option prefix (config load)
    'opt': ('option:', '选项:'),
}


def t(key: str, *args: Any) -> str:
    """取当前语言文案；支持 % 格式化。"""
    pair = _S.get(key)
    if not pair:
        return key if not args else (key % args)
    text = pair[0] if lang() == 'en' else pair[1]
    if args:
        try:
            return text % args
        except TypeError:
            return text
    return text
