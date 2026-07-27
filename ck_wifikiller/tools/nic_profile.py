#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""根据网卡驱动/芯片选择 deauth 发包策略。

目标：尽量踢得下（注入够猛）又不至于全程狂发打断 EAPOL。
策略在 send_deauth 里消费；探测失败则用 balanced 默认。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from ..util.process import Process


@dataclass(frozen=True)
class DeauthProfile:
    name: str
    # scapy | aireplay | both
    engine: str
    # 每向份数：0=用 scapy 内置 精准16/广播32
    per_dir: int
    rounds: int
    inter: float
    # aireplay -0 包数
    aireplay_count: int
    # Scapy 成功后是否仍用 aireplay 补刀
    aireplay_after_scapy: bool
    note: str


# 驱动关键字 → 配置（小写匹配）
# MT76/MT7921U：实测 Scapy 突发最稳（用户 auto_attack 参考）
_PROFILES = (
    (
        ('mt76', 'mt7921', 'mt7612', 'mt7601', 'mediatek'),
        DeauthProfile(
            name='mt76',
            engine='both',
            per_dir=0,
            rounds=4,
            inter=0.003,
            aireplay_count=64,
            aireplay_after_scapy=True,
            note='MediaTek mt76: Scapy burst primary + aireplay backup',
        ),
    ),
    (
        ('ath9k', 'ath10k', 'ath11k', 'ath12k', 'ath5k', 'carl9170'),
        DeauthProfile(
            name='ath',
            engine='both',
            per_dir=0,
            rounds=4,
            inter=0.002,
            aireplay_count=64,
            aireplay_after_scapy=True,
            note='Atheros: strong injection, dual channel',
        ),
    ),
    (
        ('rt2800', 'rt73', 'rtlwifi', 'rtl8xxx', 'r8188', '88x2',
         '8812', '8814', '8821', '8822', '8852', 'rtl88'),
        DeauthProfile(
            name='realtek',
            engine='both',
            per_dir=24,  # 稍加大每向份数
            rounds=4,
            inter=0.004,
            aireplay_count=64,  # 对齐 aireplay-ng 源码有向 64
            aireplay_after_scapy=True,
            note='Realtek: heavier aireplay + denser scapy',
        ),
    ),
    (
        ('iwlwifi', 'iwl'),
        DeauthProfile(
            name='intel',
            engine='both',
            per_dir=12,
            rounds=4,
            inter=0.005,
            aireplay_count=64,
            aireplay_after_scapy=True,
            note='Intel: limited inject, dual with moderate density',
        ),
    ),
    (
        ('brcmfmac', 'brcmutil', 'bcm'),
        DeauthProfile(
            name='broadcom',
            engine='aireplay',  # 许多 Broadcom 监控注入差，优先 aireplay
            per_dir=16,
            rounds=4,
            inter=0.005,
            aireplay_count=64,
            aireplay_after_scapy=False,
            note='Broadcom: prefer aireplay (inject often weak)',
        ),
    ),
    (
        ('ralink', 'rt2x00'),
        DeauthProfile(
            name='ralink',
            engine='both',
            per_dir=0,
            rounds=4,
            inter=0.003,
            aireplay_count=64,
            aireplay_after_scapy=True,
            note='Ralink: dual channel',
        ),
    ),
)

_DEFAULT = DeauthProfile(
    name='balanced',
    engine='both',
    per_dir=0,
    rounds=4,
    inter=0.003,
    aireplay_count=64,
    aireplay_after_scapy=True,
    note='default balanced dual-channel',
)


def _read_driver_symlink(iface: str) -> str:
    '''/sys/class/net/<iface>/device/driver → 驱动名'''
    if not iface:
        return ''
    # mon 口常挂在 phy 下，先试 iface，再试去掉 mon 后缀
    candidates = [iface]
    if iface.endswith('mon'):
        candidates.append(iface[:-3])
    for name in candidates:
        path = f'/sys/class/net/{name}/device/driver'
        try:
            if os.path.islink(path):
                return os.path.basename(os.readlink(path)).lower()
        except OSError:
            pass
        # 部分 mon 设备
        path2 = f'/sys/class/net/{name}/device/driver'
        try:
            if os.path.isdir(f'/sys/class/net/{name}'):
                for root, dirs, files in os.walk(f'/sys/class/net/{name}', topdown=True):
                    if 'driver' in dirs or 'driver' in files:
                        pass
                    break
        except OSError:
            pass
    return ''


def _driver_from_ethtool(iface: str) -> str:
    if not iface or not Process.exists('ethtool'):
        return ''
    try:
        out = Process(['ethtool', '-i', iface]).stdout() or ''
        m = re.search(r'^driver:\s*(\S+)', out, re.M)
        return (m.group(1) if m else '').lower()
    except Exception:
        return ''


def _driver_from_airmon(iface: str) -> str:
    '''解析 airmon-ng 表。'''
    if not Process.exists('airmon-ng'):
        return ''
    try:
        out = Process(['airmon-ng']).stdout() or ''
    except Exception:
        return ''
    base = iface[:-3] if iface.endswith('mon') else iface
    for line in out.splitlines():
        if iface in line or base in line:
            parts = re.split(r'\s+', line.strip())
            # PHY IFACE DRIVER CHIPSET 或 IFACE DRIVER CHIPSET
            if len(parts) >= 3:
                # 找驱动列：非 phy 名、非 iface
                for p in parts:
                    pl = p.lower()
                    if pl in (iface.lower(), base.lower()):
                        continue
                    if pl.startswith('phy'):
                        continue
                    if re.match(r'^[a-z0-9_]+$', pl) and len(pl) > 2:
                        return pl
    return ''


def detect_driver(iface: Optional[str] = None) -> str:
    from ..config import Configuration
    iface = iface or getattr(Configuration, 'interface', None) or ''
    for fn in (_read_driver_symlink, _driver_from_ethtool, _driver_from_airmon):
        d = fn(iface)
        if d:
            return d
    return ''


def profile_for_driver(driver: str) -> DeauthProfile:
    d = (driver or '').lower()
    if not d:
        return _DEFAULT
    for keys, prof in _PROFILES:
        if any(k in d for k in keys):
            return prof
    return _DEFAULT


@lru_cache(maxsize=8)
def get_deauth_profile(iface: str = '') -> DeauthProfile:
    '''带缓存的网卡 deauth 配置。'''
    drv = detect_driver(iface or None)
    return profile_for_driver(drv)


def describe_profile(iface: Optional[str] = None) -> str:
    from ..config import Configuration
    iface = iface or getattr(Configuration, 'interface', None) or ''
    drv = detect_driver(iface)
    prof = profile_for_driver(drv)
    return 'driver=%s profile=%s engine=%s rounds=%d aireplay=%d (%s)' % (
        drv or 'unknown',
        prof.name,
        prof.engine,
        prof.rounds,
        prof.aireplay_count,
        prof.note,
    )
