#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kismet 集成 — 2026 无线侦察第一层

定位: 无线版 Nmap + WIDS（不做二次实现，做编排与结果消费）
Kali: sudo apt install kismet
官方: https://www.kismetwireless.net/  (2025-09-R1+ 支持现代 WPA3/指纹/BT/Zigbee)

能力映射:
  - 周围无线资产 / AP 指纹 / 客户端行为 / 信道利用率
  - Bluetooth / Zigbee / SDR 数据源 (取决于已装 capture helper)
  - 可疑 AP / WIDS 告警 (Kismet REST)

本模块: 启动引导、依赖检测、REST 摘要、生成 recon 报告 JSON。
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .dependency import Dependency
from ..util.color import Color
from ..util.process import Process
from ..config import Configuration


class Kismet(Dependency):
    dependency_required = False
    dependency_name = 'kismet'
    dependency_url = 'https://www.kismetwireless.net/'

    # 默认本地 REST（Kismet 新版 web UI）
    DEFAULT_HTTP = 'http://127.0.0.1:2501'

    @classmethod
    def package_hint(cls) -> str:
        return (
            'sudo apt install -y kismet kismet-capture-linux-wifi '
            'kismet-capture-linux-bluetooth'
        )

    @classmethod
    def ensure_message(cls) -> None:
        if cls.exists():
            Color.pl('{+} Kismet: {G}found{W}')
            Color.pl('{+} {D}可选: Zigbee/SDR → apt search kismet-capture{W}')
        else:
            Color.pl('{!} Kismet: {O}not found{W} — %s' % cls.package_hint())

    @classmethod
    def launch_guide(cls, interface: str | None = None) -> None:
        """打印在 Kali 上推荐的启动方式（用户确认后自行跑，避免抢网卡）。"""
        iface = interface or Configuration.interface or 'wlan0'
        Color.pl('')
        Color.pl('{+} {C}=== Layer-1 Recon: Kismet ==={W}')
        Color.pl('{+} 1) 停止占用网卡的服务: {C}sudo systemctl stop NetworkManager{W} (按需)')
        Color.pl('{+} 2) 启动: {C}sudo kismet -c %s{W}' % iface)
        Color.pl('{+}    或数据源: {C}sudo kismet -c %s:name=wifi{W}' % iface)
        Color.pl('{+} 3) Web UI / REST: {C}%s{W}' % cls.DEFAULT_HTTP)
        Color.pl('{+} 4) BT: 确保已装 {C}kismet-capture-linux-bluetooth{W} 并加载 HCI 源')
        Color.pl('{+} 5) Zigbee: {C}kismet-capture-freaklabs-zigbee{W} / KillerBee / TI CC2531 等')
        Color.pl('{+} 文档: 见仓库 docs/TOOLCHAIN-2026.md')
        Color.pl('')

    @classmethod
    def rest_get(cls, path: str, base: str | None = None, timeout: float = 3.0) -> dict | list | None:
        """无认证探测本地 Kismet REST（若开启）。"""
        base = (base or cls.DEFAULT_HTTP).rstrip('/')
        url = base + path
        try:
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
                return json.loads(raw)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
            return None

    @classmethod
    def fetch_summary(cls, base: str | None = None) -> dict:
        """拉取设备/系统摘要（Kismet 运行中时）。"""
        summary = {
            'kismet_up': False,
            'system': None,
            'devices_sample': [],
            'note': '',
        }
        sysinfo = cls.rest_get('/system/status.json', base=base) or cls.rest_get(
            '/system/status.json', base=base
        )
        # 不同版本路径可能变化
        if sysinfo is None:
            sysinfo = cls.rest_get('/api/v1/system/status', base=base)
        if sysinfo is None:
            summary['note'] = '无法连接 Kismet REST（未启动或需登录/新 API 路径）'
            return summary

        summary['kismet_up'] = True
        summary['system'] = sysinfo if isinstance(sysinfo, dict) else {'raw': sysinfo}

        devices = (
            cls.rest_get('/devices/summary/devices.json', base=base)
            or cls.rest_get('/devices/last-time/0/devices.json', base=base)
        )
        if isinstance(devices, list):
            summary['devices_sample'] = devices[:50]
        elif isinstance(devices, dict):
            # 某些版本包在键里
            for key in ('devices', 'data', 'results'):
                if key in devices and isinstance(devices[key], list):
                    summary['devices_sample'] = devices[key][:50]
                    break
        return summary

    @classmethod
    def write_recon_report(cls, out_path: str | None = None) -> str:
        """写 recon 报告 JSON。"""
        report = {
            'layer': 'recon',
            'engine': 'kismet',
            'role': 'wireless Nmap + WIDS + multi-PHY (WiFi/BT/Zigbee/SDR)',
            'kali_packages': [
                'kismet',
                'kismet-capture-linux-wifi',
                'kismet-capture-linux-bluetooth',
                'kismet-capture-freaklabs-zigbee',
                'kismet-capture-rz-killerbee',
                'kismet-capture-ubertooth-one',
            ],
            'summary': cls.fetch_summary(),
        }
        path = out_path or os.path.join(os.getcwd(), 'ck-recon-kismet.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        Color.pl('{+} Recon report: {C}%s{W}' % path)
        return path
