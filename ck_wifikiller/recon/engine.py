#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第一层：无线侦察 (Recon) 编排引擎

设计原则:
  - 不重写 Kismet/bettercap，做「工具链编排 + 结果汇总 + 与攻击层衔接」
  - 2026 推荐栈见 docs/TOOLCHAIN-2026.md

后端优先级:
  1) Kismet  — 全频谱资产 / 指纹 / BT / Zigbee / WIDS
  2) bettercap — 主动 WiFi recon + PMKID assoc
  3) airodump-ng — 经典 AP/客户端表（已有 Scanner）
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone

from ..util.color import Color
from ..util.process import Process
from ..tools.kismet import Kismet
from ..tools.bettercap_wifi import BettercapWifi


class ReconEngine:
    """打印工具矩阵、生成 caplet/报告、检测 Kali 依赖。"""

    TOOL_MATRIX = [
        {
            'layer': 1,
            'name': 'Kismet',
            'role': '无线 Nmap + WIDS + 多 PHY',
            'covers': [
                '周围无线资产',
                'AP 指纹 (厂商 IE)',
                '客户端行为',
                '信道利用率',
                'Bluetooth / BTLE',
                'Zigbee / 802.15.4',
                '可疑 AP / 告警',
            ],
            'binary': 'kismet',
            'apt': 'kismet kismet-capture-linux-wifi kismet-capture-linux-bluetooth',
        },
        {
            'layer': 1,
            'name': 'bettercap',
            'role': '主动 WiFi recon / PMKID / deauth 编排',
            'covers': ['扫描', 'PMKID assoc', '握手自动存', '假 AP 探测辅助'],
            'binary': 'bettercap',
            'apt': 'bettercap',
        },
        {
            'layer': 1,
            'name': 'airodump-ng',
            'role': '经典 AP/客户端列表 (ck-wifikiller 内置 Scanner)',
            'covers': ['ESSID/BSSID/信道/加密/客户端'],
            'binary': 'airodump-ng',
            'apt': 'aircrack-ng',
        },
        {
            'layer': 1,
            'name': 'iw / iwlist',
            'role': '内核级接口与扫描补充',
            'covers': ['接口能力', '监管域', '扫描缓存'],
            'binary': 'iw',
            'apt': 'iw',
        },
        {
            'layer': 2,
            'name': 'hcxdumptool',
            'role': 'PMKID + EAPOL 采集 (现代 pcapng)',
            'covers': ['PMKID', 'M1–M4', '客户端挑战'],
            'binary': 'hcxdumptool',
            'apt': 'hcxdumptool',
        },
        {
            'layer': 2,
            'name': 'hcxpcapngtool',
            'role': '转 hashcat -m 22000',
            'covers': ['hc22000', 'ESSID 词表 -E'],
            'binary': 'hcxpcapngtool',
            'apt': 'hcxtools',
        },
        {
            'layer': 3,
            'name': 'hashcat',
            'role': 'GPU 离线爆破',
            'covers': ['22000 PMKID+EAPOL'],
            'binary': 'hashcat',
            'apt': 'hashcat',
        },
    ]

    @classmethod
    def print_matrix(cls) -> None:
        Color.pl('')
        Color.pl('{+} {C}ck-wifikiller · 2026 无线工具链矩阵{W}')
        Color.pl('{+} {D}编排集成市面主力工具，而非重复实现其内核{W}')
        Color.pl('')
        for t in cls.TOOL_MATRIX:
            ok = Process.exists(t['binary'])
            flag = '{G}OK{W}' if ok else '{O}MISSING{W}'
            Color.pl(
                '  [{D}L%d{W}] {C}%-16s{W} %s  %s'
                % (t['layer'], t['name'], flag, t['role'])
            )
            Color.pl('       {D}apt: %s{W}' % t['apt'])
            Color.pl('       {D}%s{W}' % ', '.join(t['covers'][:6]))
        Color.pl('')

    @classmethod
    def missing_apt_packages(cls) -> list[str]:
        missing = []
        for t in cls.TOOL_MATRIX:
            if not Process.exists(t['binary']):
                # 只返回主包名第一段
                missing.append(t['apt'].split()[0])
        # 去重保序
        seen = set()
        out = []
        for m in missing:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out

    @classmethod
    def run_cli(cls, mode: str = 'status') -> None:
        """
        mode:
          status  — 矩阵 + 依赖
          kismet  — Kismet 启动指南 + REST 摘要
          bettercap — 写 caplet
          report  — 汇总 JSON
        """
        cls.print_matrix()
        miss = cls.missing_apt_packages()
        if miss:
            Color.pl('{!} 缺少组件，Kali 可执行:')
            Color.pl('{+}   {C}sudo apt update && sudo apt install -y %s{W}' % ' '.join(miss))
            Color.pl('')

        if mode in ('status', 'kismet', 'report'):
            Kismet.ensure_message()
        if mode == 'kismet':
            Kismet.launch_guide()
            summary = Kismet.fetch_summary()
            if summary.get('kismet_up'):
                Color.pl('{+} Kismet REST: {G}up{W}')
                n = len(summary.get('devices_sample') or [])
                Color.pl('{+} devices sample: {C}%d{W}' % n)
            else:
                Color.pl('{!} %s' % summary.get('note', 'Kismet REST unavailable'))

        if mode == 'bettercap':
            if BettercapWifi.exists():
                BettercapWifi.write_caplet()
            else:
                Color.pl('{!} bettercap missing — %s' % BettercapWifi.package_hint())

        if mode == 'clients':
            # 自动扫描 WiFi 并检测有在线客户端的 AP（需要 root + 监听网卡）
            from .clients import ClientsScan
            scan_time = getattr(Configuration, 'scan_time', 0) or None
            ClientsScan(scan_time=scan_time).run()
            return

        if mode == 'report':
            report = {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'matrix': cls.TOOL_MATRIX,
                'missing': miss,
                'kismet': Kismet.fetch_summary(),
                'binaries': {
                    t['binary']: bool(shutil.which(t['binary']))
                    for t in cls.TOOL_MATRIX
                },
            }
            path = os.path.join(os.getcwd(), 'ck-recon-report.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            Color.pl('{+} Full recon report: {C}%s{W}' % path)
            Kismet.write_recon_report()
