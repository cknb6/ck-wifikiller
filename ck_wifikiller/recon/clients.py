#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""--recon clients：自动扫描 WiFi，列出每个 AP 的在线客户端。

用法:
  sudo ck-wifikiller --recon clients            # 默认扫描 15s
  sudo ck-wifikiller --recon clients -p 30      # 扫描 30s
  sudo ck-wifikiller --recon clients --showb    # 显示 ESSID 列
  sudo ck-wifikiller --recon clients --5ghz     # 含 5GHz 频段

输出:
  1) 扫描期实时进度行（\r 覆盖刷新）
  2) 结束后的完整报告：有在线客户端的 AP 优先列出
     BSSID / SSID / CH / 加密 / 信号 / 客户端数量 + 客户端 MAC 列表（OUI 厂商）
  3) 报告同时保存到 ck-clients-report.txt
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime

from ..config import Configuration
from ..tools.airodump import Airodump
from ..util.color import Color
from ..util.i18n import t
from ..util.router_advisory import (
    _database_paths,
    _load_oui_database,
    identify_vendor,
    normalize_oui,
)
from ..util.term_layout import pad

# 终端颜色/样式标记，如 {G} {O} {W} {D}
_TAG_RE = re.compile(r'\{[A-Za-z]\}')

# 报告表格列宽（纯文本列，BSSID 17 字符）
_COL_BSSID = 17
_COL_SSID = 20


def _strip_tags(line: str) -> str:
    """去掉 Color 标记，用于写文件时保存纯文本。"""
    return _TAG_RE.sub('', line)


def _client_vendor(mac: str) -> str | None:
    """客户端 MAC 厂商识别：优先品牌归一化，退回 OUI 原始登记名。

    手机/电脑（Apple/Samsung/Xiaomi/Huawei 等）不在中国路由器品牌表内，
    因此直接展示 OUI 数据库中的原始组织名，尽力而为。
    """
    vendor = identify_vendor(mac)
    if vendor:
        return vendor
    oui = normalize_oui(mac)
    if not oui:
        return None
    raw = _load_oui_database(_database_paths()).get(oui)
    if not raw:
        return None
    name = ' '.join((raw or '').split())
    return (name[:30] or None)


class ClientsScan:
    """扫描全部信道并收集每个 AP 的在线客户端。"""

    DEFAULT_SCAN_TIME = 15
    REPORT_NAME = 'ck-clients-report.txt'

    def __init__(self, scan_time: int | None = None):
        self.scan_time = max(3, int(scan_time or self.DEFAULT_SCAN_TIME))
        self.targets = []
        self.interface = '?'
        self.started_at = ''

    # ---------------------------------------------------------------
    # 扫描循环
    # ---------------------------------------------------------------

    def run(self) -> int:
        self.interface = Configuration.interface or '?'
        self.started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        start = time.time()
        try:
            with Airodump() as airodump:
                while True:
                    if airodump.pid.poll() is not None:
                        Color.pl('{!} {R}airodump-ng exited unexpectedly{W}')
                        break
                    self.targets = airodump.get_targets(old_targets=self.targets)
                    remaining = max(0, start + self.scan_time - time.time())
                    self._render_progress(remaining)
                    if remaining <= 0:
                        break
                    time.sleep(0.5)
            Color.pl('')
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}%s{W}' % t('interrupted'))

        self._report()
        return 0

    def _render_progress(self, remaining: int) -> None:
        """单行 \\r 覆盖刷新，避免清屏闪烁。"""
        total_clients = sum(len(t.clients) for t in self.targets)
        line = t('clients.scanning', self.scan_time, len(self.targets),
                 total_clients, int(remaining))
        Color.p('\r{D}%s{W}' % line.ljust(80))

    # ---------------------------------------------------------------
    # 报告生成
    # ---------------------------------------------------------------

    def _targets_sorted(self) -> list:
        """在线 AP 优先，按客户端数量降序。"""
        online = [t for t in self.targets if t.clients]
        idle = [t for t in self.targets if not t.clients]
        online.sort(key=lambda t: len(t.clients), reverse=True)
        idle.sort(key=lambda t: (t.essid or '').lower())
        return online, idle

    def _report(self) -> None:
        online, idle = self._targets_sorted()
        total_devices = sum(len(t.clients) for t in self.targets)
        lines = []

        # 标题区
        lines.append('=' * 72)
        lines.append('{G}%s{W}' % t('clients.title'))
        lines.append('-' * 72)
        lines.append(t('clients.meta', self.interface, self.scan_time, self.started_at))
        lines.append(t('clients.summary', len(self.targets), len(online), total_devices))
        lines.append('-' * 72)

        # 表头
        header = (
            pad(t('scan.hdr_num'), 4, align='right') + '  ' +
            pad('BSSID', _COL_BSSID) + '  ' +
            pad(t('scan.hdr_essid'), _COL_SSID) + '  ' +
            pad(t('scan.hdr_ch'), 4, align='right') + '  ' +
            pad(t('scan.hdr_encr'), 5) + '  ' +
            pad(t('scan.hdr_power'), 5, align='right') + '  ' +
            pad('CLI', 4, align='right')
        )

        # 有在线客户端的 AP
        if online:
            lines.append('{C}%s{W}' % t('clients.online_section', len(online)))
            lines.append(header)
            for idx, target in enumerate(online, 1):
                lines.append(self._ap_row(idx, target))
                for client in target.clients:
                    vendor = _client_vendor(client.station)
                    vendor_txt = vendor or t('clients.unknown')
                    lines.append('      %s  {D}%s{W}' % (client.station, vendor_txt))
                lines.append('')
            lines.append('-' * 72)

        # 无客户端的 AP
        if idle:
            lines.append(t('clients.idle_section', len(idle)))
            lines.append(header)
            for idx, target in enumerate(idle, 1):
                lines.append(self._ap_row(idx, target))
            lines.append('-' * 72)

        lines.append('{D}%s{W}' % t('clients.oui_note'))

        # 终端输出
        for line in lines:
            Color.pl(line)

        # 保存纯文本报告
        try:
            path = os.path.join(os.getcwd(), self.REPORT_NAME)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(_strip_tags(l) for l in lines) + '\n')
            Color.pl('{+} %s{W}' % t('clients.saved', path))
        except OSError as e:
            Color.pl('{!} {R}%s{W}' % e)

    def _ap_row(self, idx: int, target) -> str:
        """单行 AP 摘要。"""
        essid = target.essid or t('clients.hidden')
        pwr = getattr(target, 'power', None)
        pwr_txt = str(pwr) if pwr is not None else '?'
        encr = (target.encryption or '?').upper()[:5]
        return (
            pad(str(idx), 4, align='right') + '  ' +
            pad(target.bssid, _COL_BSSID) + '  ' +
            pad(essid, _COL_SSID) + '  ' +
            pad(str(target.channel), 4, align='right') + '  ' +
            pad(encr, 5) + '  ' +
            pad(pwr_txt, 5, align='right') + '  ' +
            pad(str(len(target.clients)), 4, align='right')
        )
