#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 AP 并选择目标。

表格刷新采用 wifite 经典「光标上移就地覆盖」：
  始终只有一张表 + 底部一行状态，每秒原地刷新。
关键修正:
  1) 上移行数 = header+sep+N 目标 + 状态行 = N+3（从状态行回到表头需 N+2）
  2) 上移必须用 Color.p，禁止 Color.pl（pl 会多换一行导致错位）
  3) 行数变少或装不下时才 clear
  4) Ctrl+C：可中断短 sleep；airodump 独立进程组，SIGINT 只打断 Python
"""

from __future__ import annotations

import re
from time import sleep, time

from ..util.color import Color
from ..tools.airodump import Airodump
from ..util.input import raw_input, xrange
from ..model.target import Target, WPSState
from ..config import Configuration


class Scanner(object):
    ''' Scans wifi networks & provides menu for selecting targets '''

    # 光标上移一行（CSI A）；wifite 用 \x1B[1F，两者在常见终端等价
    UP_CHAR = '\033[A'

    def __init__(self):
        self.previous_target_count = 0
        self._printed_rows = 0  # 上一帧表格占用行数（含 header/sep/targets，不含 status）
        self._has_status = False
        self.targets = []
        self.target = None
        self.err_msg = None
        max_scan_time = Configuration.scan_time

        try:
            with Airodump() as airodump:
                scan_start_time = time()

                while True:
                    if airodump.pid.poll() is not None:
                        # 子进程异常退出：尽量保留已扫到的目标
                        if not self.targets:
                            self.err_msg = Color.s(
                                '{!} {O}airodump-ng exited unexpectedly{W}')
                        break

                    self.targets = airodump.get_targets(old_targets=self.targets)

                    if self.found_target():
                        return

                    for target in self.targets:
                        if target.bssid in airodump.decloaked_bssids:
                            target.decloaked = True

                    self.print_targets()
                    self._print_status(airodump)

                    if max_scan_time > 0 and time() > scan_start_time + max_scan_time:
                        break

                    # 可中断 sleep：最多等 0.2s 就能响应 Ctrl+C
                    self._interruptible_sleep(1.0)

        except KeyboardInterrupt:
            # 一次 Ctrl+C：结束扫描，进入选目标（不要再 clear 整屏叠表）
            Color.pl('')
            self._has_status = False
            # 保留 previous 行数，选目标前会 force 干净重画一次

    @staticmethod
    def _interruptible_sleep(seconds: float) -> None:
        '''分段 sleep，便于尽快收到 KeyboardInterrupt。'''
        end = time() + max(0.0, seconds)
        while True:
            left = end - time()
            if left <= 0:
                return
            sleep(min(0.2, left))

    def found_target(self):
        bssid = Configuration.target_bssid
        essid = Configuration.target_essid

        if bssid is None and essid is None:
            return False

        for target in self.targets:
            if Configuration.wps_only and target.wps not in [WPSState.UNLOCKED, WPSState.LOCKED]:
                continue
            if bssid and target.bssid and bssid.lower() == target.bssid.lower():
                self.target = target
                break
            if essid and target.essid and essid.lower() == target.essid.lower():
                self.target = target
                break

        if self.target:
            Color.pl('\n{+} {C}found target{G} %s {W}({G}%s{W})'
                     % (self.target.bssid, self.target.essid))
            return True
        return False

    def _cursor_up(self, n: int) -> None:
        '''上移 n 行，禁止 pl（否则会多输出换行把布局打乱）。'''
        if n <= 0:
            return
        Color.p(self.UP_CHAR * n)

    def print_targets(self, force_full=False):
        '''打印/刷新目标表。force_full=True 时不依赖上移，直接在当前位置画新表。'''
        if len(self.targets) == 0:
            Color.p('\r')
            return

        from .i18n import t
        from .term_layout import pad, term_cols

        n = len(self.targets)
        # 表格本体行数：header + sep + n 行目标
        table_rows = 2 + n
        term_h = Scanner.get_terminal_height()

        if not force_full and self._printed_rows > 0 and Configuration.verbose <= 1:
            # 从「状态行」回到表头：状态 1 行 + 上一帧 table_rows
            # 光标当前在状态行末尾（无换行）
            lines_up = self._printed_rows + (1 if self._has_status else 0)
            # 目标变少或终端装不下 → clear 后整表重画
            if (self.previous_target_count > n
                    or term_h < table_rows + 3
                    or lines_up >= term_h):
                from ..util.process import Process
                Process.call(['clear'])
                self._printed_rows = 0
                self._has_status = False
            else:
                self._cursor_up(lines_up)
                # 从光标清到屏底，去掉残留
                Color.p('\033[J')
                self._has_status = False

        self.previous_target_count = n
        self._printed_rows = table_rows

        cols = term_cols()
        fixed = 4 + 2 + 3 + 2 + 4 + 2 + 5 + 2 + 4 + 2 + 4 + 2
        if Configuration.show_bssids:
            fixed += 17 + 2
        essid_width = max(12, min(36, cols - fixed - 2))

        # 表头
        Color.clear_entire_line()
        Color.p('{W}{D}')
        header = '%s  %s' % (
            pad(t('scan.hdr_num'), 4, align='right'),
            pad(t('scan.hdr_essid'), essid_width),
        )
        if Configuration.show_bssids:
            header += '  %s' % pad(t('scan.hdr_bssid'), 17)
        header += '  %s  %s  %s  %s  %s' % (
            pad(t('scan.hdr_ch'), 3, align='right'),
            pad(t('scan.hdr_encr'), 4),
            pad(t('scan.hdr_power'), 5, align='right'),
            pad(t('scan.hdr_wps'), 4),
            pad(t('scan.hdr_cli'), 4, align='right'),
        )
        Color.pl(header)

        Color.clear_entire_line()
        sep = '%s  %s' % (pad('---', 4), '-' * essid_width)
        if Configuration.show_bssids:
            sep += '  %s' % ('-' * 17)
        sep += '  %s  %s  %s  %s  %s{W}' % (
            '-' * 3, '-' * 4, '-' * 5, '-' * 4, '-' * 4)
        Color.pl(sep)

        for idx, target in enumerate(self.targets, start=1):
            Color.clear_entire_line()
            Color.p('{G}%s{W}  ' % pad(str(idx), 4, align='right'))
            Color.pl(target.to_str(Configuration.show_bssids, essid_width=essid_width))

    def _print_status(self, airodump) -> None:
        from .i18n import t
        decloak = t('scan.decloak') if airodump.decloaking else ''
        outline = '{+} ' + t(
            'scan.progress',
            decloak,
            len(self.targets),
            sum(len(t.clients) for t in self.targets),
        )
        Color.clear_entire_line()
        Color.p(outline)
        self._has_status = True

    @staticmethod
    def get_terminal_height():
        import shutil
        return shutil.get_terminal_size().lines

    @staticmethod
    def get_terminal_width():
        import shutil
        return shutil.get_terminal_size().columns

    def select_targets(self):
        if self.target:
            return [self.target]

        if len(self.targets) == 0:
            if self.err_msg is not None:
                Color.pl(self.err_msg)
            raise Exception(
                'No targets found.'
                ' You may need to wait longer,'
                ' or you may have issues with your wifi card')

        if Configuration.scan_time > 0 or getattr(Configuration, 'auto_attack', False):
            return self.targets

        # 选目标：换行后就地画一张干净表（不再 clear 整屏，避免闪屏）
        if self._has_status:
            Color.pl('')  # 结束状态行
            self._has_status = False
        # 从上移覆盖扫描表位置重画
        if self._printed_rows > 0 and Configuration.verbose <= 1:
            self._cursor_up(self._printed_rows)
            Color.p('\033[J')
            self._printed_rows = 0
        self.print_targets(force_full=True)

        if self.err_msg is not None:
            Color.pl(self.err_msg)

        from .i18n import t
        return self._prompt_target_choice(t)

    def _prompt_target_choice(self, t):
        while True:
            input_str = '{+} ' + t('scan.select', len(self.targets))
            try:
                raw = raw_input(Color.s(input_str)).strip()
            except KeyboardInterrupt:
                Color.pl('')
                raise

            if not raw:
                Color.pl('{!} {O}%s{W}' % t('scan.empty_select'))
                continue

            chosen = self._parse_target_selection(raw)
            if not chosen:
                Color.pl('{!} {O}%s{W}' % t('scan.invalid_select'))
                continue
            return chosen

    def _parse_target_selection(self, raw: str):
        text = raw.strip()
        if not text:
            return []
        if text.lower() == 'all':
            return list(self.targets)

        tokens = [tok for tok in re.split(r'[\s,]+', text) if tok]
        chosen = []
        seen = set()
        n = len(self.targets)

        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue
            if tok.lower() == 'all':
                return list(self.targets)
            if '-' in tok and not tok.startswith('-'):
                parts = tok.split('-', 1)
                if not (parts[0].isdigit() and parts[1].isdigit()):
                    continue
                lower = int(parts[0]) - 1
                upper = int(parts[1]) - 1
                if lower > upper:
                    lower, upper = upper, lower
                for i in xrange(max(0, lower), min(n, upper + 1)):
                    if i not in seen:
                        seen.add(i)
                        chosen.append(self.targets[i])
            elif tok.isdigit():
                i = int(tok) - 1
                if 0 <= i < n and i not in seen:
                    seen.add(i)
                    chosen.append(self.targets[i])
        return chosen


if __name__ == '__main__':
    Configuration.initialize()
    try:
        s = Scanner()
        targets = s.select_targets()
    except Exception as e:
        Color.pl('\r {!} {R}Error{W}: %s' % str(e))
        Configuration.exit_gracefully(0)
    for t in targets:
        Color.pl('    {W}Selected: %s' % t)
    Configuration.exit_gracefully(0)
