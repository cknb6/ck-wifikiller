#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 AP 并选择目标。

刷新逻辑（对齐 wifite 经典体验 + 修正行数）:
  - 上方 splash / banner **永远不动**
  - 其下 **只有一张表** + 底部状态行，每秒原地覆盖刷新
  - 算法：光标上移到表头 → \\033[J 清表区到底 → 重画表 → 状态行
  - 绝不用每秒 clear 整屏（会闪、且在部分终端叠表）
  - 绝不多上移（会盖住 splash）

Ctrl+C：
  - airodump 独立进程组，SIGINT 只到 Python
  - sleep 按 0.2s 分段，一次 Ctrl+C 结束扫描进入选目标
"""

from __future__ import annotations

import re
from time import sleep, time

from ..util.color import Color
from ..tools.airodump import Airodump
from ..util.input import raw_input, xrange
from ..model.target import WPSState
from ..config import Configuration


class Scanner(object):
    ''' Scans wifi networks & provides menu for selecting targets '''

    # CSI CUU — 上移一行（与 kimocoder wifite2 一致用 1A）
    UP_CHAR = '\033[A'

    def __init__(self):
        self.previous_target_count = 0
        # 上一帧「表体」行数 = 2(header+sep) + N，不含状态行
        self._table_rows = 0
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

                    self._interruptible_sleep(1.0)

        except KeyboardInterrupt:
            # 一次 Ctrl+C：光标仍在状态行，select_targets 会就地盖成选表
            # 不要在这里 Color.pl（会多换行导致上移算错、盖到 splash）
            pass

    @staticmethod
    def _interruptible_sleep(seconds: float) -> None:
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

    def _move_to_table_top(self) -> None:
        '''光标从当前位置回到表头行首；不动 splash。

        布局（表头为第 0 行）:
          0 header
          1 sep
          2..N+1 targets (N 行)
          N+2 status   ← 扫描时无换行停在此行
        从 status 回到 header 需上移 (N+2) = table_rows 次
        （table_rows = 2+N；从 status 上移 2+N 次刚好到 header）
        若已换行离开 status，则上移 table_rows 次。
        '''
        if self._table_rows <= 0:
            return
        # 有状态行且光标在状态行上：上移行数 = table_rows
        # （status 在 table 下方第 1 行，从 status 到 header = table_rows 行）
        # 例 N=1: rows=3 (h,sep,t1), status 第4行，UP 3 到 header ✓
        ups = self._table_rows
        if self._has_status:
            # 光标在 status：再多 0？ table_rows 行内容之上就是 header
            # h,sep,t1,...,tN = table_rows 行，status 在下一行
            # 从 status UP table_rows → header. 正确。
            pass
        Color.p(self.UP_CHAR * ups)
        # 从光标清到屏底：只清表区及以下，上方 splash 不动
        Color.p('\033[J')
        self._has_status = False
        self._table_rows = 0

    def print_targets(self, for_select=False):
        '''打印/刷新目标表（始终一张）。

        for_select: 选目标前调用，先离开状态行再就地覆盖。
        '''
        if len(self.targets) == 0:
            Color.p('\r')
            return

        from .i18n import t
        from .term_layout import pad, term_cols

        n = len(self.targets)
        table_rows = 2 + n  # header + sep + targets
        term_h = Scanner.get_terminal_height()

        if self._table_rows > 0 and Configuration.verbose <= 1:
            # 终端太矮或表太大：无法安全上移时，仅 clear 表以下——
            # 用全屏 clear 会抹掉 splash，仅在装不下时使用
            need_full_clear = (
                table_rows + 2 >= term_h
                or self._table_rows + 2 >= term_h
            )
            if need_full_clear:
                from ..util.process import Process
                Process.call(['clear'])
                self._table_rows = 0
                self._has_status = False
            else:
                self._move_to_table_top()

        self.previous_target_count = n
        self._table_rows = table_rows

        cols = term_cols()
        fixed = 4 + 2 + 3 + 2 + 4 + 2 + 5 + 2 + 4 + 2 + 4 + 2
        if Configuration.show_bssids:
            fixed += 17 + 2
        essid_width = max(12, min(36, cols - fixed - 2))

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
        Color.p(outline)  # 不换行，下一帧从这行上移回表头
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

        # 选目标：光标多半还在状态行 → 上移 table_rows 到表头，清表区，重画
        # （不动 splash；不要先 pl 换行）
        if self._table_rows > 0 and Configuration.verbose <= 1:
            ups = self._table_rows  # 从 status 到 header 正好 table_rows
            Color.p(self.UP_CHAR * ups)
            Color.p('\033[J')
            self._table_rows = 0
            self._has_status = False
        self.print_targets()

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
