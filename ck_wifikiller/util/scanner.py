#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..util.color import Color
from ..tools.airodump import Airodump
from ..util.input import raw_input, xrange
from ..model.target import Target, WPSState
from ..config import Configuration

from time import sleep, time

class Scanner(object):
    ''' Scans wifi networks & provides menu for selecting targets '''

    # Console code for moving up one line
    UP_CHAR = '\x1B[1F'

    def __init__(self):
        '''
        Scans for targets via Airodump.
        Loops until scan is interrupted via user or config.
        Note: Sets this object's `targets` attrbute (list[Target]) upon interruption.
        '''
        self.previous_target_count = 0
        self._status_line_printed = False
        self.targets = []
        self.target = None # Target specified by user (based on ESSID/BSSID)

        max_scan_time = Configuration.scan_time

        self.err_msg = None

        # Loads airodump with interface/channel/etc from Configuration
        try:
            with Airodump() as airodump:
                # Loop until interrupted (Ctrl+C)
                scan_start_time = time()

                while True:
                    if airodump.pid.poll() is not None:
                        return  # Airodump process died

                    self.targets = airodump.get_targets(old_targets=self.targets)

                    if self.found_target():
                        return  # We found the target we want

                    if airodump.pid.poll() is not None:
                        return  # Airodump process died

                    for target in self.targets:
                        if target.bssid in airodump.decloaked_bssids:
                            target.decloaked = True

                    self.print_targets()

                    target_count = len(self.targets)
                    client_count = sum(len(t.clients) for t in self.targets)

                    from .i18n import t
                    decloak = t('scan.decloak') if airodump.decloaking else ''
                    outline = '\r{+} ' + t(
                        'scan.progress', decloak, target_count, client_count)
                    Color.clear_entire_line()
                    Color.p(outline)
                    self._status_line_printed = True

                    if max_scan_time > 0 and time() > scan_start_time + max_scan_time:
                        return

                    sleep(1)

        except KeyboardInterrupt:
            # 扫描中断：清状态行，保留目标列表供选择
            Color.pl('')
            self._status_line_printed = False


    def found_target(self):
        '''
        Detect if we found a target specified by the user (optional).
        Sets this object's `target` attribute if found.
        Returns: True if target was specified and found, False otherwise.
        '''
        bssid = Configuration.target_bssid
        essid = Configuration.target_essid

        if bssid is None and essid is None:
            return False  # No specific target from user.

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


    def print_targets(self, include_status_line=True):
        '''Prints targets selection menu (1 target per row).

        布局（自顶向下）:
          header / sep / target×N / [status 同一行无换行]
        刷新时用「光标上移 + 清到屏底」，避免 NUM 表头重复。
        '''
        if len(self.targets) == 0:
            Color.p('\r')
            return

        from .i18n import t
        from .term_layout import pad, term_cols

        if self.previous_target_count > 0 and Configuration.verbose <= 1:
            # 上一轮: header + sep + N targets (+ status 占一行)
            prev_n = self.previous_target_count
            lines_up = 2 + prev_n  # header + sep + targets
            if getattr(self, '_status_line_printed', False):
                lines_up += 1
            term_h = Scanner.get_terminal_height()
            if prev_n > len(self.targets) or term_h < lines_up + 2:
                from ..util.process import Process
                Process.call('clear')
            else:
                # 必须用 p 不能 pl：pl 会再换行导致错位、表头重复
                Color.p(Scanner.UP_CHAR * lines_up)
                Color.p('\033[J')  # 从光标清到屏底

        self.previous_target_count = len(self.targets)
        self._status_line_printed = False

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

    @staticmethod
    def get_terminal_height():
        import shutil
        # shutil.get_terminal_size 在非 tty 下回退默认值，避免 stty size 崩溃
        return shutil.get_terminal_size().lines

    @staticmethod
    def get_terminal_width():
        import shutil
        return shutil.get_terminal_size().columns

    def select_targets(self):
        '''
        Returns list(target)
        Either a specific target if user specified -bssid or --essid.
        Otherwise, prompts user to select targets and returns the selection.
        '''

        if self.target:
            # When user specifies a specific target
            return [self.target]

        if len(self.targets) == 0:
            if self.err_msg is not None:
                Color.pl(self.err_msg)

            # TODO Print a more-helpful reason for failure.
            # 1. Link to wireless drivers wiki,
            # 2. How to check if your device supporst monitor mode,
            # 3. Provide airodump-ng command being executed.
            raise Exception('No targets found.'
                + ' You may need to wait longer,'
                + ' or you may have issues with your wifi card')

        # 闭环：pillage (-p) / --auto 扫完即打全部，不交互选目标
        if Configuration.scan_time > 0 or getattr(Configuration, 'auto_attack', False):
            return self.targets

        # Ask user for targets（只打印一次表，避免与扫描刷新叠表头）
        self._status_line_printed = False
        self.previous_target_count = 0  # 强制整表重画，不依赖上移
        Color.pl('')
        self.print_targets()
        Color.clear_entire_line()

        if self.err_msg is not None:
            Color.pl(self.err_msg)

        from .i18n import t
        return self._prompt_target_choice(t)

    def _prompt_target_choice(self, t):
        '''解析选择：支持 1 3 5 / 1,3,5 / 1-3 / all；空输入重试。'''
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
        '''支持空格/逗号混用：1 3 5  或  1,3,5  或  1-3,5 all'''
        text = raw.strip()
        if not text:
            return []
        if text.lower() == 'all':
            return list(self.targets)

        # 逗号与空白都当分隔
        import re
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
    # 'Test' script will display targets and selects the appropriate one
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

