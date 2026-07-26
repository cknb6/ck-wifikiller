#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time


class Attack(object):
    '''Contains functionality common to all attacks.'''

    # 初始等待 AP 出现的默认上限（秒）；实际还会被 path_deadline / 路径切片收紧
    target_wait = 20
    # 攻击循环中刷新目标信息时的短超时（秒）——禁止再次卡 20~60s
    target_refresh_wait = 3

    def __init__(self, target):
        self.target = target

    def run(self):
        raise Exception('Unimplemented method: run')

    def _max_target_wait(self, timeout=None):
        '''综合 path_deadline / 显式 timeout / 默认值，取最短正数上限。

        不扫其它路径的残留 timeout（如 pixie 切片后的 wpa_attack_timeout），
        避免误伤；调度器已通过 path_deadline 统一收口。
        '''
        from ..config import Configuration

        now = time.time()
        caps = [float(getattr(self, 'target_wait', Attack.target_wait) or 20)]
        if timeout is not None:
            try:
                caps.append(float(timeout))
            except (TypeError, ValueError):
                pass

        deadline = getattr(Configuration, 'path_deadline', None)
        if deadline is not None:
            caps.append(max(0.5, float(deadline) - now))

        positive = [c for c in caps if c is not None and c > 0]
        if not positive:
            return 5.0
        # 最少 2s（airodump --write-interval 1）
        return max(2.0, min(positive))

    def wait_for_target(self, airodump, timeout=None, refresh=False, on_wait=None):
        '''等待 airodump 扫到本目标 BSSID。

        旧逻辑只在 targets 为空时循环；一旦 CSV 里出现其他 AP 或解析抖动，
        要么立刻抛错、要么在刷新路径里再次卡满 target_wait——表现为「卡死」。

        新逻辑：
          - 始终按 BSSID（大小写不敏感）轮询，直到出现或超时
          - 认 path_deadline / 路径切片，避免 20s 切片内干等 60s
          - refresh=True 时用短超时，失败返回原 target（不炸循环）
          - airodump 进程已退出则立刻失败
          - on_wait(remaining) 可刷新状态行
        '''
        start_time = time.time()
        if refresh and timeout is None:
            timeout = float(getattr(self, 'target_refresh_wait', Attack.target_refresh_wait) or 3)
        max_wait = self._max_target_wait(timeout=timeout)
        want = (getattr(self.target, 'bssid', None) or '').strip().lower()
        if not want:
            raise Exception('Target BSSID is empty')

        while True:
            elapsed = time.time() - start_time
            remaining = max_wait - elapsed
            if remaining <= 0:
                msg = 'Target %s did not appear after %ds' % (
                    getattr(self.target, 'bssid', '?'), int(max_wait))
                if refresh:
                    # 刷新失败：保留旧 target，不中断攻击循环
                    return self.target
                # 常见根因提示（NM/wpa 抢网卡、信道错、信号消失）
                hint = (
                    ' — check channel/monitor; if NetworkManager conflicts, re-run with --kill'
                )
                raise Exception(msg + hint)

            # airodump 挂了就别空等
            pid = getattr(airodump, 'pid', None)
            if pid is not None:
                try:
                    code = pid.poll()
                except Exception:
                    code = None
                if code is not None:
                    raise Exception(
                        'airodump-ng exited (code %s) before target appeared' % code)

            try:
                targets = airodump.get_targets(apply_filter=False)
            except Exception:
                targets = []

            for t in targets or []:
                bssid = (getattr(t, 'bssid', None) or '').strip().lower()
                if bssid == want:
                    # 合并：保留扫描阶段已知的 essid/wps，用实时 power/channel/clients
                    if not getattr(t, 'essid_known', False) and getattr(self.target, 'essid_known', False):
                        t.essid = self.target.essid
                        t.essid_known = True
                    if getattr(t, 'wps', None) is not None and getattr(self.target, 'wps', None) is not None:
                        # wash/tshark 可能 skip；保留原先 WPS 状态
                        from .target import WPSState
                        if t.wps == WPSState.UNKNOWN and self.target.wps != WPSState.UNKNOWN:
                            t.wps = self.target.wps
                    return t

            if on_wait is not None:
                try:
                    on_wait(remaining)
                except Exception:
                    pass

            time.sleep(0.4)
