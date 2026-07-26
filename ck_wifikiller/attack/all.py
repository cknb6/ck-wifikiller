#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多目标攻击调度：按厂商排序路径，按时长切片，不默认跳过向量。"""

from __future__ import annotations

import time

from .wep import AttackWEP
from .wpa import AttackWPA
from .wps import AttackWPS
from .pmkid import AttackPMKID
from ..config import Configuration
from ..model.target import WPSState
from ..util.color import Color
from ..util.i18n import t


class AttackAll(object):

    PATH_MAP = {
        'pmkid': 'pmkid',
        'pmkid (clientless)': 'pmkid',
        'handshake': 'handshake',
        'wpa handshake': 'handshake',
        'wps': 'wps_pixie',
        'pixie': 'wps_pixie',
        'pixie-dust': 'wps_pixie',
        'wps pixie-dust': 'wps_pixie',
        'wps pixie': 'wps_pixie',
        'wps pin': 'wps_pin',
        'pin': 'wps_pin',
    }

    # 无品牌信息时默认优先级：快失败优先，PIN 也保留
    DEFAULT_ORDER = ['pmkid', 'wps_pixie', 'wps_pin', 'handshake']

    @classmethod
    def attack_multiple(cls, targets):
        if any(getattr(t, 'wps', 0) for t in targets) and not AttackWPS.can_attack_wps():
            Color.pl('{!} {O}%s{W}' % t('atk.wps_note'))

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else 'hidden'
            Color.pl('\n{+} %s' % t('atk.start', index, len(targets), essid, bssid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    # 路径权重：捕获向（PMKID/握手）略高，PIN 仅探测可略低
    PATH_WEIGHTS = {
        'pmkid': 1.25,
        'wps_pixie': 1.0,
        'wps_pin': 0.85,
        'handshake': 1.35,
        'wep': 1.0,
    }

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        - 按品牌排序攻击路径（不默认跳过 PIN / Pixie / PMKID）
        - 每条路径至少 attack_min_slice 秒（默认 15）
        - 单目标预算 target_timeout（默认 90；不够则抬到 n×min）
        - 切片内捕获优先（满切片）；爆破用抓到后的 path_deadline 剩余墙钟
        - 握手 deauth 间隔与捕获窗口联动，开局即 deauth
        '''
        cls._print_target_brief(target)
        queue = cls._build_attack_queue(target)
        if not queue:
            Color.pl('{!} {R}%s{W}' % t('atk.none'))
            return True

        names = [n for n, _ in queue]
        slices = cls._allocate_time_slices(names)
        Color.pl('{+} {D}%s{W}' % t(
            'atk.plan',
            ' | '.join('%s %ds' % (n, s) for n, s in zip(names, slices))))

        saved = {
            'pmkid': Configuration.pmkid_timeout,
            'pixie': Configuration.wps_pixie_timeout,
            'wpa': Configuration.wpa_attack_timeout,
            'pin': getattr(Configuration, 'wps_pin_timeout', 60),
            'deauth': getattr(Configuration, 'wpa_deauth_timeout', 15),
            'deadline': getattr(Configuration, 'path_deadline', None),
            'hashcat_rt': getattr(Configuration, 'hashcat_runtime', 0),
        }

        attack = None
        total_budget = sum(slices)
        deadline = time.time() + total_budget

        try:
            for (name, attack_obj), slice_sec in zip(queue, slices):
                remain = int(deadline - time.time())
                if remain < 1:
                    Color.pl('{!} {O}%s{W}' % t('atk.budget_done'))
                    break
                slice_sec = max(1, min(slice_sec, remain))
                path_deadline = time.time() + slice_sec
                cls._apply_timeouts(name, slice_sec, path_deadline)
                Color.pl('{+} {C}%s{W} {D}(%ds){W}' % (name, slice_sec))

                try:
                    result = attack_obj.run()
                    attack = attack_obj
                    if result:
                        break
                except KeyboardInterrupt:
                    Color.pl('\n{!} {O}%s{W}\n' % t('interrupted'))
                    # --auto 闭环：中断时默认跳过当前目标，不交互
                    if getattr(Configuration, 'auto_attack', False) or Configuration.scan_time > 0:
                        return True
                    answer = cls.user_wants_to_continue(
                        targets_remaining, max(0, len(queue) - 1))
                    if answer is True:
                        continue
                    if answer is None:
                        return True
                    return False
                except Exception as e:
                    Color.pexception(e)
                    attack = attack_obj
                    continue
        finally:
            Configuration.pmkid_timeout = saved['pmkid']
            Configuration.wps_pixie_timeout = saved['pixie']
            Configuration.wpa_attack_timeout = saved['wpa']
            Configuration.wps_pin_timeout = saved['pin']
            Configuration.wpa_deauth_timeout = saved['deauth']
            Configuration.path_deadline = saved['deadline']
            Configuration.hashcat_runtime = saved['hashcat_rt']

        if (attack is not None
                and getattr(attack, 'success', False)
                and getattr(attack, 'crack_result', None)):
            attack.crack_result.save()

        return True

    @classmethod
    def _allocate_time_slices(cls, names_or_n) -> list[int]:
        '''按权重分配目标时长；每人至少 min_slice（默认 15s）。

        兼容旧调用：传入 int 路径数 → 均分；传入 names 列表 → 加权。
        '''
        if isinstance(names_or_n, int):
            names = ['p%d' % i for i in range(names_or_n)]
            weights = [1.0] * names_or_n
        else:
            names = list(names_or_n)
            weights = [
                float(cls.PATH_WEIGHTS.get(n, 1.0)) for n in names
            ]
        n = len(names)
        if n <= 0:
            return []
        min_s = max(15, int(getattr(Configuration, 'attack_min_slice', 15) or 15))
        total = int(getattr(Configuration, 'target_timeout', 90) or 90)
        # 保证每条路径至少 min_s，不足则抬高总预算
        total = max(total, n * min_s)

        wsum = sum(weights) or float(n)
        # 先按权重浮点分，再修正到整数且每人 >= min_s、总和 = total
        raw = [total * (w / wsum) for w in weights]
        slices = [max(min_s, int(x)) for x in raw]
        # 总和可能偏大或偏小
        diff = total - sum(slices)
        if diff != 0:
            # 按权重从大到小调整 1s
            order = sorted(range(n), key=lambda i: weights[i], reverse=(diff > 0))
            idx = 0
            guard = 0
            while diff != 0 and guard < total * 4:
                i = order[idx % n]
                if diff > 0:
                    slices[i] += 1
                    diff -= 1
                elif slices[i] > min_s:
                    slices[i] -= 1
                    diff += 1
                idx += 1
                guard += 1
        return slices

    @staticmethod
    def _apply_timeouts(name: str, seconds: int, path_deadline: float | None = None) -> None:
        '''切片秒数写入各工具超时。

        设计（v2.5.6）：
        - 在线捕获用满切片（不预扣 3s 假爆破）
        - 爆破只花「抓到后 path_deadline 剩余墙钟」（hashcat --runtime / aircrack kill）
        - 握手 deauth 间隔 = clamp(3, 8, slice//3)，保证切片内至少 1～2 次 deauth
        '''
        seconds = max(1, int(seconds))
        Configuration.path_deadline = path_deadline
        # 不再预留 crack_budget 缩短捕获；爆破看墙钟剩余
        Configuration.hashcat_runtime = 0

        if name == 'pmkid':
            Configuration.pmkid_timeout = seconds
        elif name == 'wps_pixie':
            Configuration.wps_pixie_timeout = seconds
        elif name == 'wps_pin':
            Configuration.wps_pin_timeout = seconds
            Configuration.wps_pixie_timeout = seconds
        elif name == 'handshake':
            Configuration.wpa_attack_timeout = seconds
            # deauth 间隔必须 < 捕获窗口，否则切片内零 deauth
            Configuration.wpa_deauth_timeout = max(3, min(8, max(3, seconds // 3)))
        elif name == 'wep':
            Configuration.wep_timeout = seconds

    @staticmethod
    def _print_target_brief(target):
        try:
            from ..util.router_advisory import get_advisory
            essid = target.essid if getattr(target, 'essid_known', False) else ''
            adv = get_advisory(target.bssid, essid or '')
        except Exception:
            adv = None
        vendor = (adv or {}).get('vendor')
        paths = (adv or {}).get('recommended_paths') or []
        if vendor:
            msg = '{+} {C}%s{W}' % vendor
            if paths:
                msg += '  {D}%s{W}' % ' > '.join(paths[:4])
            Color.pl(msg)
        try:
            if target.is_wpa3_transition():
                Color.pl('{!} {O}%s{W}' % t('atk.wpa3_trans'))
            elif target.is_wpa3_sae():
                Color.pl('{!} {O}%s{W}' % t('atk.wpa3_sae'))
        except Exception:
            pass

    @classmethod
    def _build_attack_queue(cls, target):
        '''按品牌排序；默认全开 PMKID / Pixie / PIN / 握手。'''
        if Configuration.use_eviltwin:
            return []

        if 'WEP' in target.encryption:
            return [('wep', AttackWEP(target))]

        if 'WPA' not in target.encryption:
            return []

        named = {}
        # WPS：未关闭且工具存在则加入（不因 UNKNOWN 直接砍掉）
        if not Configuration.use_pmkid_only and not Configuration.no_wps:
            if AttackWPS.can_attack_wps():
                if Configuration.wps_pixie:
                    named['wps_pixie'] = AttackWPS(target, pixie_dust=True)
                if Configuration.wps_pin:
                    named['wps_pin'] = AttackWPS(target, pixie_dust=False)

        if not Configuration.wps_only:
            named['pmkid'] = AttackPMKID(target)
            if not Configuration.use_pmkid_only:
                named['handshake'] = AttackWPA(target)

        # 明确无 WPS 时去掉 WPS 向量（空转浪费 15s+）
        if target.wps == WPSState.NONE and not Configuration.wps_only:
            named.pop('wps_pixie', None)
            named.pop('wps_pin', None)

        order = []
        try:
            from ..util.router_advisory import get_advisory
            essid = target.essid if getattr(target, 'essid_known', False) else ''
            adv = get_advisory(target.bssid, essid or '') or {}
            for path in adv.get('recommended_paths') or []:
                key = cls.PATH_MAP.get(str(path).strip().lower())
                if key and key in named and key not in order:
                    order.append(key)
        except Exception:
            pass

        for key in cls.DEFAULT_ORDER:
            if key in named and key not in order:
                order.append(key)

        return [(k, named[k]) for k in order if k in named]

    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        if attacks_remaining == 0 and targets_remaining == 0:
            return

        parts = []
        if attacks_remaining > 0:
            parts.append('%d attack(s)' % attacks_remaining)
        if targets_remaining > 0:
            parts.append('%d target(s)' % targets_remaining)
        left = ' / '.join(parts)

        from ..util.input import raw_input
        answer = raw_input(Color.s('{+} ' + t('atk.cont', left))).lower()
        if answer.startswith('s'):
            return None
        if answer.startswith('e'):
            return False
        return True
