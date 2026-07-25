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
            Color.pl('{!} {O}WPS tools missing (reaver/bully){W}')

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else 'hidden'
            Color.pl('\n{+} ({G}%d{W}/{G}%d{W}) {C}%s{W} ({C}%s{W})' % (
                index, len(targets), essid, bssid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        - 按品牌排序攻击路径（不默认跳过 PIN / Pixie / PMKID）
        - 每条路径至少 attack_min_slice 秒（默认 15）
        - 单目标预算 target_timeout（默认 60；不够则抬到 n×15）
        '''
        cls._print_target_brief(target)
        queue = cls._build_attack_queue(target)
        if not queue:
            Color.pl('{!} {R}no attack available{W}')
            return True

        names = [n for n, _ in queue]
        slices = cls._allocate_time_slices(len(queue))
        Color.pl('{+} {D}plan: %s{W}' % ' | '.join(
            '%s %ds' % (n, s) for n, s in zip(names, slices)))

        saved = {
            'pmkid': Configuration.pmkid_timeout,
            'pixie': Configuration.wps_pixie_timeout,
            'wpa': Configuration.wpa_attack_timeout,
            'pin': getattr(Configuration, 'wps_pin_timeout', 60),
        }

        attack = None
        total_budget = sum(slices)
        deadline = time.time() + total_budget

        try:
            for (name, attack_obj), slice_sec in zip(queue, slices):
                remain = int(deadline - time.time())
                if remain < 1:
                    Color.pl('{!} {O}target budget used, next AP{W}')
                    break
                slice_sec = max(1, min(slice_sec, remain))
                cls._apply_timeouts(name, slice_sec)
                Color.pl('{+} {C}%s{W} {D}(%ds){W}' % (name, slice_sec))

                try:
                    result = attack_obj.run()
                    attack = attack_obj
                    if result:
                        break
                except KeyboardInterrupt:
                    Color.pl('\n{!} {O}Interrupted{W}\n')
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

        if (attack is not None
                and getattr(attack, 'success', False)
                and getattr(attack, 'crack_result', None)):
            attack.crack_result.save()

        return True

    @staticmethod
    def _allocate_time_slices(n: int) -> list[int]:
        '''均分目标时长；每人至少 min_slice（默认 15s）。'''
        if n <= 0:
            return []
        min_s = max(15, int(getattr(Configuration, 'attack_min_slice', 15) or 15))
        total = int(getattr(Configuration, 'target_timeout', 60) or 60)
        # 保证每条路径至少 min_s，不足则抬高总预算
        total = max(total, n * min_s)
        base = total // n
        rem = total % n
        # 优先级靠前的路径多分 1 秒余数
        return [base + (1 if i < rem else 0) for i in range(n)]

    @staticmethod
    def _apply_timeouts(name: str, seconds: int) -> None:
        # 切片已在分配阶段保证 >= min_slice；此处只保证正数，
        # 不把剩余不足 15s 的尾巴再强行抬回 15（避免拖垮总预算）。
        seconds = max(1, int(seconds))
        if name == 'pmkid':
            Configuration.pmkid_timeout = seconds
        elif name == 'wps_pixie':
            Configuration.wps_pixie_timeout = seconds
        elif name == 'wps_pin':
            Configuration.wps_pin_timeout = seconds
            Configuration.wps_pixie_timeout = seconds
        elif name == 'handshake':
            Configuration.wpa_attack_timeout = seconds
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
                Color.pl('{!} {O}WPA3 transition (SAE+PSK){W}')
            elif target.is_wpa3_sae():
                Color.pl('{!} {O}WPA3-SAE{W}')
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
            parts.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            parts.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        Color.pl('{+} %s remain' % ' / '.join(parts))

        from ..util.input import raw_input
        answer = raw_input(Color.s(
            '{+} [c]ontinue / [s]kip target / [e]xit? {C}')).lower()
        if answer.startswith('s'):
            return None
        if answer.startswith('e'):
            return False
        return True
