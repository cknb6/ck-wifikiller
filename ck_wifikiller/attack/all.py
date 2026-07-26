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

        # 二次保险：只打有 ESSID 的目标（隐藏 SSID 无字典关联价值）
        from ..tools.airodump import Airodump
        named = [x for x in targets if Airodump._has_usable_essid(x)]
        skipped = len(targets) - len(named)
        if skipped > 0:
            Color.pl('{!} {O}%s{W}' % t('atk.skip_hidden', skipped))
        targets = named
        if not targets:
            Color.pl('{!} {R}%s{W}' % t('atk.none_named'))
            return 0

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

        # 汇总独立窗口/后台爆破任务
        try:
            from ..tools.bg_crack import BgCrack
            BgCrack.summarize()
        except Exception:
            pass

        return attacked_targets

    # 路径权重：捕获向（PMKID/握手）略高，PIN 仅探测可略低
    PATH_WEIGHTS = {
        'pmkid': 1.25,
        'wps_pixie': 1.0,
        'wps_pin': 0.85,
        'handshake': 1.35,
        'wep': 1.0,
    }

    # 路径硬性下限（秒）：PMKID ≥60，其余 ≥45；再与 attack_min_slice 取 max
    PATH_MIN_SLICE = {
        'pmkid': 60,
        'wps_pixie': 45,
        'wps_pin': 45,
        'handshake': 45,
        'wep': 45,
    }

    @classmethod
    def _path_min_slice(cls, name: str) -> int:
        '''单路径最短秒数。'''
        user = int(getattr(Configuration, 'attack_min_slice', 45) or 45)
        floor = int(cls.PATH_MIN_SLICE.get(name, 45))
        return max(floor, user)

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        - 按品牌排序攻击路径（不默认跳过 PIN / Pixie / PMKID）
        - PMKID 至少 60s，其它路径至少 45s（不够则抬高总预算）
        - 切片内只做捕获；字典全量爆破默认丢独立窗口/后台
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
        '''按权重分配目标时长；每人至少路径下限（PMKID 60 / 其它 45）。

        兼容旧调用：传入 int 路径数 → 均分；传入 names 列表 → 加权。
        '''
        if isinstance(names_or_n, int):
            names = ['p%d' % i for i in range(names_or_n)]
            weights = [1.0] * names_or_n
            mins = [cls._path_min_slice('handshake') for _ in names]
        else:
            names = list(names_or_n)
            weights = [
                float(cls.PATH_WEIGHTS.get(n, 1.0)) for n in names
            ]
            mins = [cls._path_min_slice(n) for n in names]
        n = len(names)
        if n <= 0:
            return []

        min_total = sum(mins)
        total = int(getattr(Configuration, 'target_timeout', 210) or 210)
        # 保证每条路径至少各自下限，不足则抬高总预算
        total = max(total, min_total)

        wsum = sum(weights) or float(n)
        raw = [total * (w / wsum) for w in weights]
        slices = [max(mins[i], int(raw[i])) for i in range(n)]
        # 总和可能偏大或偏小
        diff = total - sum(slices)
        if diff != 0:
            order = sorted(range(n), key=lambda i: weights[i], reverse=(diff > 0))
            idx = 0
            guard = 0
            while diff != 0 and guard < total * 4:
                i = order[idx % n]
                if diff > 0:
                    slices[i] += 1
                    diff -= 1
                elif slices[i] > mins[i]:
                    slices[i] -= 1
                    diff += 1
                idx += 1
                guard += 1
        return slices

    @staticmethod
    def _apply_timeouts(name: str, seconds: int, path_deadline: float | None = None) -> None:
        '''切片秒数写入各工具超时。

        设计（v2.5.18）：
        - 在线捕获用满切片
        - 字典全量爆破默认独立窗口（BgCrack），不再靠 path_deadline 截断字典
        - 握手: 爆发 deauth×rounds → 静默 listen 秒（默认 4）→ 再爆发
        '''
        seconds = max(1, int(seconds))
        Configuration.path_deadline = path_deadline
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
            # 静默监听：默认 4s；切片短时略缩、长时最多 6s
            # 保证捕获窗内至少能完成 1～2 个「爆发+静默」周期
            base_listen = int(getattr(Configuration, 'wpa_deauth_listen', 4) or 4)
            listen = max(3, min(6, base_listen))
            if seconds < 20:
                listen = min(listen, max(3, seconds // 5))
            Configuration.wpa_deauth_listen = listen
            Configuration.wpa_deauth_timeout = listen  # 兼容旧字段
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

        # 明确无 WPS 时去掉 WPS 向量（空转浪费切片）
        if target.wps == WPSState.NONE and not Configuration.wps_only:
            named.pop('wps_pixie', None)
            named.pop('wps_pin', None)
        # LOCKED：保留 Pixie，去掉 PIN（除非 --ignore-locks）
        if (target.wps == WPSState.LOCKED
                and not Configuration.wps_ignore_lock
                and not Configuration.wps_only):
            named.pop('wps_pin', None)

        # 纯 WPA3-SAE：离线 22000 不可行，去掉 PMKID/握手（Transition 仍可打）
        try:
            if target.is_wpa3_sae() and not target.is_wpa3_transition():
                named.pop('pmkid', None)
                named.pop('handshake', None)
        except Exception:
            pass

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
