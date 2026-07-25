#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .wep import AttackWEP
from .wpa import AttackWPA
from .wps import AttackWPS
from .pmkid import AttackPMKID
from ..config import Configuration
from ..model.target import WPSState
from ..util.color import Color

class AttackAll(object):

    @classmethod
    def attack_multiple(cls, targets):
        '''
        Attacks all given `targets` (list[ck_wifikiller.model.target]) until user interruption.
        Returns: Number of targets that were attacked (int)
        '''
        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            # Warn that WPS attacks are not available.
            Color.pl('{!} {O}Note: WPS attacks are not possible because you do not have {C}reaver{O} nor {C}bully{W}')

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else '{O}ESSID unknown{W}'

            Color.pl('\n{+} ({G}%d{W}/{G}%d{W})' % (index, len(targets)) +
                     ' Starting attacks against {C}%s{W} ({C}%s{W})' % (bssid, essid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        Attacks a single `target` (ck_wifikiller.model.target).
        Returns: True if attacks should continue, False otherwise.
        '''

        # 精简提示 + 按厂商推荐顺序排攻击队列
        cls._print_target_brief(target)
        attacks = cls._build_attack_queue(target)

        if len(attacks) == 0:
            Color.pl('{!} {R}no attack available for this target{W}')
            return True  # Keep attacking other targets (skip)

        attack = None
        while len(attacks) > 0:
            attack = attacks.pop(0)
            try:
                result = attack.run()
                if result:
                    break  # Attack was successful, stop other attacks.
            except Exception as e:
                Color.pexception(e)
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Interrupted{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer is True:
                    continue  # Keep attacking the same target (continue)
                elif answer is None:
                    return True  # Keep attacking other targets (skip)
                else:
                    return False  # Stop all attacks (exit)

        if attack is not None and getattr(attack, 'success', False) and getattr(attack, 'crack_result', None):
            attack.crack_result.save()

        return True  # Keep attacking other targets


    @staticmethod
    def _print_target_brief(target):
        '''一行厂商 + WPA3 提示，无防御清单。'''
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
                msg += '  {D}%s{W}' % ' > '.join(paths[:3])
            Color.pl(msg)
        try:
            if target.is_wpa3_transition():
                Color.pl('{!} {O}WPA3 transition (SAE+PSK) — may downgrade to WPA2{W}')
            elif target.is_wpa3_sae():
                Color.pl('{!} {O}WPA3-SAE only — offline crack N/A{W}')
        except Exception:
            pass

    @staticmethod
    def _build_attack_queue(target):
        '''构建攻击队列；有厂商推荐路径时重排 WPA 向量顺序。'''
        if Configuration.use_eviltwin:
            return []

        if 'WEP' in target.encryption:
            return [AttackWEP(target)]

        if 'WPA' not in target.encryption:
            return []

        # 命名便于排序
        named = {}
        if not Configuration.use_pmkid_only:
            if target.wps != WPSState.NONE and AttackWPS.can_attack_wps():
                if Configuration.wps_pixie:
                    named['wps_pixie'] = AttackWPS(target, pixie_dust=True)
                if Configuration.wps_pin:
                    named['wps_pin'] = AttackWPS(target, pixie_dust=False)
        if not Configuration.wps_only:
            named['pmkid'] = AttackPMKID(target)
            if not Configuration.use_pmkid_only:
                named['handshake'] = AttackWPA(target)

        # 默认顺序
        default_order = ['wps_pixie', 'wps_pin', 'pmkid', 'handshake']

        # 厂商路径关键字 → 队列键
        path_map = {
            'pmkid': 'pmkid',
            'handshake': 'handshake',
            'wpa handshake': 'handshake',
            'wps': 'wps_pixie',
            'pixie': 'wps_pixie',
            'pixie-dust': 'wps_pixie',
            'wps pixie-dust': 'wps_pixie',
            'wps pin': 'wps_pin',
        }
        order = []
        try:
            from ..util.router_advisory import get_advisory
            essid = target.essid if getattr(target, 'essid_known', False) else ''
            adv = get_advisory(target.bssid, essid or '') or {}
            for path in adv.get('recommended_paths') or []:
                key = path_map.get(path.strip().lower())
                if key and key in named and key not in order:
                    order.append(key)
        except Exception:
            pass
        for key in default_order:
            if key in named and key not in order:
                order.append(key)
        return [named[k] for k in order if k in named]


    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        '''
        Asks user if attacks should continue onto other targets
        Returns:
            True if user wants to continue, False otherwise.
        '''
        if attacks_remaining == 0 and targets_remaining == 0:
            return  # No targets or attacksleft, drop out

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        prompt = ' and '.join(prompt_list) + ' remain'
        Color.pl('{+} %s' % prompt)

        prompt = '{+} Do you want to'
        options = '('

        if attacks_remaining > 0:
            prompt += ' {G}continue{W} attacking,'
            options += '{G}C{W}{D}, {W}'

        if targets_remaining > 0:
            prompt += ' {O}skip{W} to the next target,'
            options += '{O}s{W}{D}, {W}'

        options += '{R}e{W})'
        prompt += ' or {R}exit{W} %s? {C}' % options

        from ..util.input import raw_input
        answer = raw_input(Color.s(prompt)).lower()

        if answer.startswith('s'):
            return None  # Skip
        elif answer.startswith('e'):
            return False  # Exit
        else:
            return True  # Continue

