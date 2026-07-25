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

        # 路由器厂商识别 + 审计建议（2026：针对性攻击路径排序）
        cls.print_vendor_advisory(target)

        # WPA3 前沿 PoC 检测：Transition Mode 可降级，纯 SAE 仅在线爆破
        cls.print_wpa3_advisory(target)

        attacks = []

        if Configuration.use_eviltwin:
            # TODO: EvilTwin attack
            pass

        elif 'WEP' in target.encryption:
            attacks.append(AttackWEP(target))

        elif 'WPA' in target.encryption:
            # WPA can have multiple attack vectors:

            # WPS：仅在明确非 NONE 时尝试（UNKNOWN/UNLOCKED/LOCKED）
            if not Configuration.use_pmkid_only:
                if target.wps != WPSState.NONE and AttackWPS.can_attack_wps():
                    # Pixie-Dust
                    if Configuration.wps_pixie:
                        attacks.append(AttackWPS(target, pixie_dust=True))

                    # PIN attack
                    if Configuration.wps_pin:
                        attacks.append(AttackWPS(target, pixie_dust=False))

            if not Configuration.wps_only:
                # PMKID
                attacks.append(AttackPMKID(target))

                # Handshake capture
                if not Configuration.use_pmkid_only:
                    attacks.append(AttackWPA(target))

        if len(attacks) == 0:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
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
    def print_vendor_advisory(target):
        '''识别路由器厂商并打印针对性审计建议（不实际攻击，仅辅助排序）。'''
        try:
            from ..util.router_advisory import get_advisory
            # 传入 ESSID，才能利用 SSID 指纹与运营商场景提示
            essid = target.essid if getattr(target, 'essid_known', False) else ''
            adv = get_advisory(target.bssid, essid or '')
        except Exception:
            return
        if not adv:
            return
        vendor = adv.get('vendor', 'Unknown')
        Color.pl('{+} {C}厂商识别 / Vendor{W}: {G}%s{W} (BSSID {D}%s{W})' % (vendor, target.bssid))
        paths = adv.get('recommended_paths')
        if paths:
            Color.pl('{+} {O}推荐攻击路径 / Recommended{W}: {C}%s{W}' % ' → '.join(paths))
        checks = adv.get('audit_checks')
        if checks:
            Color.pl('{+} {D}防御核查清单 / Audit checks{W}:')
            for check in checks[:3]:
                Color.pl('{+}   {D}%s{W}' % check)

    @staticmethod
    def print_wpa3_advisory(target):
        '''WPA3 前沿 PoC 检测提示（仅检测，不攻击）。'''
        try:
            if target.is_wpa3_transition():
                Color.pl('{!} {O}WPA3 Transition Mode 检测到 (SAE+PSK){W}')
                Color.pl('{!} {O}可降级攻击 / Downgrade viable: hostapd-mana 伪 AP + deauth → WPA2 握手{W}')
                Color.pl('{!} {D}前提: MFP(802.11w) 未强制；需 Wireshark 确认{W}')
            elif target.is_wpa3_sae():
                Color.pl('{!} {O}纯 WPA3-SAE: 离线爆破不可行，仅在线爆破 (Wacker){W}')
        except Exception:
            return


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

