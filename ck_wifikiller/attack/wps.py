#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..util.color import Color
from ..util.process import Process
from ..config import Configuration
from ..tools.bully import Bully
from ..tools.reaver import Reaver

class AttackWPS(Attack):

    @staticmethod
    def can_attack_wps():
        return Reaver.exists() or Bully.exists()

    def __init__(self, target, pixie_dust=False):
        super(AttackWPS, self).__init__(target)
        self.success = False
        self.crack_result = None
        self.pixie_dust = pixie_dust

    def run(self):
        ''' Run all WPS-related attacks '''

        # Drop out if user specified to not use Reaver/Bully
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        if Configuration.no_wps:
            self.success = False
            return False

        if not Configuration.wps_pixie and self.pixie_dust:
            Color.pl('\r{!} {O}--no-pixie{R} was given, skipping WPS Pixie-Dust on ' +
                    '{O}%s{W}' % self.target.essid)
            self.success = False
            return False

        if not Configuration.wps_pin and not self.pixie_dust:
            Color.pl('\r{!} {O}--no-pin{R} was given, skipping WPS PIN on ' +
                    '{O}%s{W}' % self.target.essid)
            self.success = False
            return False

        # LOCKED：PIN 在线几乎必失败；Pixie 仍可试（不依赖在线 PIN 穷举）
        from ..model.target import WPSState
        if (not self.pixie_dust
                and getattr(self.target, 'wps', None) == WPSState.LOCKED
                and not Configuration.wps_ignore_lock):
            Color.pl('\r{!} {O}WPS locked, skip PIN (use --ignore-locks or Pixie){W}')
            self.success = False
            return False

        # 工具选择：reaver 优先（Kali 默认），缺则 bully；Pixie 能力不足时换 bully
        if Configuration.use_bully and Bully.exists():
            return self.run_bully()
        if not Reaver.exists() and Bully.exists():
            return self.run_bully()
        if self.pixie_dust and Reaver.exists() and not Reaver.is_pixiedust_supported():
            if Bully.exists():
                return self.run_bully()
            Color.pl('\r{!} {R}Skipping WPS Pixie: reaver has no pixie support, bully missing{W}')
            return False
        if Reaver.exists():
            return self.run_reaver()
        if Bully.exists():
            return self.run_bully()
        if self.pixie_dust:
            Color.pl('\r{!} {R}Skipping WPS Pixie-Dust: need reaver or bully{W}')
        else:
            Color.pl('\r{!} {R}Skipping WPS PIN: need reaver or bully{W}')
        return False


    def run_bully(self):
        bully = Bully(self.target, pixie_dust=self.pixie_dust)
        bully.run()
        bully.stop()
        self.crack_result = bully.crack_result
        self.success = self.crack_result is not None
        return self.success


    def run_reaver(self):
        reaver = Reaver(self.target, pixie_dust=self.pixie_dust)
        reaver.run()
        self.crack_result = reaver.crack_result
        self.success = self.crack_result is not None
        return self.success

