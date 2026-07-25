#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception(
        'You may need to run ck-wifikiller from the repo root (which includes README.md)',
        e)

from .util.color import Color

import os
import sys


class CKWifiKiller(object):
    """ck-wifikiller entry — fork of wifite2 for modern Kali (2018→2026)."""

    def __init__(self):
        self.print_banner()

        Configuration.initialize(load_interface=False)

        if os.getuid() != 0 and not Configuration.recon_mode:
            # recon status 可在无 root 下看依赖矩阵；kismet 启动仍需 root
            if Configuration.recon_mode not in ('status', 'report'):
                Color.pl('{!} {R}error: {O}ck-wifikiller{R} must be run as {O}root{W}')
                Color.pl('{!} {R}re-run with {O}sudo{W}')
                Configuration.exit_gracefully(0)
        elif os.getuid() != 0 and Configuration.recon_mode in ('kismet', 'bettercap'):
            Color.pl('{!} {O}提示: 启动 Kismet/bettercap 通常需要 root{W}')

        if not Configuration.recon_mode:
            from .tools.dependency import Dependency
            Dependency.run_dependency_check()

    def start(self):
        from .model.result import CrackResult
        from .model.handshake import Handshake
        from .util.crack import CrackHelper

        if Configuration.recon_mode:
            from .recon.engine import ReconEngine
            ReconEngine.run_cli(Configuration.recon_mode)
            return

        if Configuration.show_cracked:
            CrackResult.display()

        elif Configuration.check_handshake:
            Handshake.check()

        elif Configuration.crack_handshake:
            CrackHelper.run()

        else:
            if os.getuid() != 0:
                Color.pl('{!} {R}error: {O}ck-wifikiller{R} must be run as {O}root{W}')
                Configuration.exit_gracefully(0)
            Configuration.get_monitor_mode_interface()
            self.scan_and_attack()

    def print_banner(self):
        from .util.splash import show_splash
        show_splash(Configuration.version)
        Color.pl(r' {G}  .     {GR}{D}     {W}{G}     .    {W}')
        Color.pl(r' {G}.´  ·  .{GR}{D}     {W}{G}.  ·  `.  {G}ck-wifikiller {D}%s{W}' % Configuration.version)
        Color.pl(r' {G}:  :  : {GR}{D} (¯) {W}{G} :  :  :  {W}{D}wireless auditor for modern Kali{W}')
        Color.pl(r' {G}`.  ·  `{GR}{D} /¯\ {W}{G}´  ·  .´  {C}{D}Kismet recon · PMKID · hc22000{W}')
        Color.pl(r' {G}  `     {GR}{D}/¯¯¯\{W}{G}     ´    {W}')
        Color.pl('')

    def scan_and_attack(self):
        from .util.scanner import Scanner
        from .attack.all import AttackAll

        Color.pl('')
        s = Scanner()
        targets = s.select_targets()
        attacked_targets = AttackAll.attack_multiple(targets)
        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)


# 兼容旧名
Wifite = CKWifiKiller


def entry_point():
    try:
        app = CKWifiKiller()
        app.start()
    except Exception as e:
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')
    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')
