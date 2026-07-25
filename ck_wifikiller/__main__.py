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
        self._session = None
        # --help / -h 不刷启动页，避免污染帮助输出
        self._want_help = any(a in ('-h', '--help') for a in sys.argv[1:])
        if not self._want_help:
            self.print_banner()

        Configuration.initialize(load_interface=False)

        if not self._want_help:
            self._check_update()

        if not self._want_help:
            self._start_session_log()

        if os.getuid() != 0 and not Configuration.recon_mode:
            Color.pl('{!} {R}error: {O}ck-wifikiller{R} must be run as {O}root{W}')
            Color.pl('{!} {R}re-run with {O}sudo{W}')
            Configuration.exit_gracefully(0)
        elif os.getuid() != 0 and Configuration.recon_mode in ('kismet', 'bettercap'):
            Color.pl('{!} {O}提示: 启动 Kismet/bettercap 通常需要 root{W}')

        if not Configuration.recon_mode and not self._want_help:
            from .tools.dependency import Dependency
            Dependency.run_dependency_check()

    def _start_session_log(self):
        try:
            from .util.session_log import SessionLog
            if SessionLog.enabled():
                self._session = SessionLog.get()
                Color.pl('{+} session log: {C}%s{W}' % self._session.dir)
                Color.pl('{+} {D}升级反馈可填 feedback.md · Issues: github.com/cknb6/ck-wifikiller/issues{W}')
        except Exception:
            self._session = None

    def _check_update(self):
        '''启动时检查 GitHub 最新 Release（非阻塞，仅提示）。'''
        if not getattr(Configuration, 'update_check', True):
            return
        try:
            from .util.update_check import run_update_check
            run_update_check(Configuration.version)
        except Exception:
            pass

    def start(self):
        from .model.result import CrackResult
        from .model.handshake import Handshake
        from .util.crack import CrackHelper

        if Configuration.recon_mode:
            from .recon.engine import ReconEngine
            if self._session:
                self._session.event('recon', {'mode': Configuration.recon_mode})
            ReconEngine.run_cli(Configuration.recon_mode)
            return

        if Configuration.show_cracked:
            CrackResult.display()

        elif Configuration.check_handshake:
            Handshake.check()

        elif Configuration.crack_handshake:
            if self._session:
                self._session.event('crack_helper', {})
            CrackHelper.run()

        else:
            if os.getuid() != 0:
                Color.pl('{!} {R}error: {O}ck-wifikiller{R} must be run as {O}root{W}')
                Configuration.exit_gracefully(0)
            Configuration.get_monitor_mode_interface()
            if self._session:
                self._session.event('scan_and_attack', {
                    'interface': Configuration.interface,
                })
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
        if self._session:
            self._session.event('targets_selected', {
                'count': len(targets) if targets else 0,
            })
        attacked_targets = AttackAll.attack_multiple(targets)
        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)
        if self._session:
            self._session.event('attack_finished', {'attacked': attacked_targets})


# 兼容旧名
Wifite = CKWifiKiller


def entry_point():
    app = None
    code = 0
    try:
        app = CKWifiKiller()
        app.start()
    except Exception as e:
        code = 1
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')
        if app and getattr(app, '_session', None):
            app._session.event('exception', {'error': str(e)})
    except KeyboardInterrupt:
        code = 130
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')
        if app and getattr(app, '_session', None):
            app._session.event('interrupted', {})
    finally:
        if app and getattr(app, '_session', None):
            logdir = app._session.finalize(code)
            Color.pl('{+} session log saved: {C}%s{W}' % logdir)
