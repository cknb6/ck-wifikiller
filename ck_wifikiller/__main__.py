#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception(
        'You may need to run ck-wifikiller from the repo root (which includes README.md)',
        e)

from .util.color import Color
from .util.i18n import t

import os
import sys


class CKWifiKiller(object):
    """ck-wifikiller entry."""

    def __init__(self):
        self._session = None
        self._want_help = any(a in ('-h', '--help') for a in sys.argv[1:])
        if not self._want_help:
            self.print_banner()

        Configuration.initialize(load_interface=False)

        if not self._want_help:
            self._check_update()
            self._start_session_log()

        if os.getuid() != 0 and not Configuration.recon_mode:
            Color.pl('{!} {R}%s{W}' % t('need_root'))
            Configuration.exit_gracefully(1)
        elif os.getuid() != 0 and Configuration.recon_mode in ('kismet', 'bettercap'):
            Color.pl('{!} {O}%s{W}' % t('need_root_recon'))

        if not Configuration.recon_mode and not self._want_help:
            from .tools.dependency import Dependency
            Dependency.run_dependency_check()

    def _start_session_log(self):
        try:
            from .util.session_log import SessionLog
            if SessionLog.enabled():
                self._session = SessionLog.get()
        except Exception:
            self._session = None

    def _check_update(self):
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
                Color.pl('{!} {R}%s{W}' % t('need_root'))
                Configuration.exit_gracefully(1)
            Configuration.get_monitor_mode_interface()
            if self._session:
                self._session.event('scan_and_attack', {
                    'interface': Configuration.interface,
                })
            self.scan_and_attack()

    def print_banner(self):
        from .util.splash import show_splash
        show_splash(Configuration.version)

    def scan_and_attack(self):
        from .util.scanner import Scanner
        from .attack.all import AttackAll

        s = Scanner()
        targets = s.select_targets()
        if self._session:
            self._session.event('targets_selected', {
                'count': len(targets) if targets else 0,
            })
        attacked = AttackAll.attack_multiple(targets)
        Color.pl('{+} %s' % t('attack_done', attacked))
        if self._session:
            self._session.event('attack_finished', {'attacked': attacked})


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
        Color.pl('\n{!} {R}%s{W}\n' % t('exiting'))
        if app and getattr(app, '_session', None):
            app._session.event('exception', {'error': str(e)})
    except KeyboardInterrupt:
        code = 130
        Color.pl('\n{!} {O}%s{W}' % t('interrupted'))
        if app and getattr(app, '_session', None):
            app._session.event('interrupted', {})
    finally:
        if app and getattr(app, '_session', None):
            app._session.finalize(code)
    return code


if __name__ == '__main__':
    sys.exit(entry_point())
