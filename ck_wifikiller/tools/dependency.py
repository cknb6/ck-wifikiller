#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Dependency(object):
    required_attr_names = ['dependency_name', 'dependency_url', 'dependency_required']

    # https://stackoverflow.com/a/49024227
    def __init_subclass__(cls):
        for attr_name in cls.required_attr_names:
            if not attr_name in cls.__dict__:
                raise NotImplementedError(
                    'Attribute "{}" has not been overridden in class "{}"' \
                    .format(attr_name, cls.__name__)
                )


    @classmethod
    def exists(cls):
        from ..util.process import Process
        return Process.exists(cls.dependency_name)


    @classmethod
    def run_dependency_check(cls):
        from ..util.color import Color
        from ..util.process import Process

        from .airmon import Airmon
        from .airodump import Airodump
        from .aircrack import Aircrack
        from .aireplay import Aireplay
        from .ifconfig import Ifconfig
        from .iwconfig import Iwconfig
        from .bully import Bully
        from .reaver import Reaver
        from .wash import Wash
        from .pyrit import Pyrit
        from .tshark import Tshark
        from .macchanger import Macchanger
        from .hashcat import Hashcat, HcxDumpTool, HcxPcapTool
        from .hcx_psk import HcxPskTool
        from .kismet import Kismet
        from .bettercap_wifi import BettercapWifi

        apps = [
                # Aircrack 套件
                Aircrack, Airmon, Airodump,
                # wireless/net tools
                Iwconfig, Ifconfig,
                # WPS
                Reaver, Bully, Wash,
                # Cracking/handshakes — pyrit 已基本从 Kali 消失，降级为可选检测
                Tshark,
                # Hashcat + modern hcx (Kali 2024–2026)
                Hashcat, HcxDumpTool, HcxPcapTool, HcxPskTool,
                # Layer-1 recon (optional)
                Kismet, BettercapWifi,
                # Misc
                Macchanger
            ]
        # pyrit 仅在存在时检查，避免 Kali 新版本误杀
        if Process.exists('pyrit'):
            apps.insert(-3, Pyrit)

        missing_required = any([app.fails_dependency_check() for app in apps])

        if missing_required:
            Color.pl('{!} {O}At least 1 Required app is missing. ck-wifikiller needs Required apps{W}')
            Color.pl('{!} {O}Kali: sudo apt install aircrack-ng hashcat hcxtools hcxdumptool tshark{W}')
            import sys
            sys.exit(-1)


    @classmethod
    def fails_dependency_check(cls):
        from ..util.color import Color
        from ..util.process import Process

        if Process.exists(cls.dependency_name):
            return False

        if cls.dependency_required:
            Color.p('{!} {O}Error: Required app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return True

        else:
            Color.p('{!} {O}Warning: Recommended app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return False
