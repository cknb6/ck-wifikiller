#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

from .util.color import Color
from .tools.macchanger import Macchanger
from ._version import get_version as _get_version

class Configuration(object):
    ''' Stores configuration variables and functions for ck-wifikiller. '''
    # 版本号动态化：环境变量 CK_WIFI_VERSION > git describe > 内置基线
    version = _get_version()

    initialized = False # Flag indicating config has been initialized
    temp_dir = None     # Temporary directory
    interface = None
    verbose = 0

    @classmethod
    def initialize(cls, load_interface=True):
        '''
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        '''
        # TODO: categorize configuration into separate classes (under config/*.py)
        # E.g. Configuration.wps.enabled, Configuration.wps.timeout, etc

        # Only initialize this class once
        if cls.initialized:
            return
        cls.initialized = True

        cls.verbose = 0 # Verbosity of output. Higher number means more debug info about running processes.
        cls.print_stack_traces = True

        cls.kill_conflicting_processes = False

        cls.scan_time = 0 # Time to wait before attacking all targets

        cls.tx_power = 0 # Wifi transmit power (0 is default)
        cls.interface = None
        cls.target_channel = None # User-defined channel to scan
        cls.target_essid = None # User-defined AP name
        cls.target_bssid = None # User-defined AP BSSID
        cls.ignore_essid = None # ESSIDs to ignore
        cls.clients_only = False # Only show targets that have associated clients
        cls.five_ghz = False # Scan 5Ghz channels
        cls.show_bssids = False # Show BSSIDs in targets list
        cls.random_mac = False # Should generate a random Mac address at startup.
        cls.no_deauth = False # Deauth hidden networks & WPA handshake targets
        # aireplay -0 包数：对齐 aireplay-ng 源码 do_attack_deauth 有向 64 帧
        cls.num_deauths = 64
        # deauth 引擎：auto=有 scapy 则双通道，both/scapy/aireplay
        cls.deauth_engine = 'auto'
        # Scapy 突发（对齐 aireplay-ng 源码 + auto_attack.py / MT7921U）:
        #   0 = 自动（精准每向 64、广播每向 128）；>0 强制每向份数
        #   rounds=4 → 每目标约 256×4=1024 帧/次爆发；inter=0.003
        # 周期: 爆发(×rounds=4) → 静默监听 wpa_deauth_listen 秒 → 再爆发
        # （静默期纯收包等 EAPOL；发包策略按网卡驱动自动选）
        cls.scapy_deauth_count = 0
        cls.scapy_deauth_rounds = 4
        cls.scapy_deauth_inter = 0.003
        cls.wpa_deauth_listen = 10  # 爆发后静默秒数（默认 10s，给足重连/EAPOL）


        cls.encryption_filter = ['WEP', 'WPA', 'WPS']

        # EvilTwin variables
        cls.use_eviltwin = False
        cls.eviltwin_port = 80
        cls.eviltwin_deauth_iface = None
        cls.eviltwin_fakeap_iface = None

        # WEP variables
        cls.wep_filter = False # Only attack WEP networks
        cls.wep_pps = 600 # Packets per second
        cls.wep_timeout = 600 # Seconds to wait before failing
        cls.wep_crack_at_ivs = 10000 # Minimum IVs to start cracking
        cls.require_fakeauth = False
        cls.wep_restart_stale_ivs = 11 # Seconds to wait before restarting
                                                 # Aireplay if IVs don't increaes.
                                                 # '0' means never restart.
        cls.wep_restart_aircrack = 30  # Seconds to give aircrack to crack
                                                 # before restarting the process.
        cls.wep_crack_at_ivs = 10000   # Number of IVS to start cracking
        cls.wep_keep_ivs = False       # Retain .ivs files across multiple attacks.

        # WPA variables
        cls.wpa_filter = False # Only attack WPA networks
        # 兼容旧名：与 wpa_deauth_listen 同步；调度器会按切片微调 listen
        cls.wpa_deauth_timeout = 10
        cls.wpa_attack_timeout = 45 # 单路径握手捕获下限 45s（调度器按切片覆盖）
        cls.wpa_handshake_dir = 'hs' # Dir to store handshakes
        cls.wpa_strip_handshake = False # Strip non-handshake packets
        cls.ignore_old_handshakes = False # Always fetch a new handshake

        # 单目标总预算 / 每条攻击路径最短时长（秒）
        # PMKID ≥60s，其它 ≥45s；4 路径抬高约 60+45*3=195，默认总预算 210
        # 不够各自下限时自动抬高总预算
        cls.target_timeout = 210
        cls.attack_min_slice = 45
        # 闭环：--auto 扫完即打全部；path_deadline 只约束捕获
        cls.auto_attack = False
        cls.path_deadline = None  # float unix ts，当前路径墙钟截止
        cls.hashcat_runtime = 0   # 0=跟 path_deadline；>0 显式秒数
        # 捕获后字典默认独立窗口/后台全量跑（--no-bg-crack 可关）
        cls.bg_crack = True

        # PMKID variables
        cls.use_pmkid_only = False  # Only use PMKID Capture+Crack attack
        cls.pmkid_timeout = 60  # 默认；调度器按切片覆盖（下限 60）

        # hashcat 离线口令审计（rules + 掩码 + 增量）
        cls.hashcat_rules = None       # 规则文件路径，如 /usr/share/hashcat/rules/best64.rule
        cls.hashcat_mask = None        # 自定义掩码，如 ?d?d?d?d?d?d?d?d（8 位纯数字）
        cls.hashcat_increment = False  # 掩码阶段增量，WPA 口令最短 8 位
        cls.hashcat_increment_max = 8  # 增量最大长度
        cls.hashcat_extra_args = None  # 透传额外 hashcat 参数（高级用户）

        # 中国大陆审计配置：CLI 未指定时只按明确 IANA 时区自动启用
        cls.cn_optimize = False        # 字典失败后追加经授权的弱口令掩码核查
        cls.cn_auto_detected = False
        cls.cn_region_source = 'unresolved'
        cls.cn_mask_limit = 4          # 自动掩码阶段数量（控制耗时）

        # 自动更新检测（启动时查 GitHub 最新 Release，仅提示不自动安装）
        cls.update_check = True        # 可用 --no-update 关闭

        # Default dictionary for cracking（优先 ck 增强词典）
        cls.cracked_file = 'cracked.txt'
        cls.wordlist = None
        _root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        wordlists = [
            os.path.join(_root, 'wordlists', 'ck-default-wpa.txt'),
            './wordlists/ck-default-wpa.txt',
            './wordlists/wpa-top4800.txt',
            './wordlist-top4800-probable.txt',
            # 安装后（deb / pip）字典落在 share/ck-wifikiller/wordlists/
            '/usr/share/ck-wifikiller/wordlists/ck-default-wpa.txt',
            '/usr/local/share/ck-wifikiller/wordlists/ck-default-wpa.txt',
            '/usr/share/ck-wifikiller/wordlists/rockyou.txt',
            '/usr/local/share/ck-wifikiller/wordlists/rockyou.txt',
            '/usr/share/dict/wordlist-top4800-probable.txt',
            '/usr/local/share/dict/wordlist-top4800-probable.txt',
            '/usr/share/wordlists/fern-wifi/common.txt',
        ]
        # 环境变量显式指定字典（最高优先级）
        env_wl = os.environ.get('CK_WIFI_WORDLIST', '').strip()
        if env_wl:
            wordlists.insert(0, env_wl)
        for wlist in wordlists:
            # 支持文件或目录：目录内自动搜索常见字典名
            resolved, _how = cls.resolve_wordlist(wlist)
            if resolved:
                cls.wordlist = resolved
                break

        # WPS variables
        cls.wps_filter  = False  # Only attack WPS networks
        cls.no_wps      = False  # Do not use WPS attacks (Pixie-Dust & PIN attacks)
        cls.wps_only    = False  # ONLY use WPS attacks on non-WEP networks
        cls.use_bully   = False  # Use bully instead of reaver
        cls.wps_pixie   = True
        cls.wps_pin     = True   # 默认不跳过 PIN，由时长切片控制
        cls.wps_ignore_lock = False  # Skip WPS PIN attack if AP is locked.
        cls.wps_pixie_timeout = 60       # Pixie 墙钟；调度器按切片覆盖
        cls.wps_pin_timeout = 60         # PIN 墙钟；调度器按切片覆盖
        cls.wps_fail_threshold = 100     # Max number of failures
        cls.wps_timeout_threshold = 100  # Max number of timeouts

        # Commands
        cls.show_cracked = False
        cls.check_handshake = None
        cls.crack_handshake = False
        cls.recon_mode = None  # status|audit|kismet|bettercap|report

        # Overwrite config values with arguments (if defined)
        cls.load_from_arguments()

        if load_interface:
            cls.get_monitor_mode_interface()


    @classmethod
    def get_monitor_mode_interface(cls):
        if cls.interface is None:
            # Interface wasn't defined, select it!
            from .tools.airmon import Airmon
            cls.interface = Airmon.ask()
            if cls.random_mac:
                Macchanger.random()

    @classmethod
    def load_from_arguments(cls):
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        args = Arguments(cls).args
        cls.parse_settings_args(args)
        cls.parse_wep_args(args)
        cls.parse_wpa_args(args)
        cls.parse_wps_args(args)
        cls.parse_pmkid_args(args)
        cls.parse_hashcat_args(args)
        cls.parse_schedule_args(args)
        cls.parse_encryption()

        # 打印字典加载状态，帮助模式不打扰
        if '-h' not in sys.argv and '--help' not in sys.argv:
            if cls.wordlist:
                Color.pl('{+} {D}wordlist: {G}%s{W}' % cls.wordlist)
            else:
                Color.pl('{!} {O}no wordlist found; handshake/PMKID cracks will be skipped '
                         '(use {C}--dict <file|dir>{O} or env {C}CK_WIFI_WORDLIST{O}){W}')

        # EvilTwin
        '''
        if args.use_eviltwin:
            cls.use_eviltwin = True
            Color.pl('{+} {C}option:{W} using {G}eviltwin attacks{W} against all targets')
        '''

        cls.parse_wep_attacks()

        cls.validate()

        # Commands
        if args.cracked:         cls.show_cracked = True
        if args.check_handshake: cls.check_handshake = args.check_handshake
        if args.crack_handshake: cls.crack_handshake = True
        if getattr(args, 'recon_mode', None):
            cls.recon_mode = args.recon_mode


    @classmethod
    def validate(cls):
        if cls.use_pmkid_only and cls.wps_only:
            Color.pl('{!} {R}Bad Configuration:{O} --pmkid and --wps-only are not compatible')
            raise RuntimeError('Unable to attack networks: --pmkid and --wps-only are not compatible together')


    @classmethod
    def parse_settings_args(cls, args):
        '''Parses basic settings/configurations from arguments.'''
        if args.random_mac:
            cls.random_mac = True
            Color.pl('{+} {C}option:{W} using {G}random mac address{W} ' +
                    'when scanning & attacking')

        if args.channel:
            from .util.validate import is_safe_channel
            if not is_safe_channel(args.channel):
                Color.pl('{!} {R}invalid channel:{O} %s{W}' % args.channel)
                raise RuntimeError('Invalid channel: %r' % args.channel)
            cls.target_channel = args.channel
            Color.pl('{+} {C}option:{W} scanning for targets on channel ' +
                    '{G}%s{W}' % args.channel)

        if args.interface:
            from .util.validate import is_safe_iface
            if not is_safe_iface(args.interface):
                Color.pl('{!} {R}invalid interface name:{O} %s{W}' % args.interface)
                raise RuntimeError('Invalid wireless interface name: %r' % args.interface)
            cls.interface = args.interface
            Color.pl('{+} {C}option:{W} using wireless interface ' +
                    '{G}%s{W}' % args.interface)

        if args.target_bssid:
            from .util.validate import is_mac_address
            if not is_mac_address(args.target_bssid):
                Color.pl('{!} {R}invalid BSSID:{O} %s{W}' % args.target_bssid)
                raise RuntimeError('Invalid target BSSID: %r' % args.target_bssid)
            cls.target_bssid = args.target_bssid
            Color.pl('{+} {C}option:{W} targeting BSSID ' +
                    '{G}%s{W}' % args.target_bssid)

        if args.five_ghz == True:
            cls.five_ghz = True
            Color.pl('{+} {C}option:{W} including {G}5Ghz networks{W} in scans')

        if args.show_bssids == True:
            cls.show_bssids = True
            Color.pl('{+} {C}option:{W} showing {G}bssids{W} of targets during scan')

        if args.no_deauth == True:
            cls.no_deauth = True
            Color.pl('{+} {C}option:{W} will {R}not{W} {O}deauth{W} clients ' +
                    'during scans or captures')

        if args.num_deauths and args.num_deauths > 0:
            cls.num_deauths = args.num_deauths
            Color.pl('{+} {C}option:{W} send {G}%d{W} deauth packets when deauthing' % (
                cls.num_deauths))

        if getattr(args, 'deauth_engine', None):
            eng = str(args.deauth_engine).strip().lower()
            if eng in ('auto', 'both', 'scapy', 'aireplay'):
                cls.deauth_engine = eng
                Color.pl('{+} {C}option:{W} deauth engine {G}%s{W}' % cls.deauth_engine)

        if getattr(args, 'scapy_deauth_count', None):
            try:
                cls.scapy_deauth_count = max(4, min(256, int(args.scapy_deauth_count)))
                Color.pl('{+} {C}option:{W} scapy deauth burst {G}%d{W}/dir' % cls.scapy_deauth_count)
            except (TypeError, ValueError):
                pass

        if args.target_essid:
            cls.target_essid = args.target_essid
            Color.pl('{+} {C}option:{W} targeting ESSID {G}%s{W}' % args.target_essid)

        if args.ignore_essid is not None:
            cls.ignore_essid = args.ignore_essid
            Color.pl('{+} {C}option:{W} {O}ignoring ESSIDs that include {R}%s{W}' % (
                args.ignore_essid))

        if args.clients_only == True:
            cls.clients_only = True
            Color.pl('{+} {C}option:{W} {O}ignoring targets that do not have ' +
                'associated clients')

        if args.scan_time:
            cls.scan_time = args.scan_time
            Color.pl('{+} {C}option:{W} ({G}pillage{W}) attack all targets ' +
                'after {G}%d{W}s' % args.scan_time)

        if getattr(args, 'auto_attack', False):
            cls.auto_attack = True
            # 未指定 -p 时给默认扫描窗口，扫完直接打 all
            if not cls.scan_time:
                cls.scan_time = 15
            Color.pl('{+} {C}option:{W} ({G}auto{W}) scan {G}%ds{W} then attack all'
                     % cls.scan_time)

        if args.verbose:
            cls.verbose = args.verbose
            Color.pl('{+} {C}option:{W} verbosity level {G}%d{W}' % args.verbose)

        if hasattr(args, 'update_check') and args.update_check is False:
            cls.update_check = False
            Color.pl('{+} {C}option:{W} startup update check {R}disabled{W}')

        if args.kill_conflicting_processes:
            cls.kill_conflicting_processes = True
            Color.pl('{+} {C}option:{W} kill conflicting processes {G}enabled{W}')


    @classmethod
    def parse_wep_args(cls, args):
        '''Parses WEP-specific arguments'''
        if args.wep_filter:
            cls.wep_filter = args.wep_filter

        if args.wep_pps:
            cls.wep_pps = args.wep_pps
            Color.pl('{+} {C}option:{W} using {G}%d{W} packets/sec on WEP attacks' % (
                args.wep_pps))

        if args.wep_timeout:
            cls.wep_timeout = args.wep_timeout
            Color.pl('{+} {C}option:{W} WEP attack timeout set to ' +
                '{G}%d seconds{W}' % args.wep_timeout)

        if args.require_fakeauth:
            cls.require_fakeauth = True
            Color.pl('{+} {C}option:{W} fake-authentication is ' +
                '{G}required{W} for WEP attacks')

        if args.wep_crack_at_ivs:
            cls.wep_crack_at_ivs = args.wep_crack_at_ivs
            Color.pl('{+} {C}option:{W} will start cracking WEP keys at ' +
                '{G}%d IVs{W}' % args.wep_crack_at_ivs)

        if args.wep_restart_stale_ivs:
            cls.wep_restart_stale_ivs = args.wep_restart_stale_ivs
            Color.pl('{+} {C}option:{W} will restart aireplay after ' +
                '{G}%d seconds{W} of no new IVs' % args.wep_restart_stale_ivs)

        if args.wep_restart_aircrack:
            cls.wep_restart_aircrack = args.wep_restart_aircrack
            Color.pl('{+} {C}option:{W} will restart aircrack every ' +
                '{G}%d seconds{W}' % args.wep_restart_aircrack)

        if args.wep_keep_ivs:
            cls.wep_keep_ivs = args.wep_keep_ivs
            Color.pl('{+} {C}option:{W} keep .ivs files across multiple WEP attacks')

    # 目录内常见字典名（按优先级精确匹配）
    WORDLIST_COMMON_NAMES = (
        'rockyou.txt',
        'wifi_cn_combined.txt',
        'wifi_combined.txt',
        'wpa_cn_combined.txt',
        'ck-default-wpa.txt',
        'wpa-top4800.txt',
        'password.lst',
        'passwords.txt',
        'common.txt',
        'wordlist.txt',
    )
    # 目录内兜底匹配模式（按优先级）
    WORDLIST_PATTERNS = ('*combined*.txt', 'wifi*.txt', '*.txt', '*.lst')

    @classmethod
    def resolve_wordlist(cls, path):
        '''把用户给定的字典路径解析为可用字典文件。

        支持三种输入：
          - 具体文件：存在即返回
          - 目录：按优先级在目录内搜索常见字典名与通配模式
          - 环境变量 / 配置候选：走同一套逻辑（文件或目录都接受）

        返回 (filepath|None, how)，how 取值：file / dir / missing / dir_empty / empty。
        '''
        import glob
        if not path:
            return None, 'empty'
        if os.path.isfile(path):
            return path, 'file'
        if not os.path.isdir(path):
            return None, 'missing'
        # 目录：先精确匹配常见字典名
        for name in cls.WORDLIST_COMMON_NAMES:
            cand = os.path.join(path, name)
            if os.path.isfile(cand):
                return cand, 'dir'
        # 再按通配模式匹配（只取第一个）
        for pattern in cls.WORDLIST_PATTERNS:
            hits = sorted(f for f in glob.glob(os.path.join(path, pattern)) if os.path.isfile(f))
            if hits:
                return hits[0], 'dir'
        return None, 'dir_empty'

    @classmethod
    def parse_wpa_args(cls, args):
        '''Parses WPA-specific arguments'''
        if args.wpa_filter:
            cls.wpa_filter = args.wpa_filter

        if args.wordlist:
            resolved, how = cls.resolve_wordlist(args.wordlist)
            if resolved is None:
                cls.wordlist = None
                if how == 'dir_empty':
                    # 目录存在但里面没有任何字典文件
                    Color.pl('{+} {C}option:{O} wordlist dir {R}%s{O} contains no dict file (rockyou.txt / *.txt / *.lst), ck-wifikiller will NOT crack' % args.wordlist)
                else:
                    Color.pl('{+} {C}option:{O} wordlist {R}%s{O} was not found, ck-wifikiller will NOT attempt to crack handshakes' % args.wordlist)
            elif how == 'dir':
                cls.wordlist = resolved
                Color.pl('{+} {C}option:{W} %s{O} is a directory, using {G}%s{W} to crack WPA handshakes' % (args.wordlist, resolved))
            else:
                cls.wordlist = resolved
                Color.pl('{+} {C}option:{W} using wordlist {G}%s{W} to crack WPA handshakes' % resolved)

        if args.wpa_deauth_timeout:
            cls.wpa_deauth_timeout = max(3, int(args.wpa_deauth_timeout))
            cls.wpa_deauth_listen = cls.wpa_deauth_timeout
            Color.pl('{+} {C}option:{W} after deauth volley, quiet listen '
                     '{G}%ds{W}' % cls.wpa_deauth_listen)
        if getattr(args, 'wpa_deauth_listen', None):
            cls.wpa_deauth_listen = max(5, min(30, int(args.wpa_deauth_listen)))
            cls.wpa_deauth_timeout = cls.wpa_deauth_listen
            Color.pl('{+} {C}option:{W} deauth quiet listen '
                     '{G}%ds{W}' % cls.wpa_deauth_listen)

        if args.wpa_attack_timeout:
            cls.wpa_attack_timeout = args.wpa_attack_timeout
            Color.pl('{+} {C}option:{W} will stop WPA handshake capture after ' +
                    '{G}%d seconds{W}' % args.wpa_attack_timeout)

        if args.ignore_old_handshakes:
            cls.ignore_old_handshakes = True
            Color.pl('{+} {C}option:{W} will {O}ignore{W} existing handshakes ' +
                    '(force capture)')

        if args.wpa_handshake_dir:
            cls.wpa_handshake_dir = args.wpa_handshake_dir
            Color.pl('{+} {C}option:{W} will store handshakes to ' +
                    '{G}%s{W}' % args.wpa_handshake_dir)

        if args.wpa_strip_handshake:
            cls.wpa_strip_handshake = True
            Color.pl('{+} {C}option:{W} will {G}strip{W} non-handshake packets')

    @classmethod
    def parse_wps_args(cls, args):
        '''Parses WPS-specific arguments'''
        if args.wps_filter:
            cls.wps_filter = args.wps_filter

        if args.wps_only:
            cls.wps_only = True
            cls.wps_filter = True  # Also only show WPS networks
            Color.pl('{+} {C}option:{W} will *only* attack WPS networks with ' +
                    '{G}WPS attacks{W} (avoids handshake and PMKID)')

        if args.no_wps:
            # No WPS attacks at all
            cls.no_wps = args.no_wps
            cls.wps_pixie = False
            cls.wps_pin = False
            Color.pl('{+} {C}option:{W} will {O}never{W} use {C}WPS attacks{W} ' +
                    '(Pixie-Dust/PIN) on targets')

        elif args.wps_pixie:
            # WPS Pixie-Dust only
            cls.wps_pixie = True
            cls.wps_pin = False
            Color.pl('{+} {C}option:{W} will {G}only{W} use {C}WPS Pixie-Dust ' +
                    'attack{W} (no {O}PIN{W}) on targets')

        elif args.wps_no_pixie:
            # WPS PIN only
            cls.wps_pixie = False
            cls.wps_pin = True
            Color.pl('{+} {C}option:{W} will {G}only{W} use {C}WPS PIN attack{W} ' +
                    '(no {O}Pixie-Dust{W}) on targets')

        if args.use_bully:
            from .tools.bully import Bully
            if not Bully.exists():
                Color.pl('{!} {R}Bully not found. Defaulting to {O}reaver{W}')
                cls.use_bully = False
            else:
                cls.use_bully = args.use_bully
                Color.pl('{+} {C}option:{W} use {C}bully{W} instead of {C}reaver{W} ' +
                        'for WPS Attacks')

        if args.wps_pixie_timeout:
            cls.wps_pixie_timeout = args.wps_pixie_timeout
            Color.pl('{+} {C}option:{W} WPS pixie-dust attack will fail after ' +
                    '{O}%d seconds{W}' % args.wps_pixie_timeout)

        if args.wps_fail_threshold:
            cls.wps_fail_threshold = args.wps_fail_threshold
            Color.pl('{+} {C}option:{W} will stop WPS attack after ' +
                    '{O}%d failures{W}' % args.wps_fail_threshold)

        if args.wps_timeout_threshold:
            cls.wps_timeout_threshold = args.wps_timeout_threshold
            Color.pl('{+} {C}option:{W} will stop WPS attack after ' +
                    '{O}%d timeouts{W}' % args.wps_timeout_threshold)

        if args.wps_ignore_lock:
            cls.wps_ignore_lock = True
            Color.pl('{+} {C}option:{W} will {O}ignore{W} WPS lock-outs')

    @classmethod
    def parse_pmkid_args(cls, args):
        if args.use_pmkid_only:
            cls.use_pmkid_only = True
            Color.pl('{+} {C}option:{W} will ONLY use {C}PMKID{W} attack on WPA networks')

        if args.pmkid_timeout:
            cls.pmkid_timeout = args.pmkid_timeout
            Color.pl('{+} {C}option:{W} will wait {G}%d seconds{W} during {C}PMKID{W} capture' % args.pmkid_timeout)

    @classmethod
    def parse_schedule_args(cls, args):
        '''单目标总时长 / 每路径最短切片。'''
        if getattr(args, 'target_timeout', None):
            cls.target_timeout = max(45, int(args.target_timeout))
            Color.pl('{+} {C}option:{W} target budget {G}%ds{W}' % cls.target_timeout)
        if getattr(args, 'attack_min_slice', None):
            cls.attack_min_slice = max(45, int(args.attack_min_slice))
            Color.pl('{+} {C}option:{W} min slice per path {G}%ds{W} '
                     '(PMKID floor 60s)' % cls.attack_min_slice)
        if getattr(args, 'no_bg_crack', False):
            cls.bg_crack = False
            Color.pl('{+} {C}option:{W} background crack window {O}disabled{W}')
        elif getattr(args, 'bg_crack', None) is False:
            cls.bg_crack = False

    @classmethod
    def parse_hashcat_args(cls, args):
        '''hashcat 爆破增强参数（rules / mask / 增量 / 透传）'''
        if getattr(args, 'hashcat_rules', None):
            if os.path.isfile(args.hashcat_rules):
                cls.hashcat_rules = args.hashcat_rules
                Color.pl('{+} {C}option:{W} hashcat rules: {G}%s{W}' % args.hashcat_rules)
            else:
                Color.pl('{!} {O}rules file not found, ignoring: {R}%s{W}' % args.hashcat_rules)

        if getattr(args, 'hashcat_mask', None):
            cls.hashcat_mask = args.hashcat_mask
            Color.pl('{+} {C}option:{W} hashcat mask brute force: {G}%s{W}' % args.hashcat_mask)

        if getattr(args, 'hashcat_increment', False):
            cls.hashcat_increment = True
            Color.pl('{+} {C}option:{W} hashcat incremental mode {G}enabled{W}')

        if getattr(args, 'hashcat_increment_max', None):
            cls.hashcat_increment_max = max(8, min(63, args.hashcat_increment_max))
            Color.pl('{+} {C}option:{W} hashcat increment max length {G}%d{W}'
                     % cls.hashcat_increment_max)

        if getattr(args, 'hashcat_extra_args', None):
            cls.hashcat_extra_args = args.hashcat_extra_args
            Color.pl('{+} {C}option:{W} hashcat extra args: {G}%s{W}' % args.hashcat_extra_args)

        from .util.region import resolve_cn_mode
        cn_arg = getattr(args, 'cn_optimize', None)
        cls.cn_optimize, cls.cn_region_source = resolve_cn_mode(cn_arg)
        cls.cn_auto_detected = cn_arg is None and cls.cn_optimize
        if cls.cn_optimize:
            mode = 'auto' if cls.cn_auto_detected else 'explicit'
            Color.pl('{+} {C}option:{W} {G}中国大陆审计配置 / CN profile{W} '
                     'enabled ({D}%s, %s{W})' % (mode, cls.cn_region_source))

        if getattr(args, 'cn_mask_limit', None):
            cls.cn_mask_limit = max(1, min(8, args.cn_mask_limit))
            Color.pl('{+} {C}option:{W} CN mask stages: {G}%d{W}' % args.cn_mask_limit)

    @classmethod
    def parse_encryption(cls):
        '''Adjusts encryption filter (WEP and/or WPA and/or WPS)'''
        cls.encryption_filter = []
        if cls.wep_filter: cls.encryption_filter.append('WEP')
        if cls.wpa_filter: cls.encryption_filter.append('WPA')
        if cls.wps_filter: cls.encryption_filter.append('WPS')

        if len(cls.encryption_filter) == 3:
            Color.pl('{+} {C}option:{W} targeting {G}all encrypted networks{W}')
        elif len(cls.encryption_filter) == 0:
            # Default to scan all types
            cls.encryption_filter = ['WEP', 'WPA', 'WPS']
        else:
            Color.pl('{+} {C}option:{W} ' +
                     'targeting {G}%s-encrypted{W} networks'
                        % '/'.join(cls.encryption_filter))

    @classmethod
    def parse_wep_attacks(cls):
        '''Parses and sets WEP-specific args (-chopchop, -fragment, etc)'''
        cls.wep_attacks = []
        from sys import argv
        seen = set()
        for arg in argv:
            if arg in seen: continue
            seen.add(arg)
            if arg == '-arpreplay':  cls.wep_attacks.append('replay')
            if arg == '-fragment':   cls.wep_attacks.append('fragment')
            if arg == '-chopchop':   cls.wep_attacks.append('chopchop')
            if arg == '-caffelatte': cls.wep_attacks.append('caffelatte')
            if arg == '-p0841':      cls.wep_attacks.append('p0841')
            if arg == '-hirte':      cls.wep_attacks.append('hirte')

        if len(cls.wep_attacks) == 0:
            # Use all attacks
            cls.wep_attacks = ['replay',
                'fragment',
                'chopchop',
                'caffelatte',
                'p0841',
                'hirte'
            ]
        elif len(cls.wep_attacks) > 0:
            Color.pl('{+} {C}option:{W} using {G}%s{W} WEP attacks'
                % '{W}, {G}'.join(cls.wep_attacks))


    @classmethod
    def temp(cls, subfile=''):
        ''' Creates and/or returns the temporary directory.

        subfile 仅允许相对文件名（会剥离目录分量），防止路径穿越写出临时目录外。
        无 subfile 时返回带尾部分隔符的目录路径，兼容历史 ``temp() + prefix`` 用法。
        '''
        if cls.temp_dir is None:
            cls.temp_dir = cls.create_temp()
        if not subfile:
            return cls.temp_dir
        # 禁止绝对路径与目录穿越
        name = os.path.basename(str(subfile).replace('\\', '/'))
        if not name or name in ('.', '..'):
            raise ValueError('invalid temp subfile name: %r' % (subfile,))
        return os.path.join(cls.temp_dir, name)

    @staticmethod
    def create_temp():
        ''' Creates and returns a temporary directory '''
        from tempfile import mkdtemp
        tmp = mkdtemp(prefix='ck-wifikiller-')
        if not tmp.endswith(os.sep):
            tmp += os.sep
        return tmp

    @classmethod
    def delete_temp(cls):
        ''' Remove temp files and folder '''
        if cls.temp_dir is None:
            return
        path = cls.temp_dir
        cls.temp_dir = None
        if os.path.isdir(path):
            import shutil
            try:
                shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass


    @classmethod
    def exit_gracefully(cls, code=0):
        ''' Deletes temp and exist with the given code '''
        cls.delete_temp()
        Macchanger.reset_if_changed()
        from .tools.airmon import Airmon
        if cls.interface is not None and Airmon.base_interface is not None:
            Color.pl('{!} {O}Note:{W} Leaving interface in Monitor Mode!')
            Color.pl('{!} To disable Monitor Mode when finished: ' +
                    '{C}airmon-ng stop %s{W}' % cls.interface)

            # Stop monitor mode
            #Airmon.stop(cls.interface)
            # Bring original interface back up
            #Airmon.put_interface_up(Airmon.base_interface)

        if Airmon.killed_network_manager:
            Color.pl('{!} You can restart NetworkManager when finished ({C}sudo systemctl start NetworkManager{W})')
            #Airmon.start_network_manager()

        exit(code)

    @classmethod
    def dump(cls):
        ''' (Colorful) string representation of the configuration '''
        from .util.color import Color

        max_len = 20
        for key in cls.__dict__.keys():
            max_len = max(max_len, len(key))

        result  = Color.s('{W}%s  Value{W}\n' % 'cls Key'.ljust(max_len))
        result += Color.s('{W}%s------------------{W}\n' % ('-' * max_len))

        for (key,val) in sorted(cls.__dict__.items()):
            if key.startswith('__') or type(val) in [classmethod, staticmethod] or val is None:
                continue
            result += Color.s('{G}%s {W} {C}%s{W}\n' % (key.ljust(max_len),val))
        return result

if __name__ == '__main__':
    Configuration.initialize(False)
    print(Configuration.dump())
