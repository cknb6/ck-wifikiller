#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashcat / hcxtools 封装 — 兼容 2024–2026 Kali

权威链路 (hashcat wiki + Kali hcxtools):
  hcxdumptool -i IFACE -w dump.pcapng [--bpf=filter.bpf] [-c CHa]
  hcxpcapngtool -o hash.hc22000 -E essid.list dump.pcapng
  hashcat -m 22000 hash.hc22000 wordlist

已废弃: -m 2500/.hccapx, -m 16800, 命令名 hcxpcaptool
"""

from __future__ import annotations

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import re
import shlex
import shutil
import subprocess
import tempfile


def _which_first(*names: str) -> str | None:
    for n in names:
        path = shutil.which(n)
        if path:
            return n
    return None


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'
    # 统一现代模式
    MODE_WPA = '22000'

    @staticmethod
    def _devices_blob() -> str:
        try:
            process = Process(['hashcat', '-I'])
            stdout, stderr = process.get_output()
            return (stdout or '') + (stderr or '')
        except Exception:
            return ''

    @staticmethod
    def should_use_force() -> bool:
        '''无稳定设备、或仅 CPU/虚拟机时建议 --force，避免 OpenCL 自检炸崩。'''
        blob = Hashcat._devices_blob()
        if not blob.strip():
            return True
        low = blob.lower()
        if 'no devices found' in low or 'no devices found/left' in low:
            return True
        if 'cuda' not in low and 'hip' not in low:
            if 'pocl' in low or 'cpu' in low or 'opencl' not in low:
                return True
        return False

    @staticmethod
    def detect_backend() -> dict:
        """探测 Kali 上 hashcat 该用 GPU 还是 CPU。

        返回:
          mode: gpu | cpu
          args: 建议附加参数（--force / -D 1）
          label: 给人看的说明
        """
        blob = Hashcat._devices_blob()
        low = blob.lower()
        force = Hashcat.should_use_force()

        has_cuda = 'cuda' in low and ('device' in low or '#' in blob)
        has_hip = 'hip' in low
        has_cl_gpu = (
            'opencl' in low
            and any(x in low for x in (
                'gpu', 'geforce', 'radeon', 'nvidia', 'amd ', 'intel(r) arc',
                'graphics',
            ))
            and 'pocl' not in low
        )

        args: list[str] = []
        if force:
            args.append('--force')

        if has_cuda or has_hip or has_cl_gpu:
            return {
                'mode': 'gpu',
                'args': args if args else [],
                'label': 'GPU (CUDA/OpenCL)',
            }

        # 默认 CPU：虚拟机 / 无独显 / 仅 pocl
        return {
            'mode': 'cpu',
            'args': ['--force', '-D', '1'],
            'label': 'CPU (--force -D 1；无可用独显时用这个)',
        }

    @staticmethod
    def backend_cli_prefix() -> list[str]:
        try:
            return list(Hashcat.detect_backend().get('args') or [])
        except Exception:
            return ['--force', '-D', '1']

    @staticmethod
    def _extract_key(stdout: str) -> str | None:
        if not stdout or ':' not in stdout:
            return None
        # 22000 pot/show: hash:password 或 multi-field
        line = stdout.strip().splitlines()[-1]
        if ':' not in line:
            return None
        return line.rsplit(':', 1)[-1].strip() or None

    @staticmethod
    def _runtime_seconds() -> int:
        """根据路径墙钟截止 / 显式 hashcat_runtime 计算 --runtime 秒数。

        最佳实践 (hashcat docs): --runtime=N 在 N 秒后中止会话。
        预算已尽返回 0（调用方应跳过爆破，勿再强行跑 1s）。
        """
        import time as _time
        deadline = getattr(Configuration, 'path_deadline', None)
        if deadline is not None:
            return max(0, int(deadline - _time.time()))
        try:
            rt = int(getattr(Configuration, 'hashcat_runtime', 0) or 0)
        except (TypeError, ValueError):
            rt = 0
        return max(0, rt)

    @staticmethod
    def budget_exhausted() -> bool:
        """路径预算是否已尽（有 deadline 且剩余 < 1s）。"""
        if getattr(Configuration, 'path_deadline', None) is None:
            return False
        return Hashcat._runtime_seconds() < 1

    @staticmethod
    def _extra_attack_args(is_mask: bool = False) -> list[str]:
        """按攻击模式构建 hashcat 附加参数，避免组合无效选项。"""
        extra: list[str] = []
        rules = getattr(Configuration, 'hashcat_rules', None)
        if not is_mask and rules and os.path.isfile(rules):
            extra.extend(['-r', rules])

        # WPA/WPA2 口令最短 8 位；increment 只允许用于掩码模式 -a 3。
        if is_mask and getattr(Configuration, 'hashcat_increment', False):
            try:
                increment_max = int(getattr(Configuration, 'hashcat_increment_max', 8))
            except (TypeError, ValueError):
                increment_max = 8
            increment_max = max(8, increment_max)
            extra.append('--increment')
            extra.extend(['--increment-min', '8'])
            extra.extend(['--increment-max', str(increment_max)])

        # 时间预算：官方 --runtime 将爆破纳入路径剩余墙钟
        rt = Hashcat._runtime_seconds()
        if rt > 0:
            extra.extend(['--runtime', str(rt)])

        raw = getattr(Configuration, 'hashcat_extra_args', None)
        if raw:
            if isinstance(raw, str):
                extra.extend(shlex.split(raw))
            else:
                extra.extend([str(x) for x in raw])
        return extra

    @staticmethod
    def _run_hc22000_phase(
        hash_file: str,
        attack_args: list[str],
        is_mask: bool,
        verbose: bool = False,
        use_runtime: bool = True,
    ) -> str | None:
        '''执行单阶段 hashcat -m 22000（字典或掩码）。'''
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',
                '-m', Hashcat.MODE_WPA,
                '--self-test-disable',
            ]
            # GPU/CPU 后端（Kali 无独显时强制 CPU，避免 segfault）
            for tok in Hashcat.backend_cli_prefix():
                if tok not in command:
                    command.append(tok)
            command.extend(attack_args[:2])  # -a 0|3
            if use_runtime:
                command.extend(Hashcat._extra_attack_args(is_mask=is_mask))
            else:
                # 快打：rules 可保留，但不套 path_deadline --runtime
                extra = Hashcat._extra_attack_args(is_mask=is_mask)
                cleaned: list[str] = []
                skip_next = False
                for tok in extra:
                    if skip_next:
                        skip_next = False
                        continue
                    if tok == '--runtime':
                        skip_next = True
                        continue
                    cleaned.append(tok)
                command.extend(cleaned)
            # backend 已含 --force 时不再重复
            if Hashcat.should_use_force() and '--force' not in command:
                command.append('--force')
            command.extend(additional_arg)
            command.extend(attack_args[2:])
            if verbose and not additional_arg:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            proc = Process(command)
            proc.wait()
            key = Hashcat._extract_key(proc.stdout() or '')
            if key:
                return key
        return None

    @staticmethod
    def crack_hc22000(hash_file: str, verbose: bool = False,
                      essid: str | None = None) -> str | None:
        """对 hashcat -m 22000 文件跑字典（握手+PMKID 通用）。

        阶段:
          0) hcxpsktool 弱口令候选（Kali hcxtools，可选快打）
          1) 用户字典 (-a 0) + rules
          2) 掩码 (-a 3)（若提供）
        """
        if Configuration.wordlist is None and Configuration.hashcat_mask is None:
            # 仍允许仅 hcxpsktool
            pass
        if not os.path.isfile(hash_file):
            return None
        if Hashcat.budget_exhausted():
            return None

        # 0) hcxpsktool 候选（不占用长 budget：无 --runtime）
        try:
            from .hcx_psk import HcxPskTool
            if HcxPskTool.exists():
                cand = HcxPskTool.generate_candidates_file(hash_file, essid=essid)
                if cand:
                    try:
                        Color.pl('{+} {C}hcxpsktool{W} weak PSK candidates ...')
                        key = Hashcat._run_hc22000_phase(
                            hash_file, ['-a', '0', hash_file, cand],
                            is_mask=False, verbose=verbose, use_runtime=False)
                        if key:
                            return key
                    finally:
                        try:
                            os.remove(cand)
                        except OSError:
                            pass
        except Exception:
            pass

        if Configuration.wordlist is None and Configuration.hashcat_mask is None:
            return None

        mask = getattr(Configuration, 'hashcat_mask', None)
        phases: list[tuple[list[str], bool]] = []
        if Configuration.wordlist is not None:
            phases.append((['-a', '0', hash_file, Configuration.wordlist], False))
        if mask:
            phases.append((['-a', '3', hash_file, mask], True))

        for base, is_mask in phases:
            if Hashcat.budget_exhausted():
                break
            key = Hashcat._run_hc22000_phase(
                hash_file, base, is_mask=is_mask, verbose=verbose, use_runtime=True)
            if key:
                return key
        return None

    @staticmethod
    def crack_hc22000_mask(hash_file: str, mask: str, verbose: bool = False) -> str | None:
        """对 hc22000 文件跑单个掩码爆破（-a 3），供国内优化管线复用。"""
        if not mask or not os.path.isfile(hash_file):
            return None
        if Hashcat.budget_exhausted():
            return None
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat', '--quiet',
                '-m', Hashcat.MODE_WPA,
                '--self-test-disable',
                '-a', '3',
            ]
            command.extend(Hashcat._extra_attack_args(is_mask=True))
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            command.extend([hash_file, mask])
            if verbose and not additional_arg:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            proc = Process(command)
            proc.wait()
            key = Hashcat._extract_key(proc.stdout() or '')
            if key:
                return key
        return None

    @staticmethod
    def crack_handshake(handshake, show_command: bool = False) -> str | None:
        """cap/pcap/pcapng → hc22000 → hashcat -m 22000"""
        hc_file = HcxPcapTool.generate_hc22000_file(
            handshake.capfile, show_command=show_command)
        try:
            essid = getattr(handshake, 'essid', None)
            return Hashcat.crack_hc22000(hc_file, verbose=show_command, essid=essid)
        finally:
            if hc_file and os.path.exists(hc_file):
                try:
                    os.remove(hc_file)
                except OSError:
                    pass

    @staticmethod
    def crack_pmkid(pmkid_file: str, verbose: bool = False,
                    essid: str | None = None) -> str | None:
        """
        破解 PMKID/EAPOL 文本哈希。
        支持: *.hc22000 / *.22000 / 旧 *.16800（统一用 -m 22000 解析）。

        hashcat 6.x 已移除 -m 16800；旧 16800 星号格式需用 hcxpcapngtool
        从原始 pcapng 重新生成 .hc22000，这里不再尝试已废弃的模式。
        """
        path = pmkid_file
        if path.endswith('.16800'):
            Color.pl('{!} {O}检测到废弃的 .16800 格式，统一用 -m 22000 解析；'
                     '若失败请用 hcxpcapngtool 从原始 pcapng 重新生成 .hc22000{W}')
        return Hashcat.crack_hc22000(path, verbose=verbose, essid=essid)


class HcxDumpTool(Dependency):
    """
    现代 hcxdumptool (v6.3+ / Kali 2024+) 使用:
      -w dump.pcapng
      --bpf=filter.bpf  (旧 --filterlist 已移除)
      -c <channel>a     (如 6a)
    若探测到旧版 CLI，回退 --filterlist / -o。
    """
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, target, pcapng_file: str):
        self.target = target
        self.pcapng_file = pcapng_file
        if os.path.exists(pcapng_file):
            try:
                os.remove(pcapng_file)
            except OSError:
                pass

        iface = Configuration.interface
        bssid = target.bssid.replace(':', '').lower()
        bssid_colon = target.bssid.lower()
        ch = str(target.channel).strip()
        # 现代信道写法: 6 -> 6a (2.4G 默认 a)
        ch_arg = ch if ch.endswith(('a', 'b', 'c', 'd', 'e', 'f')) else f'{ch}a'

        help_out = ''
        try:
            help_out = Process(['hcxdumptool', '-h']).stdout() or ''
            help_out += Process(['hcxdumptool', '-h']).stderr() or ''
        except Exception:
            pass
        modern = ('--bpf' in help_out) or ('-w ' in help_out) or ('bpf=' in help_out.lower())

        command: list[str]
        if modern or _which_first('hcxdumptool'):
            # ZerBea: 现代版强制 BPF；exitoneapol 建议配合单目标 BPF
            bpf_path = Configuration.temp(f'pmkid-{bssid}.bpf')
            bpf_ok = self._build_bpf(bpf_path, bssid_colon)
            command = [
                'hcxdumptool',
                '-i', iface,
                '-w', pcapng_file,
                '-c', ch_arg,
            ]
            if bpf_ok:
                # 兼容 --bpf=path 与 --bpf path
                if 'bpf=' in help_out.lower() and '--bpf ' not in help_out:
                    command.append(f'--bpf={bpf_path}')
                else:
                    command.extend(['--bpf', bpf_path])
                # exitoneapol bitmask（ZerBea changelog / discussion）:
                #   1=PMKID  2=M2M3授权  4=M1M2挑战  → 7=任一可爆破材料即停
                # 仅在 BPF 成功时启用（官方：建议配合 target BPF）
                if '--exitoneapol' in help_out:
                    command.extend(['--exitoneapol', '7'])
            # 旧版兼容探测
            if '--filterlist' in help_out and not bpf_ok:
                fl = Configuration.temp(f'pmkid-{bssid}.filterlist')
                with open(fl, 'w', encoding='utf-8') as fh:
                    fh.write(bssid + '\n')
                command = [
                    'hcxdumptool', '-i', iface,
                    '--filterlist', fl, '--filtermode', '2',
                    '-c', ch, '-o', pcapng_file,
                ]
        else:
            fl = Configuration.temp(f'pmkid-{bssid}.filterlist')
            with open(fl, 'w', encoding='utf-8') as fh:
                fh.write(bssid + '\n')
            command = [
                'hcxdumptool', '-i', iface,
                '--filterlist', fl, '--filtermode', '2',
                '-c', ch, '-o', pcapng_file,
            ]

        self.proc = Process(command)

    @staticmethod
    def _build_bpf(bpf_path: str, bssid_colon: str) -> bool:
        """构建单目标 BPF（ZerBea hcxdumptool docs/example.md 2026）。

        官方推荐（attack 单目标）:
          wlan addr1 <AP> or wlan addr2 <AP> or wlan addr3 <AP>
          or type mgt subtype probereq
        不得过滤掉 undirected PROBEREQUEST（可含弱口令线索，且 client-less 关联需要）。
        编译：hcxdumptool --bpfc= 优先，失败 tcpdump -ddd。
        """
        # 规范 MAC（允许带冒号）
        bssid_colon = bssid_colon.strip().lower()
        # 无冒号形式（部分 bpfc/工具更稳）
        bssid_hex = bssid_colon.replace(':', '')
        exprs = [
            # ZerBea example.md 2026 官方 attack BPF
            (f'wlan addr1 {bssid_colon} or wlan addr2 {bssid_colon} '
             f'or wlan addr3 {bssid_colon} or type mgt subtype probereq'),
            # 同上 + 显式保留广播 undirected probe
            (f'wlan addr1 {bssid_colon} or wlan addr2 {bssid_colon} '
             f'or wlan addr3 {bssid_colon} or wlan addr3 ff:ff:ff:ff:ff:ff'),
            # 旧写法兼容
            f'wlan addr3 {bssid_colon} or wlan addr3 ff:ff:ff:ff:ff:ff',
            f'wlan addr3 {bssid_colon} or (wlan type mgt and subtype probe-req)',
            f'wlan addr3 {bssid_colon}',
            f'wlan addr3 {bssid_hex}',
        ]
        for expr in exprs:
            # 内置编译器
            p = Process(['hcxdumptool', f'--bpfc={expr}'])
            p.wait()
            out = (p.stdout() or '')
            err = (p.stderr() or '')
            blob = out + err
            if out.strip() and 'error' not in blob.lower()[:120]:
                try:
                    with open(bpf_path, 'w', encoding='utf-8') as f:
                        f.write(out if out.endswith('\n') else out + '\n')
                    if os.path.getsize(bpf_path) > 4:
                        return True
                except OSError:
                    pass
            # tcpdump 回退：-s 65535 -y IEEE802_11_RADIO（ZerBea 示例）
            if shutil.which('tcpdump'):
                try:
                    with open(bpf_path, 'w', encoding='utf-8') as fh:
                        r = subprocess.run(
                            ['tcpdump', '-s', '65535', '-y', 'IEEE802_11_RADIO',
                             expr, '-ddd'],
                            stdout=fh, stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    if (r.returncode == 0
                            and os.path.isfile(bpf_path)
                            and os.path.getsize(bpf_path) > 4):
                        return True
                except OSError:
                    continue
        return False

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        self.proc.interrupt()


class HcxPcapTool(Dependency):
    """
    现代工具名: hcxpcapngtool（Kali 包 hcxtools）
    旧名 hcxpcaptool 仅作回退。
    """
    dependency_required = False
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.hash_file = Configuration.temp(f'pmkid-{self.bssid}.hc22000')

    @classmethod
    def exists(cls) -> bool:
        from ..util.process import Process
        return Process.exists('hcxpcapngtool') or Process.exists('hcxpcaptool')

    @classmethod
    def fails_dependency_check(cls) -> bool:
        from ..util.color import Color
        if cls.exists():
            return False
        Color.p('{!} {O}Warning: Recommended app {R}hcxpcapngtool{O} was not found')
        Color.pl('. {W}install @ {C}%s{W} (Kali: apt install hcxtools)' % cls.dependency_url)
        return False

    @staticmethod
    def _tool() -> str:
        return _which_first('hcxpcapngtool', 'hcxpcaptool') or 'hcxpcapngtool'

    @staticmethod
    def generate_hc22000_file(capfile: str, show_command: bool = False) -> str:
        """任意 cap/pcap/pcapng → hashcat -m 22000 文本。"""
        out = Configuration.temp('generated.hc22000')
        if os.path.exists(out):
            os.remove(out)
        tool = HcxPcapTool._tool()
        command = [tool, '-o', out, capfile]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(out) or os.path.getsize(out) == 0:
            raise ValueError(
                'Failed to generate hc22000 file with %s\n%s\n%s' % (tool, stdout, stderr)
            )
        return out

    # 旧 API 兼容名
    @staticmethod
    def generate_hccapx_file(handshake, show_command: bool = False) -> str:
        Color.pl('{!} {O}hccapx/2500 已废弃，自动改用 hc22000 / -m 22000{W}')
        return HcxPcapTool.generate_hc22000_file(handshake.capfile, show_command)

    @staticmethod
    def generate_john_file(handshake, show_command: bool = False) -> str:
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)
        tool = HcxPcapTool._tool()
        # 现代 hcxpcapngtool 用 --john=
        command = [tool, f'--john={john_file}', handshake.capfile]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            # 旧 -j
            command = [tool, '-j', john_file, handshake.capfile]
            process = Process(command)
            stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file: %s\n%s' % (stdout, stderr))
        return john_file

    def get_pmkid_hash(self, pcapng_file: str) -> str | None:
        """从 pcapng 提取匹配目标 BSSID 的 WPA*01* 或任意 WPA* 行。"""
        if not os.path.exists(pcapng_file):
            return None
        if os.path.exists(self.hash_file):
            try:
                os.remove(self.hash_file)
            except OSError:
                pass

        tool = HcxPcapTool._tool()
        command = [tool, '-o', self.hash_file, pcapng_file]
        proc = Process(command)
        proc.wait()

        if not os.path.exists(self.hash_file):
            return None

        matching = None
        try:
            with open(self.hash_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith('WPA*'):
                        continue
                    fields = line.split('*')
                    # WPA*01*pmkid*macap*macclient*essid...
                    # hcxpcapngtool 的 MAC 带冒号（aa:bb:...），self.bssid 为无冒号形式
                    if len(fields) >= 5 and fields[3].lower().replace(':', '') == self.bssid:
                        matching = line
                        break
                    if len(fields) >= 4 and fields[2].lower().replace(':', '') == self.bssid:
                        # 极旧格式容错
                        matching = line
                        break
        finally:
            try:
                os.remove(self.hash_file)
            except OSError:
                pass
        return matching
