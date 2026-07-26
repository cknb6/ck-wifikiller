#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hcxpsktool / hcxeiutool — 从 hc22000 与 ESSID 生成弱口令候选。

ZerBea 官方链路可选增强:
  hcxdumptool → hcxpcapngtool → hcxpsktool → hashcat -m 22000

Kali: apt install hcxtools
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Optional

from ..config import Configuration
from ..util.color import Color
from ..util.process import Process


class HcxPskTool(object):
    dependency_name = 'hcxpsktool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'
    dependency_required = False

    @classmethod
    def exists(cls) -> bool:
        return Process.exists('hcxpsktool')

    @classmethod
    def fails_dependency_check(cls) -> bool:
        return False  # 可选

    @classmethod
    def generate_candidates_file(
        cls,
        hash_file: str,
        essid: Optional[str] = None,
        limit: int = 50000,
    ) -> Optional[str]:
        '''生成候选字典文件路径；失败返回 None。'''
        if not cls.exists() or not hash_file or not os.path.isfile(hash_file):
            return None

        cmd = ['hcxpsktool', '-i', hash_file]
        # 部分版本支持 -e ESSID
        help_blob = ''
        try:
            help_blob = (Process(['hcxpsktool', '-h']).stdout() or '') + (
                Process(['hcxpsktool', '-h']).stderr() or '')
        except Exception:
            pass
        if essid and ('-e ' in help_blob or '--essid' in help_blob):
            cmd.extend(['-e', essid])

        try:
            proc = Process(cmd)
            out = proc.stdout() or ''
        except Exception:
            return None

        lines: list[str] = []
        seen = set()
        for raw in out.splitlines():
            w = raw.strip()
            if not w or w.startswith('#'):
                continue
            # 口令长度 WPA 8–63
            if len(w) < 8 or len(w) > 63:
                continue
            if w in seen:
                continue
            seen.add(w)
            lines.append(w)
            if len(lines) >= limit:
                break

        # 再补 ESSID 简单变体（无 hcxeiutool 时的兜底）
        if essid:
            for v in cls._essid_variants(essid):
                if v not in seen and 8 <= len(v) <= 63:
                    seen.add(v)
                    lines.append(v)

        if not lines:
            return None

        fd, path = tempfile.mkstemp(prefix='ck-psk-', suffix='.txt')
        os.close(fd)
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('\n'.join(lines) + '\n')
        except OSError:
            try:
                os.remove(path)
            except OSError:
                pass
            return None
        return path

    @staticmethod
    def _essid_variants(essid: str) -> list[str]:
        e = (essid or '').strip()
        if not e:
            return []
        out = [e, e.lower(), e.upper()]
        # 常见后缀
        for suf in ('123', '1234', '12345678', 'admin', 'password', 'wifi', '2024', '2025', '2026'):
            out.append(e + suf)
            out.append(e.lower() + suf)
        # 去特殊字符
        alnum = re.sub(r'[^a-zA-Z0-9]', '', e)
        if alnum and alnum != e:
            out.append(alnum)
            out.append(alnum + '12345678')
        return out

    @classmethod
    def try_crack_quick(cls, hash_file: str, essid: Optional[str] = None) -> Optional[str]:
        '''用 hcxpsktool 候选做一轮快打；命中返回 key。'''
        from .hashcat import Hashcat

        cand = cls.generate_candidates_file(hash_file, essid=essid)
        if not cand:
            return None
        try:
            Color.pl('{+} {C}hcxpsktool{W} candidates → hashcat -m 22000 ...')
            return Hashcat._run_hc22000_phase(
                hash_file, ['-a', '0', hash_file, cand],
                is_mask=False, verbose=False, use_runtime=False)
        finally:
            try:
                os.remove(cand)
            except OSError:
                pass
