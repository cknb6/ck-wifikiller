#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""同一 AP 多份捕获：只保留/选用有效哈希；相同取其一，不同取最新。

策略（用户约定）:
  1. 无效哈希一律不用于爆破
  2. 多份内容相同 → 任取一份（优先较新文件名/mtime）
  3. 多份内容不同且均有效 → 取最新
  4. 仅部分有效 → 在有效集合里再按 2/3
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Iterable

# handshake_ESSID_AA-BB-CC-DD-EE-FF_2026-07-26T12-00-00.cap
_HS_NAME = re.compile(
    r'^handshake_(?P<essid>[^_]+)_(?P<bssid>[0-9A-Fa-f-]{17})_(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})\.cap$',
)
# pmkid_ESSID_AA-BB-..._date.hc22000
_PMKID_NAME = re.compile(
    r'^pmkid_(?P<essid>.+)_(?P<bssid>[0-9A-Fa-f-]{17})_(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})\.(?:16800|22000|hc22000)$',
    re.I,
)

_MAC12 = re.compile(r'^[0-9a-f]{12}$')
_HEX = re.compile(r'^[0-9a-fA-F]+$')


def _norm_bssid(bssid: str | None) -> str:
    return (bssid or '').lower().replace(':', '').replace('-', '').strip()


def file_fingerprint(path: str) -> str:
    '''内容指纹：相同抓包/哈希 → 相同 digest。'''
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(1024 * 64)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return ''
    return h.hexdigest()


def line_fingerprint(text: str) -> str:
    return hashlib.sha256(text.strip().encode('utf-8', errors='replace')).hexdigest()


def is_valid_hc22000_line(line: str, want_bssid: str | None = None) -> bool:
    '''校验 hashcat -m 22000 文本行（PMKID WPA*01* 或 EAPOL WPA*02*）。'''
    line = (line or '').strip()
    if not line or line.startswith('#'):
        return False
    parts = line.split('*')
    if len(parts) < 6:
        return False
    if parts[0].upper() != 'WPA':
        return False
    kind = parts[1]
    if kind not in ('01', '02'):
        return False
    # WPA*01*PMKID*MACAP*MACSTA*ESSID...
    # WPA*02*MIC*MACAP*MACSTA*ESSID*NONCE*EAPOL*MP
    pmk_or_mic = parts[2]
    mac_ap = parts[3].lower().replace(':', '')
    mac_sta = parts[4].lower().replace(':', '')
    if not _MAC12.match(mac_ap) or not _MAC12.match(mac_sta):
        return False
    if kind == '01':
        # PMKID 32 hex
        if len(pmk_or_mic) != 32 or not _HEX.match(pmk_or_mic):
            return False
    else:
        # MIC 至少 16 hex
        if len(pmk_or_mic) < 16 or not _HEX.match(pmk_or_mic):
            return False
    if want_bssid:
        if mac_ap != _norm_bssid(want_bssid):
            return False
    return True


def read_valid_hc22000_lines(path: str, want_bssid: str | None = None) -> list[str]:
    if not path or not os.path.isfile(path):
        return []
    out: list[str] = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                if is_valid_hc22000_line(line, want_bssid=want_bssid):
                    out.append(line.strip())
    except OSError:
        return []
    return out


def is_valid_pmkid_file(path: str, want_bssid: str | None = None) -> bool:
    return len(read_valid_hc22000_lines(path, want_bssid=want_bssid)) > 0


def is_valid_handshake_cap(path: str, bssid: str | None = None, essid: str | None = None) -> bool:
    '''cap 是否含可爆破握手：工具确认 或 能导出非空 hc22000。'''
    if not path or not os.path.isfile(path) or os.path.getsize(path) < 64:
        return False
    try:
        from ..model.handshake import Handshake
        hs = Handshake(path, bssid=bssid, essid=essid)
        if hs.has_handshake():
            return True
    except Exception:
        pass
    # 再试导出 22000（tshark 缺失时的兜底）
    try:
        from ..tools.hashcat import HcxPcapTool
        from ..util.process import Process
        if not (Process.exists('hcxpcapngtool') or Process.exists('hcxpcaptool')):
            return False
        tmp = HcxPcapTool.generate_hc22000_file(path)
        try:
            lines = read_valid_hc22000_lines(tmp, want_bssid=bssid)
            return len(lines) > 0
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
    except Exception:
        return False


@dataclass
class CaptureCandidate:
    path: str
    mtime: float
    fingerprint: str
    valid: bool
    kind: str  # handshake | pmkid


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def pick_best_candidate(cands: list[CaptureCandidate]) -> CaptureCandidate | None:
    '''有效优先；有效集合内：指纹去重后取最新；全无效返回 None。'''
    valid = [c for c in cands if c.valid and c.fingerprint]
    if not valid:
        return None
    # 按指纹分组，每组只留 mtime 最新
    best_by_fp: dict[str, CaptureCandidate] = {}
    for c in valid:
        prev = best_by_fp.get(c.fingerprint)
        if prev is None or c.mtime >= prev.mtime:
            best_by_fp[c.fingerprint] = c
    # 不同内容 → 取全局最新
    return max(best_by_fp.values(), key=lambda c: c.mtime)


def list_handshake_caps(hs_dir: str, bssid: str, essid: str | None = None) -> list[str]:
    if not hs_dir or not os.path.isdir(hs_dir):
        return []
    want = _norm_bssid(bssid)
    if not want:
        return []
    essid_safe = re.sub(r'[^a-zA-Z0-9]', '', essid) if essid else None
    out: list[str] = []
    for name in os.listdir(hs_dir):
        if not name.startswith('handshake_') or not name.endswith('.cap'):
            continue
        path = os.path.join(hs_dir, name)
        if not os.path.isfile(path):
            continue
        m = _HS_NAME.match(name)
        if m:
            file_bssid = _norm_bssid(m.group('bssid'))
            if file_bssid != want:
                continue
            if essid_safe and m.group('essid') != essid_safe:
                # ESSID 安全名不一致时仍按 BSSID 认（改名 AP）
                pass
        else:
            # 宽松：文件名含 BSSID
            if want not in name.lower().replace(':', '').replace('-', ''):
                # 再读 cap 太贵，跳过
                if bssid.replace(':', '-').lower() not in name.lower():
                    continue
        out.append(path)
    return out


def select_handshake_cap(hs_dir: str, bssid: str, essid: str | None = None) -> str | None:
    '''从 hs/ 为指定 BSSID 选最佳有效握手 .cap。'''
    paths = list_handshake_caps(hs_dir, bssid, essid)
    cands: list[CaptureCandidate] = []
    for path in paths:
        valid = is_valid_handshake_cap(path, bssid=bssid, essid=essid)
        cands.append(CaptureCandidate(
            path=path,
            mtime=_mtime(path),
            fingerprint=file_fingerprint(path) if valid else '',
            valid=valid,
            kind='handshake',
        ))
    best = pick_best_candidate(cands)
    return best.path if best else None


def list_pmkid_files(hs_dir: str, bssid: str) -> list[str]:
    if not hs_dir or not os.path.isdir(hs_dir):
        return []
    want = _norm_bssid(bssid)
    if not want:
        return []
    file_re = re.compile(r'.*pmkid_.*\.(16800|22000|hc22000)$', re.I)
    out: list[str] = []
    for name in os.listdir(hs_dir):
        if not file_re.match(name):
            continue
        path = os.path.join(hs_dir, name)
        if not os.path.isfile(path):
            continue
        # 快速：文件名 BSSID 或内容含该 AP
        m = _PMKID_NAME.match(name)
        if m:
            if _norm_bssid(m.group('bssid')) != want:
                continue
        else:
            # 宽松回退：文件名必须含该 BSSID（无分隔符形式），
            # 否则 bg_pmkid_<其它BSSID>.hc22000 会被误列给所有目标
            name_norm = name.lower().replace(':', '').replace('-', '')
            if want not in name_norm:
                continue
        out.append(path)
    return out


def select_pmkid_file(hs_dir: str, bssid: str) -> str | None:
    '''选最佳有效 PMKID/hc22000；内容按有效行指纹去重。'''
    paths = list_pmkid_files(hs_dir, bssid)
    cands: list[CaptureCandidate] = []
    for path in paths:
        lines = read_valid_hc22000_lines(path, want_bssid=bssid)
        if not lines:
            cands.append(CaptureCandidate(
                path=path, mtime=_mtime(path), fingerprint='', valid=False, kind='pmkid'))
            continue
        # 多行时用排序后拼接指纹（文件内顺序无关）
        fp = line_fingerprint('\n'.join(sorted(set(lines))))
        cands.append(CaptureCandidate(
            path=path,
            mtime=_mtime(path),
            fingerprint=fp,
            valid=True,
            kind='pmkid',
        ))
    best = pick_best_candidate(cands)
    return best.path if best else None


def dedupe_save_needed(new_path_or_content_fp: str, existing_paths: Iterable[str],
                       is_file: bool = True) -> bool:
    '''新捕获是否需要落盘：与任一已有有效文件指纹相同则 False。'''
    if is_file:
        new_fp = file_fingerprint(new_path_or_content_fp)
    else:
        new_fp = line_fingerprint(new_path_or_content_fp)
    if not new_fp:
        return True
    for p in existing_paths:
        if file_fingerprint(p) == new_fp:
            return False
    return True


def ensure_valid_for_crack_cap(path: str, bssid: str | None = None,
                              essid: str | None = None) -> bool:
    return is_valid_handshake_cap(path, bssid=bssid, essid=essid)


def ensure_valid_for_crack_pmkid(path: str, bssid: str | None = None) -> bool:
    return is_valid_pmkid_file(path, want_bssid=bssid)
