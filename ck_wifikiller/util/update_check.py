#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自动更新检测 —— 启动时检查 GitHub 最新 Release

设计原则（最小变动 + 闭环 + 合规）:
  - 仅检测、不自动安装；提示用户手动升级命令
  - 非阻塞：网络异常/超时静默跳过，不影响主流程
  - 短超时（3s），离线环境无感知
  - 可通过 --no-update 关闭

版本比较: 解析 tag 的数字部分（v2.4.0 → (2,4,0)）做元组比较，
兼容 git describe 的 v2.4.0-5-gabcdef 形式（取前缀）。
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Optional, Tuple

# Release API（公开仓库无需 token）
RELEASES_API = 'https://api.github.com/repos/cknb6/ck-wifikiller/releases/latest'
GITHUB_REPO = 'https://github.com/cknb6/ck-wifikiller'


def _parse_version(ver: str) -> Tuple[int, ...]:
    '''解析版本字符串为可比较的数字元组。v2.4.0-5-gabc → (2,4,0)。'''
    if not ver:
        return (0,)
    # 去掉前缀 v，取第一段（git describe 的 -N-gHASH 之前）
    s = ver.lstrip('vV').split('-')[0]
    nums = re.findall(r'\d+', s)
    return tuple(int(n) for n in nums) if nums else (0,)


def _strip_v(tag: str) -> str:
    '''去掉 tag 前缀 v/V，用于展示。'''
    return tag[1:] if tag and tag[0] in ('v', 'V') else tag


def _fetch_latest_release(timeout: float = 3.0) -> Optional[dict]:
    '''请求 GitHub Releases API，返回最新 release dict 或 None。'''
    try:
        req = urllib.request.Request(
            RELEASES_API,
            headers={
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'ck-wifikiller-update-check',
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode('utf-8', errors='replace')
        return json.loads(data)
    except Exception:
        return None


def check_for_update(current_version: str, timeout: float = 3.0) -> Optional[dict]:
    '''检查是否有新版本。

    返回:
      None       — 无新版 / 检查失败（应静默跳过）
      {'latest': 'v2.5.0', 'current': 'v2.4.0', 'url': '...'}  — 有新版
    '''
    rel = _fetch_latest_release(timeout=timeout)
    if not rel or not isinstance(rel, dict):
        return None
    latest_tag = (rel.get('tag_name') or '').strip()
    if not latest_tag:
        return None
    if _parse_version(latest_tag) <= _parse_version(current_version):
        return None
    html_url = rel.get('html_url') or (GITHUB_REPO + '/releases/tag/' + latest_tag)
    return {
        'latest': latest_tag,
        'current': current_version,
        'url': html_url,
    }


def print_update_hint(info: dict) -> None:
    '''打印升级提示（不自动安装）。'''
    try:
        from .color import Color
    except Exception:
        return
    latest = _strip_v(info['latest'])
    current = _strip_v(info['current'])
    Color.pl('{+} {O}发现新版本 / Update available{W}: {C}%s{W} → {G}%s{W}'
             % (current, latest))
    Color.pl('{+} {D}升级 / Upgrade{W}:')
    Color.pl('{+}   {C}git pull{W}  或/or  {C}sudo apt install ./ck-wifikiller_*.deb{W}')
    Color.pl('{+}   {D}%s{W}' % info.get('url', GITHUB_REPO))


def run_update_check(current_version: str, enabled: bool = True) -> None:
    '''启动时调用：enabled 为 False 时跳过。'''
    if not enabled:
        return
    info = check_for_update(current_version)
    if info:
        print_update_hint(info)


if __name__ == '__main__':
    # 自检：与本地版本比较
    from ._version import get_version
    run_update_check(get_version())
