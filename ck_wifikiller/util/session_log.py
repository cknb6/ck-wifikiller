#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali 运行会话日志 —— 自动落盘，方便升级改进

默认目录（优先）:
  ~/.ck-wifikiller/logs/session-YYYYMMDD-HHMMSS/
  ./ck-logs/session-...  (无 home 写权限时)

记录:
  - meta.json     环境/版本/参数/依赖探测
  - session.log   关键事件时间线
  - feedback.md   改进反馈模板（可手填）
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime


class SessionLog:
    _instance = None

    def __init__(self):
        self.started_at = time.time()
        self.events = []
        self.dir = self._make_dir()
        self.log_path = os.path.join(self.dir, 'session.log')
        self.meta_path = os.path.join(self.dir, 'meta.json')
        self.feedback_path = os.path.join(self.dir, 'feedback.md')
        self._write_meta_initial()
        self.event('session_start', {'argv': sys.argv[:], 'cwd': os.getcwd()})

    @classmethod
    def get(cls) -> 'SessionLog':
        if cls._instance is None:
            cls._instance = SessionLog()
        return cls._instance

    @classmethod
    def enabled(cls) -> bool:
        # CK_WIFI_NO_LOG=1 可关闭
        return os.environ.get('CK_WIFI_NO_LOG', '').strip() not in ('1', 'true', 'yes')

    def _make_dir(self) -> str:
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        name = f'session-{stamp}'
        candidates = []
        home = os.path.expanduser('~')
        if home and home != '~':
            candidates.append(os.path.join(home, '.ck-wifikiller', 'logs', name))
        candidates.append(os.path.join(os.getcwd(), 'ck-logs', name))
        candidates.append(os.path.join('/tmp', 'ck-wifikiller-logs', name))
        for path in candidates:
            try:
                os.makedirs(path, exist_ok=True)
                probe = os.path.join(path, '.write_test')
                with open(probe, 'w') as f:
                    f.write('ok')
                os.remove(probe)
                return path
            except OSError:
                continue
        return candidates[-1]

    def _write_meta_initial(self) -> None:
        from ..config import Configuration
        meta = {
            'product': 'ck-wifikiller',
            'version': getattr(Configuration, 'version', 'unknown'),
            'github': 'https://github.com/cknb6/ck-wifikiller',
            'started_at': datetime.now().isoformat(timespec='seconds'),
            'platform': platform.platform(),
            'python': sys.version,
            'uname': list(platform.uname()),
            'uid': os.getuid() if hasattr(os, 'getuid') else None,
            'path_env_tools': {
                name: bool(shutil.which(name))
                for name in (
                    'aircrack-ng', 'airodump-ng', 'airmon-ng', 'aireplay-ng',
                    'hashcat', 'hcxdumptool', 'hcxpcapngtool', 'hcxpcaptool',
                    'tshark', 'kismet', 'bettercap', 'reaver', 'bully', 'iw',
                )
            },
            'argv': sys.argv[:],
            'purpose': 'Auto session log on Kali runs — use for upgrade/debug feedback',
        }
        try:
            with open(self.meta_path, 'w', encoding='utf-8') as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def _write_feedback_template(self) -> None:
        body = f'''# ck-wifikiller 运行反馈 / Run Feedback

会话目录 / Session: `{self.dir}`

## 环境
- Kali 版本 (cat /etc/os-release):
- 网卡芯片 / 驱动:
- 是否 monitor / injection 正常:

## 本次目标
- SSID / BSSID:
- 攻击类型 (PMKID / handshake / WPS / recon):

## 现象
- 期望:
- 实际:
- 报错原文 (粘贴 session.log 片段):

## 改进建议
-

## 联系
- GitHub Issues: https://github.com/cknb6/ck-wifikiller/issues
- 微信: 1837620622 （备注 wifi反馈）
'''
        try:
            with open(self.feedback_path, 'w', encoding='utf-8') as f:
                f.write(body)
        except OSError:
            pass

    def event(self, kind: str, data=None) -> None:
        rec = {
            'ts': datetime.now().isoformat(timespec='seconds'),
            'kind': kind,
            'data': data if data is not None else {},
        }
        self.events.append(rec)
        line = f"{rec['ts']}  [{kind}]  {json.dumps(data or {}, ensure_ascii=False)}\n"
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(line)
        except OSError:
            pass

    def finalize(self, code: int = 0) -> str:
        elapsed = round(time.time() - self.started_at, 2)
        self.event('session_end', {'exit_code': code, 'elapsed_sec': elapsed})
        # 更新 meta
        try:
            with open(self.meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
        except Exception:
            meta = {}
        meta['ended_at'] = datetime.now().isoformat(timespec='seconds')
        meta['exit_code'] = code
        meta['elapsed_sec'] = elapsed
        meta['event_count'] = len(self.events)
        try:
            with open(self.meta_path, 'w', encoding='utf-8') as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
            with open(os.path.join(self.dir, 'events.json'), 'w', encoding='utf-8') as f:
                json.dump(self.events, f, indent=2, ensure_ascii=False)
        except OSError:
            pass
        return self.dir
