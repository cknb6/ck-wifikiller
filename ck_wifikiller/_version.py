#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""版本号动态化 —— 不硬编码

读取优先级:
  1) 环境变量 CK_WIFI_VERSION          (CI 构建时注入 tag 名)
  2) git describe --tags --always      (源码运行)
  3) 内置基线 _BASE                    (兜底，如 deb 安装后无 .git)

GitHub Actions 在构建 .deb 时会 export CK_WIFI_VERSION=<tag>，
确保安装版与 release 版本一致。
"""

import os
import subprocess

# 兜底基线版本（无 git、无环境变量时使用）
_BASE = '2.5.8-ck'


def _git_describe() -> str:
    """尝试 git describe 获取版本；失败返回空串。"""
    try:
        # 用本文件所在目录向上找仓库根，避免依赖 cwd
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        out = subprocess.run(
            ['git', '-C', repo, 'describe', '--tags', '--always', '--dirty'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3,
        )
        if out.returncode == 0:
            ver = out.stdout.decode('utf-8', errors='replace').strip()
            if ver:
                return ver
    except Exception:
        pass
    return ''


def get_version() -> str:
    """返回当前版本字符串。"""
    env = os.environ.get('CK_WIFI_VERSION', '').strip()
    if env:
        return env
    git = _git_describe()
    if git:
        return git
    return _BASE


# 模块导入时即计算，供 Configuration.version 直接引用
version = get_version()


if __name__ == '__main__':
    print(version)
