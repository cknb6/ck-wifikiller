#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""启动界面：品牌 / GitHub / 赞助 / 商务合作"""

from .color import Color

# 公开联系信息（与用户长期规范一致）
GITHUB_REPO = 'https://github.com/cknb6/ck-wifikiller'
GITHUB_AUTHOR = 'https://github.com/1837620622'
WECHAT = '1837620622'
EMAIL_CONTACT = '2040168455@qq.com'  # 商务/非 GitHub 联系
EMAIL_GITHUB = '1837620622@qq.com'   # GitHub 贡献关联
HANDLE = '传康Kk / 万能程序员'


def show_splash(version: str) -> None:
    Color.pl('')
    Color.pl('{G}╔══════════════════════════════════════════════════════════════╗{W}')
    Color.pl('{G}║{W}          {C}ck-wifikiller{W}  ·  Wireless Auditor 2026           {G}║{W}')
    Color.pl('{G}║{W}     fork of wifite2 · Kali · PMKID · hashcat -m 22000       {G}║{W}')
    Color.pl('{G}╠══════════════════════════════════════════════════════════════╣{W}')
    Color.pl('{G}║{W}  Version   {D}%s{W}' % version.ljust(47) + '{G}║{W}')
    Color.pl('{G}║{W}  Author    {C}%s{W}' % HANDLE.ljust(47) + '{G}║{W}')
    Color.pl('{G}║{W}  GitHub    {C}%s{W}' % GITHUB_REPO[:47].ljust(47) + '{G}║{W}')
    Color.pl('{G}║{W}  Profile   {C}%s{W}' % GITHUB_AUTHOR[:47].ljust(47) + '{G}║{W}')
    Color.pl('{G}╠══════════════════════════════════════════════════════════════╣{W}')
    Color.pl('{G}║{W}  {O}赞助 / Sponsor{W}                                           {G}║{W}')
    Color.pl('{G}║{W}  微信 WeChat: {C}%s{W}  备注: wifi赞助' % WECHAT.ljust(28) + '{G}║{W}')
    Color.pl('{G}║{W}  邮箱 Email:  {C}%s{W}' % EMAIL_CONTACT.ljust(36) + '{G}║{W}')
    Color.pl('{G}║{W}  {O}商业合作 / Business{W}: 同上微信备注「商务合作」            {G}║{W}')
    Color.pl('{G}╠══════════════════════════════════════════════════════════════╣{W}')
    Color.pl('{G}║{W}  {R}仅限授权测试{W} · Authorized security testing only           {G}║{W}')
    Color.pl('{G}║{W}  未授权攻击网络可能违法 · 使用者自行承担法律责任             {G}║{W}')
    Color.pl('{G}╚══════════════════════════════════════════════════════════════╝{W}')
    Color.pl('')
