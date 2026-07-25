#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 ck-default-wpa.txt：WPA 合法长度 8–63，国内弱口令优先、体积可控。

用法:
  python3 scripts/build-wordlist.py
  python3 scripts/build-wordlist.py --target 500000
"""

from __future__ import annotations

import argparse
import itertools
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "wordlists" / "ck-default-wpa.txt"
SEED = ROOT / "wordlists" / "wpa-top4800.txt"
EXISTING = ROOT / "wordlists" / "ck-default-wpa.txt"

WPA_MIN, WPA_MAX = 8, 63

# 国内常见拼音 / 英文弱口令词根（不含针对特定设备的默认凭据）
CN_ROOTS = [
    "woaini", "woai", "aini", "aixin", "mima", "mimima", "admin", "root",
    "password", "passwd", "pass", "wifi", "wlan", "router", "gateway",
    "user", "guest", "test", "qwerty", "asdfgh", "zxcvbn", "iloveyou",
    "loveyou", "forever", "hello", "welcome", "letmein", "dragon",
    "monkey", "shadow", "master", "sunshine", "princess", "football",
    "baseball", "superman", "batman", "abcabc", "qazwsx", "1qaz2wsx",
    "qq123456", "wx123456", "zfb123", "taobao", "jingdong", "meituan",
    "douyin", "weixin", "wechat", "china", "beijing", "shanghai",
    "guangzhou", "shenzhen", "hangzhou", "chengdu", "wuhan", "nanjing",
    "tianjin", "chongqing", "suzhou", "xian", "qingdao", "dalian",
    "xiaomi", "huawei", "oppo", "vivo", "honor", "meizu", "lenovo",
    "chuizi", "redmi", "apple", "iphone", "android", "samsung",
    "telecom", "unicom", "mobile", "cmcc", "chinanet", "netcore",
    "tplink", "tenda", "mercury", "fast", "h3c", "ruijie",
    "jiating", "gongsi", "bangong", "bangongshi", "kehu", "guanli",
    "wangluo", "wuxian", "kuandai", "guangxian", "modem", "ont",
    "a123456", "aa123456", "aaa123", "abc123", "abcd1234", "abc12345",
    "qwe123", "qwe12345", "asd123", "zxc123", "123qwe", "123abc",
    "5201314", "5211314", "1314520", "520520", "521521", "1314521",
    "7758521", "7758258", "147258", "159357", "456852", "789456",
    "666666", "888888", "999999", "000000", "111111", "123123",
    "112233", "121212", "147258369", "159357456", "password1",
    "admin888", "admin666", "admin123", "root1234", "user1234",
    "wifi1234", "wifi8888", "wlan1234", "pass1234", "passw0rd",
    "p@ssw0rd", "P@ssw0rd", "Admin123", "Welcome1", "Changeme1",
]

# 数字尾缀（拼接到词根后）
NUM_SUFFIXES = [
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "000", "0000", "00000", "000000", "00000000",
    "111", "1111", "11111", "111111", "11111111",
    "666", "6666", "66666", "666666", "66666666",
    "888", "8888", "88888", "888888", "88888888",
    "999", "9999", "99999", "999999", "99999999",
    "520", "521", "1314", "5201314", "5211314",
    "66", "88", "99", "00", "01", "12", "21", "68", "86",
    "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015",
    "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023",
    "2024", "2025", "2026",
    "qwe", "asd", "zxc", "qaz", "wsx", "abc", "xyz",
]

# 纯数字高优先级模板（有界，不生成全空间）
DIGITS_PRIORITY = [
    "12345678", "123456789", "1234567890", "01234567", "0123456789",
    "87654321", "98765432", "987654321", "9876543210",
    "11111111", "22222222", "33333333", "44444444", "55555555",
    "66666666", "77777777", "88888888", "99999999", "00000000",
    "11223344", "11112222", "12341234", "12121212", "13131313",
    "14725836", "15935745", "45678901", "1122334455", "123123123",
    "111111111", "000000000", "888888888", "666666666",
    "12345678901", "12345678910", "1111111111", "0000000000",
    "112233445566", "123456789012",
]

# 手机号常见号段前 3 位（仅用于生成有界弱口令样本，非全量枚举）
PHONE_PREFIXES = [
    "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
    "145", "147", "149",
    "150", "151", "152", "153", "155", "156", "157", "158", "159",
    "166",
    "170", "171", "172", "173", "175", "176", "177", "178",
    "180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
    "190", "191", "193", "195", "196", "197", "198", "199",
]


def wpa_ok(pw: str) -> bool:
    if not pw or any(ch.isspace() for ch in pw):
        return False
    n = len(pw)
    return WPA_MIN <= n <= WPA_MAX


def load_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            w = line.strip()
            if w:
                out.append(w)
    return out


def _push(out: list[str], local: set[str], pw: str) -> None:
    """仅写入生成器本地列表；最终去重由 absorb 统一处理。"""
    if not wpa_ok(pw) or pw in local:
        return
    local.add(pw)
    out.append(pw)


def gen_cn_priority() -> list[str]:
    """国内场景高优先级弱口令（有界）。"""
    out: list[str] = []
    local: set[str] = set()

    for d in DIGITS_PRIORITY:
        _push(out, local, d)

    # 8 位重复/递增模式
    for ch in "0123456789":
        _push(out, local, ch * 8)
        _push(out, local, ch * 9)
        _push(out, local, ch * 10)
        _push(out, local, ch * 11)
        _push(out, local, ch * 12)

    for start in range(0, 10):
        seq = "".join(str((start + i) % 10) for i in range(8))
        _push(out, local, seq)
        _push(out, local, seq + str((start + 8) % 10))
        _push(out, local, seq + str((start + 8) % 10) + str((start + 9) % 10))

    # 词根 + 数字 / 数字 + 词根
    for root in CN_ROOTS:
        _push(out, local, root if wpa_ok(root) else root + "123")
        for suf in NUM_SUFFIXES:
            _push(out, local, root + suf)
            _push(out, local, suf + root)
            _push(out, local, root.capitalize() + suf)
            if len(root) <= 10:
                _push(out, local, root.upper() + suf)

    # 年份 + 词根 / 词根 + 年份
    years = [str(y) for y in range(1980, 2027)]
    short_roots = [
        "wifi", "admin", "pass", "mima", "user", "root", "abc", "qwe",
        "asd", "love", "aini", "qq", "wx", "cmcc", "zte", "huawei",
    ]
    for y, r in itertools.product(years, short_roots):
        _push(out, local, r + y)
        _push(out, local, y + r)
        _push(out, local, r + y[-2:])
        _push(out, local, y[-2:] + r + "123")

    # 生日样式：YYYYMMDD / YYMMDD 有界采样
    for y in range(1970, 2015):
        for m in ("01", "05", "06", "07", "08", "09", "10", "12"):
            for d in ("01", "08", "15", "16", "18", "20", "22", "28"):
                _push(out, local, f"{y}{m}{d}")
                _push(out, local, f"{y % 100:02d}{m}{d}")
                _push(out, local, f"{y}{m}{d}a")
                _push(out, local, f"a{y}{m}{d}")

    # 11 位手机号弱样本：号段 + 重复/顺序尾号（有界）
    tails = [
        "00000000", "11111111", "22222222", "66666666", "88888888",
        "12345678", "87654321", "00001111", "11223344", "12341234",
        "52013140", "52113140", "14725836", "15935745", "00001234",
        "12345670", "10000000", "20000000", "66668888", "88886666",
    ]
    for pfx, tail in itertools.product(PHONE_PREFIXES, tails):
        _push(out, local, pfx + tail)

    # 键盘行
    rows = [
        "qwertyui", "qwertyuiop", "asdfghjk", "asdfghjkl",
        "zxcvbnm", "1qaz2wsx", "qazwsxedc", "qweasdzxc",
        "1q2w3e4r", "1q2w3e4r5t",
    ]
    for r in rows:
        _push(out, local, r)
        for suf in ("123", "1234", "123456", "888", "666", "2024", "2025", "2026"):
            _push(out, local, r + suf)

    # 中文场景常见混合
    extras = [
        "woaini1314", "woaini520", "woaini521", "iloveyou1314",
        "qq12345678", "wx12345678", "zfb123456", "taobao123",
        "meituan12", "douyin123", "xiaomi123", "huawei123",
        "oppo1234", "vivo1234", "redmi1234", "honor1234",
        "cmcc1234", "chinanet1", "unicom12", "telecom12",
        "wifi8888", "wifi6666", "wifi0000", "wifi1111",
        "admin@123", "Admin@123", "root@1234", "P@ssw0rd",
        "Passw0rd", "Welcome1", "Welcome123", "Changeme1",
        "1qaz@WSX", "Qwer1234", "Abcd1234", "Aa123456",
        "Aa12345678", "Qq123456", "Zz123456", "Xx123456",
        "a1234567", "a12345678", "ab123456", "abc12345",
        "abcd1234", "abcde123", "qwe12345", "qwer1234",
        "asdf1234", "zxcv1234", "wasd1234",
        "5201314a", "a5201314", "1314520a", "a1314520",
        "77585210", "77582580", "52152152", "52052052",
    ]
    for e in extras:
        _push(out, local, e)

    return out


def gen_digit_expansions(budget: int) -> list[str]:
    """补充常见数字扩展，受 budget 限制。"""
    out: list[str] = []
    local: set[str] = set()
    if budget <= 0:
        return out

    # 8 位：AABBCCDD / ABABABAB / ABCDABCD 等
    for a, b, c, d in itertools.product(range(10), repeat=4):
        if len(out) >= budget:
            break
        _push(out, local, f"{a}{a}{b}{b}{c}{c}{d}{d}")
        _push(out, local, f"{a}{b}{a}{b}{a}{b}{a}{b}")
        _push(out, local, f"{a}{b}{c}{d}{a}{b}{c}{d}")
        _push(out, local, f"{a}{b}{c}{d}{d}{c}{b}{a}")
        _push(out, local, f"{a}{a}{a}{a}{b}{b}{b}{b}")

    # 8 位：前 4 位年份风格 + 后 4 位
    for y in range(1970, 2027):
        for n in range(0, 10000, 7):
            if len(out) >= budget:
                break
            _push(out, local, f"{y}{n:04d}")
        if len(out) >= budget:
            break

    # 9–12 位：重复块
    for block in ("12", "13", "15", "18", "52", "66", "88", "00", "11", "123", "520", "1314"):
        for k in range(3, 7):
            s = (block * k)[:12]
            if len(s) >= 8:
                _push(out, local, s)

    # 8–11 位：前缀 + 模式
    prefixes = ["12", "88", "66", "00", "11", "52", "13", "15", "18", "19", "13", "15", "18"]
    middles = [
        "0000", "1111", "2222", "3333", "6666", "8888", "9999",
        "1234", "4321", "5201", "1314", "0001", "1000", "2000",
    ]
    ends = ["00", "11", "66", "88", "99", "12", "21", "52", "13", "14", "20", "28"]
    for p, m, e in itertools.product(prefixes, middles, ends):
        if len(out) >= budget:
            break
        _push(out, local, p + m + e)
        _push(out, local, p + m + e + "0")
        _push(out, local, "0" + p + m + e)
        _push(out, local, p + m + e + "8")
        _push(out, local, p + "0" + m + e)

    # 11 位手机号扩展：号段 + 4 位模式 + 4 位模式
    for pfx in PHONE_PREFIXES:
        for a in ("0000", "1111", "2222", "6666", "8888", "1234", "4321", "5201", "1314", "0001"):
            for b in ("0000", "1111", "6666", "8888", "1234", "4321", "0000", "9999"):
                if len(out) >= budget:
                    break
                _push(out, local, pfx + a + b)
            if len(out) >= budget:
                break
        if len(out) >= budget:
            break

    return out


def build(target: int) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    def absorb(items: list[str]) -> None:
        for w in items:
            if len(ordered) >= target:
                return
            if wpa_ok(w) and w not in seen:
                seen.add(w)
                ordered.append(w)

    # 1) 国内优先（必须排在最前）
    absorb(gen_cn_priority())
    # 2) 已有词典
    absorb(load_lines(EXISTING))
    # 3) top4800
    absorb(load_lines(SEED))
    # 4) 数字扩展填到目标规模
    remain = max(0, target - len(ordered))
    absorb(gen_digit_expansions(remain + 80000))

    return ordered[:target]


def main() -> None:
    ap = argparse.ArgumentParser(description="Build WPA 8+ wordlist")
    ap.add_argument("--target", type=int, default=520000, help="max entries")
    ap.add_argument("--output", type=Path, default=OUT)
    args = ap.parse_args()

    words = build(args.target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        for w in words:
            fh.write(w + "\n")
    os.replace(tmp, args.output)

    # 统计
    lens = {}
    for w in words:
        lens[len(w)] = lens.get(len(w), 0) + 1
    print(f"wrote {len(words)} passwords -> {args.output}")
    print(f"min_len={min(map(len, words))} max_len={max(map(len, words))}")
    print("length_top", sorted(lens.items())[:12])


if __name__ == "__main__":
    main()
