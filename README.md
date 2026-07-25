# ck-wifikiller

**Modern Kali wireless auditor** — maintained fork of [wifite2](https://github.com/derv82/wifite2) (last upstream ~2018).
**现代化 Kali 无线审计工具** — [wifite2](https://github.com/derv82/wifite2) 的维护分支（上游止于 ~2018）。

> **Authorized security testing only. / 仅限授权安全测试。**
> Unauthorized attacks may be illegal. / 未授权攻击网络可能违法。

```
Version: dynamic (git describe / CK_WIFI_VERSION env)   版本: 动态读取
GitHub:  https://github.com/cknb6/ck-wifikiller
Author:  传康Kk（万能程序员）
WeChat:  1837620622  （赞助备注「wifi赞助」/ 商务备注「商务合作」）
Email:   2040168455@qq.com
```

---

## Why this fork? / 为何 fork？

| 2018 wifite2 | ck-wifikiller (2026 Kali) |
|--------------|---------------------------|
| `hcxpcaptool` | **`hcxpcapngtool`** |
| hashcat `-m 2500` / `16800` | **`-m 22000`** (PMKID+EAPOL) |
| hcxdumptool `--filterlist` | **BPF `--bpf=`** (+ legacy fallback) |
| small top4800 wordlist | **ck-default-wpa** (~25万高优先级) |
| no recon layer | **`--recon`** → Kismet / bettercap matrix |
| single dictionary crack | **rules + mask + increment + CN optimize** |
| no vendor intel | **OUI 厂商识别 + 漏洞咨询** |
| no WPA3 awareness | **WPA3 Transition Mode 检测** |

---

## What's new in 2026 / 2026 新增前沿功能

- **PMKID hashcat 增强**: `--rules` / `--mask` / `--increment` / `--hc-args` 透传，两阶段字典+掩码爆破。
- **国内 WiFi 智能优化 `--cn`**: 字典失败后自动按国内密码规律跑掩码管线（8 位纯数字、11 位手机号、生日、运营商光猫规律），基于公开统计调研。
- **路由器厂商识别 + 漏洞咨询**: OUI 前缀识别厂商，打印默认凭据/CVE/推荐攻击路径，辅助自动化排序。
- **WPA3 Transition Mode 检测**: 识别 SAE+PSK 降级可行性（Dragonblood），纯 SAE 提示在线爆破。
- **动态版本**: 从 `CK_WIFI_VERSION` 环境变量或 `git describe` 读取，不硬编码。
- **自动会话日志**: Kali 运行自动记录环境、事件、feedback 模板。
- **GitHub Actions 自动发布**: 打 tag 触发 CI 构建 `.deb` 并发布 Release，本地不构建。

---

## Install (Kali) / 安装

```bash
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark

# from Release .deb / 从 Release 安装
sudo apt install ./ck-wifikiller_*.deb

# or from source / 或从源码
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller && sudo pip3 install -e .
```

---

## Usage / 用法

```bash
sudo ck-wifikiller                          # 全自动扫描+攻击
sudo ck-wifikiller --recon status           # L1 工具矩阵
sudo ck-wifikiller --recon kismet           # Kismet 引导 + REST 探测
sudo ck-wifikiller --recon bettercap        # 生成 bettercap caplet
sudo ck-wifikiller --pmkid                  # 优先 PMKID 路径
sudo ck-wifikiller --dict /path/wl.txt      # 指定字典
sudo ck-wifikiller --cn                     # 国内 WiFi 智能优化（掩码管线）
sudo ck-wifikiller --rules /usr/share/hashcat/rules/best64.rule
sudo ck-wifikiller --mask '?d?d?d?d?d?d?d?d'   # 8 位纯数字掩码
sudo ck-wifikiller --increment --increment-max 8
```

---

## Architecture (2026 toolchain) / 架构

See [docs/TOOLCHAIN-2026.md](docs/TOOLCHAIN-2026.md).

1. **Recon (L1):** Kismet (Wi‑Fi/BT/Zigbee WIDS), bettercap, airodump-ng
2. **Capture (L2):** hcxdumptool / airodump + aireplay
3. **Crack (L3):** hashcat `-m 22000` + built-in wordlist + CN mask pipeline

---

## Release / 发布

Tag-triggered CI build (`.github/workflows/build-deb.yml`):

```bash
git tag v2.4.0 && git push origin v2.4.0
# → GitHub Actions 在 Debian 容器构建 .deb 并自动发布 Release
```

---

## Credits / 致谢

- Original [wifite2](https://github.com/derv82/wifite2) by derv82 & contributors (GPL-2.0)
- [hcxdumptool](https://github.com/ZerBea/hcxdumptool) / [hcxtools](https://github.com/ZerBea/hcxtools) by ZerBea
- [hashcat](https://hashcat.net/), [Kismet](https://www.kismetwireless.net/), [bettercap](https://www.bettercap.org/)

## License

GNU GPL v2 — same as wifite2. See `LICENSE` and `debian/copyright`.
