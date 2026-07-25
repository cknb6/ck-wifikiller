<div align="center">

# ⚡ ck-wifikiller

### Modern Kali Wireless Auditor · 现代化 Kali 无线审计工具

**wifite2 的 2026 维护分支** · hashcat `-m 22000` · PMKID · Kismet recon · CN optimize

`Authorized security testing only · 仅限授权安全测试`

[![Kali](https://img.shields.io/badge/Kali-2026%20Rolling-1793D1?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![hashcat](https://img.shields.io/badge/hashcat--m%2022000-49A942?logo=hashicorp&logoColor=white)](https://hashcat.net/)
[![License](https://img.shields.io/badge/License-GPL--2.0-A42E2B)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v2.5.1-2.5.1-success)](https://github.com/cknb6/ck-wifikiller/releases)

</div>

---

## 📖 项目简介 / Overview

`ck-wifikiller` 是 [derv82/wifite2](https://github.com/derv82/wifite2)（上游止于 ~2018）的**现代化维护分支**，专为 **2024–2026 Kali Linux** 工具链重新适配与增强。它不是重写 Kismet/hashcat，而是做**工具链编排壳**——调用 Kali 上仍在维护的专业工具，并补齐上游缺失的：PMKID 无客户端攻击、hashcat 22000、BPF 过滤、Layer-1 侦察、国内 WiFi 智能优化、厂商指纹、WPA3 检测、自动更新。

> ⚠️ **合规声明**：仅限在**已获授权**的网络上进行安全评估。未授权拦截/攻击无线网络可能违法，使用者自行承担法律责任。
> Authorized wireless security assessment only. Unauthorized interception/attacks may be illegal.

```
┌─────────────────────────────────────────────────────────────┐
│  Version:  动态读取 (CK_WIFI_VERSION env / git describe)      │
│  GitHub:   https://github.com/cknb6/ck-wifikiller            │
│  Author:   传康Kk（万能程序员）                                │
│  WeChat:   1837620622  （赞助备注「wifi赞助」/ 商务「商务合作」） │
│  Email:    2040168455@qq.com                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 🆚 为何 fork？上游 vs 本分支 / Why this fork?

| 2018 wifite2 (上游) | ck-wifikiller (2026 Kali) | 说明 |
|:--------------------|:--------------------------|:-----|
| `hcxpcaptool` | **`hcxpcapngtool`** | 旧名已废弃，统一现代工具 |
| hashcat `-m 2500` / `16800` | **`-m 22000`** (PMKID+EAPOL) | hashcat 6.x 唯一推荐模式 |
| hcxdumptool `--filterlist` | **BPF `--bpf=`** (+ legacy fallback) | v6.3+ 软编码列表已移除 |
| — | **`--exitoneapol=7`** 高效捕获 | 收到 PMKID/EAPOL 自动退出（前沿） |
| small top4800 wordlist | **ck-default-wpa** (~25万高优先级) | 内置增强词典 |
| no recon layer | **`--recon`** → Kismet / bettercap matrix | Layer-1 侦察编排 |
| single dictionary crack | **rules + mask + increment + CN optimize** | 多阶段爆破 |
| no vendor intel | **OUI 厂商识别 + 攻击路径推荐** | 被动指纹辅助排序 |
| no WPA3 awareness | **WPA3 Transition Mode 检测** | Dragonblood 降级提示 |
| hardcoded version | **动态版本** (env / git describe) | 不硬编码 |
| no update check | **启动自动检测 GitHub Release** | 非阻塞，`--no-update` 可关 |

---

## ✨ 2026 前沿功能 / Features

### 🔓 破解增强 (Crack L3)
- **PMKID hashcat 增强**：`--rules` / `--mask` / `--increment` / `--hc-args` 透传，两阶段字典+掩码爆破
- **`--exitoneapol=7`**：hcxdumptool 收到 PMKID(1)+EAPOL M2(2)+M3(4) 任一即自动退出，避免冗余采集（hcxdumptool v6.0+ 官方推荐）
- **统一 `-m 22000`**：彻底移除 hashcat 6.x 已删除的 `-m 16800`，旧 `.16800` 文件自动提示用 hcxpcapngtool 重新生成

### 🇨🇳 国内 WiFi 智能优化 `--cn`
- 字典失败后自动按国内密码规律跑掩码管线（8 位纯数字、11 位手机号、生日、运营商光猫规律）
- **时区自动判断**：依据明确 IANA 时区（`Asia/Shanghai` 等）自动启用，不误判新加坡/马来西亚；`--cn`/`--no-cn`/`CK_WIFI_REGION` 可覆盖
- 有界测试模板，不生成针对特定设备的默认凭据

### 🏷️ 路由器厂商识别 + 攻击路径推荐
- OUI 前缀识别厂商（TP-Link/小米/华为/中兴/烽火/H3C/锐捷等），系统 ieee-data 优先 + 内置 fallback
- 打印**推荐攻击路径**（运营商网关优先 WPS Pixie-Dust，家用优先 PMKID）+ 防御核查清单
- 保守指纹：OUI/SSID 冲突时不强行推断，不声称漏洞状态

### 🛡️ WPA3 前沿检测
- **Transition Mode (SAE+PSK)**：识别降级可行性（Dragonblood），提示 hostapd-mana 伪 AP + deauth → WPA2 握手
- **纯 SAE**：提示离线爆破不可行，仅在线爆破（Wacker）

### 🔄 自动化与运维
- **自动更新检测**：启动时查 GitHub 最新 Release，有新版提示升级命令（非阻塞，3s 超时静默跳过）
- **动态版本**：`CK_WIFI_VERSION` 环境变量 > `git describe` > 内置基线
- **自动会话日志**：Kali 运行自动记录环境/事件/feedback 模板到 `~/.ck-wifikiller/logs/`
- **GitHub Actions 自动发布**：打 tag → CI 构建 `.deb` → Release → apt 仓库（GitHub Pages），`apt install` 直装

---

## 📥 安装 / Install (Kali)

### 方式 1：apt 仓库（推荐，自动更新） / apt repository

仓库由 GitHub Actions 自动构建并签名发布到 GitHub Pages：

```bash
# 添加 apt 仓库 / Add apt repo
echo "deb [trusted=yes] https://cknb6.github.io/ck-wifikiller stable main" \
  | sudo tee /etc/apt/sources.list.d/ck-wifikiller.list
sudo apt update
sudo apt install -y ck-wifikiller

# 升级 / Upgrade
sudo apt update && sudo apt install --only-upgrade ck-wifikiller
```

> 依赖（aircrack-ng/hashcat/hcxtools/hcxdumptool/tshark）由 deb 自动拉取。

### 方式 2：Release .deb 手动安装 / Manual .deb

```bash
# 从 GitHub Releases 下载 / Download from Releases
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark
sudo apt install ./ck-wifikiller_*.deb
```

### 方式 3：源码 / From source

```bash
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller && sudo pip3 install -e .
```

### 方式 4：Docker / Container

```bash
docker build -t ck-wifikiller .
# 需挂载无线网卡 + privileged
docker run --rm --net=host --privileged ck-wifikiller --recon status
```

---

## 🚀 用法 / Usage

```bash
sudo ck-wifikiller                          # 全自动扫描+攻击
sudo ck-wifikiller --recon status           # L1 工具矩阵 + 依赖检测
sudo ck-wifikiller --recon kismet           # Kismet 引导 + REST 探测
sudo ck-wifikiller --recon bettercap        # 生成 bettercap caplet
sudo ck-wifikiller --recon report           # 汇总 JSON 报告
sudo ck-wifikiller --pmkid                  # 优先 PMKID 路径
sudo ck-wifikiller --dict /path/wl.txt      # 指定字典
sudo ck-wifikiller --cn                     # 国内 WiFi 智能优化（掩码管线）
sudo ck-wifikiller --rules /usr/share/hashcat/rules/best64.rule
sudo ck-wifikiller --mask '?d?d?d?d?d?d?d?d'   # 8 位纯数字掩码
sudo ck-wifikiller --increment --increment-max 8
sudo ck-wifikiller --no-update                 # 关闭启动更新检测
sudo ck-wifikiller --crack                     # 破解已抓握手/PMKID
sudo ck-wifikiller --check hs/handshake.cap    # 检查 .cap 是否含握手
```

> 启动时自动检测 GitHub 最新版本并提示升级（离线/超时静默跳过）。

---

## 🏗️ 架构 / Architecture (2026 toolchain)

详见 [docs/TOOLCHAIN-2026.md](docs/TOOLCHAIN-2026.md)。

```
┌──────────────────────────────────────────────────────────┐
│  L1 Recon  侦察层                                         │
│  Kismet (Wi-Fi/BT/Zigbee WIDS) · bettercap · airodump-ng │
├──────────────────────────────────────────────────────────┤
│  L2 Capture  采集层                                       │
│  hcxdumptool + BPF (--exitoneapol) · airodump + aireplay │
├──────────────────────────────────────────────────────────┤
│  L3 Crack  破解层                                         │
│  hashcat -m 22000 + 内置词典 + rules/mask/increment + CN  │
└──────────────────────────────────────────────────────────┘
```

| 层 | 角色 | 工具 | ck-wifikiller |
|:---|:-----|:-----|:--------------|
| **L1** | 无线 Nmap + WIDS | Kismet 2025-09-R1+ | `--recon kismet\|status\|report` |
| L1 | 主动 recon / PMKID assoc | bettercap | `--recon bettercap` 生成 caplet |
| L1 | 经典 AP/客户端表 | airodump-ng | 内置 Scanner |
| **L2** | PMKID + EAPOL 采集 | hcxdumptool + BPF | 现代 PMKID 攻击 |
| L2 | 统一哈希转换 | hcxpcapngtool → `hc22000` | 替代 hcxpcaptool |
| **L3** | GPU 爆破 | hashcat `-m 22000` | 内置词典 + rules/mask/increment |
| L3 | 国内优化 | CN mask pipeline | `--cn` 8/11 位数字、手机号 |
| L3 | 厂商识别 | OUI advisory | 攻击前打印厂商/推荐路径 |
| L3 | WPA3 检测 | SAE+PSK 检测 | 降级可行性提示 |

### 废弃对照 / Deprecation (2018 → 2026)

| 旧 / Old | 新 / New |
|:---------|:---------|
| hashcat `-m 2500` / hccapx | `-m 22000` / hc22000 |
| hashcat `-m 16800` | `-m 22000`（WPA*01* PMKID） |
| `hcxpcaptool` | `hcxpcapngtool` |
| hcxdumptool `--filterlist` | `--bpf=` + BPF |
| pyrit | 可选；Kali 常缺省 |

---

## 🔧 依赖 / Dependencies

```bash
sudo apt install -y \
  aircrack-ng hashcat hcxtools hcxdumptool tshark \
  reaver bully macchanger iw net-tools \
  kismet kismet-capture-linux-wifi kismet-capture-linux-bluetooth \
  bettercap
```

---

## 📦 发布 / Release

Tag-triggered CI pipeline (`.github/workflows/build-deb.yml`)：

1. **build-deb**：Debian 容器内 `dpkg-buildpackage` 构建 `.deb` → lintian 校验 → 上传产物
2. **apt-repo**：下载 `.deb` → `dpkg-scanpackages` + `apt-ftparchive` 生成签名 Debian 仓库 → 推送 `gh-pages`（GitHub Pages 提供 apt 源）
3. **publish-release**：创建/更新 GitHub Release，附加 `.deb` + `SHA256SUMS`

```bash
git tag v2.5.0 && git push origin v2.5.0
# → CI 构建 .deb + 发布 Release + 更新 apt 仓库（apt install 即可装到新版）
```

本地不构建 `.deb`，全部由 CI 完成。

---

## 🧪 测试 / Tests

```bash
./runtests.sh   # 或 python3 -m unittest discover tests -v
```

覆盖：命令注入安全（BPF/packetforge/aircrack argv）、Target BSSID 校验、hashcat 参数（increment 仅掩码/WPA 最小 8 位）、CN 时区判断、OUI 厂商识别、进程封装、入口点。

---

## 🙏 致谢 / Credits

- Original [wifite2](https://github.com/derv82/wifite2) by derv82 & contributors (GPL-2.0)
- [hcxdumptool](https://github.com/ZerBea/hcxdumptool) / [hcxtools](https://github.com/ZerBea/hcxtools) by ZerBea
- [hashcat](https://hashcat.net/) · [Kismet](https://www.kismetwireless.net/) · [bettercap](https://www.bettercap.org/)

## 📄 License

GNU GPL v2 — same as wifite2. See `LICENSE` and `debian/copyright`.
