# 2026 无线工具链（ck-wifikiller 编排） / 2026 Wireless Toolchain

本项目是 **wifite2 的现代化编排壳**：优先调用 Kali 上仍在维护的专业工具，而不是重写 Kismet/hashcat。
This project is a **modern orchestration shell for wifite2**: it calls maintained Kali tools rather than rewriting Kismet/hashcat.

## 分层 / Layers

| 层 / Layer | 角色 / Role | 工具 / Tool | ck-wifikiller |
|----|------|------|----------------|
| **L1 Recon** | 无线 Nmap + WIDS | **Kismet** 2025-09-R1+（Wi‑Fi/BT/Zigbee/SDR） | `ck-wifikiller --recon kismet\|status\|report` |
| L1 主动 | 扫描 / PMKID assoc | **bettercap** wifi 模块 | `--recon bettercap` 生成 caplet |
| L1 经典 | AP/客户端表 | airodump-ng | 内置 Scanner |
| **L2 Capture** | PMKID + EAPOL | **hcxdumptool** + BPF | 现代 PMKID 攻击 |
| L2 Convert | 统一哈希 | **hcxpcapngtool** → `hc22000` | 替代 hcxpcaptool |
| **L3 Crack** | GPU 爆破 | **hashcat -m 22000** | 内置词典 + `--dict` + rules/mask/increment |
| L3 CN | 国内优化 | **CN mask pipeline** | `--cn` 8/11 位数字、手机号、生日 |
| L3 Intel | 厂商识别 | **OUI advisory** | 攻击前打印厂商/CVE/推荐路径 |
| L3 WPA3 | Transition 检测 | **SAE+PSK 检测** | 降级可行性提示（Dragonblood） |

## Kali 安装依赖 / Install deps

```bash
sudo apt update
sudo apt install -y \
  aircrack-ng hashcat hcxtools hcxdumptool tshark \
  reaver bully macchanger iw net-tools \
  kismet kismet-capture-linux-wifi kismet-capture-linux-bluetooth \
  bettercap
```

## 废弃对照（2018 → 2026） / Deprecation

| 旧 / Old | 新 / New |
|----|-----|
| hashcat `-m 2500` / hccapx | `-m 22000` / hc22000 |
| hashcat `-m 16800` | `-m 22000`（WPA\*01\* PMKID） |
| `hcxpcaptool` | `hcxpcapngtool` |
| hcxdumptool `--filterlist` | `--bpf=` + BPF |
| pyrit | 可选；Kali 常缺省 |

## 合规 / Compliance

仅限**授权**无线安全评估。未授权拦截/攻击无线网络可能违法。
Authorized wireless security assessment only. Unauthorized interception/attacks may be illegal.

