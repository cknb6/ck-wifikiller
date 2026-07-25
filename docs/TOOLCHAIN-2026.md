# 2026 无线工具链（ck-wifikiller 编排）

本项目是 **wifite2 的现代化编排壳**：优先调用 Kali 上仍在维护的专业工具，而不是重写 Kismet/hashcat。

## 分层

| 层 | 角色 | 工具 | ck-wifikiller |
|----|------|------|----------------|
| **L1 Recon** | 无线 Nmap + WIDS | **Kismet** 2025-09-R1+（Wi‑Fi/BT/Zigbee/SDR） | `ck-wifikiller --recon kismet\|status\|report` |
| L1 主动 | 扫描 / PMKID assoc | **bettercap** wifi 模块 | `--recon bettercap` 生成 caplet |
| L1 经典 | AP/客户端表 | airodump-ng | 内置 Scanner |
| **L2 Capture** | PMKID + EAPOL | **hcxdumptool** + BPF | 现代 PMKID 攻击 |
| L2 Convert | 统一哈希 | **hcxpcapngtool** → `hc22000` | 替代 hcxpcaptool |
| **L3 Crack** | GPU 爆破 | **hashcat -m 22000** | 内置词典 + `--dict` |
| L3 辅助 | 弱默认口令 | hcxpsktool / hcxeiutool | 后续接入 |

## Kali 安装依赖

```bash
sudo apt update
sudo apt install -y \
  aircrack-ng hashcat hcxtools hcxdumptool tshark \
  reaver bully macchanger iw net-tools \
  kismet kismet-capture-linux-wifi kismet-capture-linux-bluetooth \
  bettercap
```

## 废弃对照（2018 → 2026）

| 旧 | 新 |
|----|-----|
| hashcat `-m 2500` / hccapx | `-m 22000` / hc22000 |
| hashcat `-m 16800` | `-m 22000`（WPA\*01\* PMKID） |
| `hcxpcaptool` | `hcxpcapngtool` |
| hcxdumptool `--filterlist` | `--bpf=` + BPF |
| pyrit | 可选；Kali 常缺省 |

## 合规

仅限**授权**无线安全评估。未授权拦截/攻击无线网络可能违法。
