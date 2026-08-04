# ck-wifikiller

- Path: `/Volumes/256G/ck-wifikiller`
- Fork of derv82/wifite2 (GPL-2.0)
- Publish: GitHub **cknb6/ck-wifikiller** (Actions); commit author **1837620622**
- Runtime target: **Kali Linux** (monitor NIC, root). macOS 仅开发，不跑注入。
- Wordlist: `wordlists/ck-default-wpa.txt`
- Build deb: `scripts/build-deb.sh` on Kali/Debian

## 攻击矩阵（v2.5.30 / 2026 工具链）

| 路径 | 捕获/在线 | 离线爆破 | Kali 依赖 | 备注 |
|------|-----------|----------|-----------|------|
| **PMKID** | hcxdumptool BPF + `--exitoneapol=7` | hashcat `-m 22000` + hcxpsktool 候选 | hcxdumptool hcxtools hashcat | clientless 优先 |
| **Handshake** | airodump + Scapy deauth 爆发×4 / 静默 4s | 同上；后台全量字典 | aircrack-ng scapy | 有客户端更稳 |
| **WPS Pixie** | reaver `-K/--pixie-dust` 或 bully `--pixiewps` | 在线得 PIN/PSK | reaver bully | 老路由；LOCKED 仍可试 |
| **WPS PIN** | reaver/bully 在线 | — | reaver bully | LOCKED 默认跳过 |
| **WEP** | aireplay IV | aircrack | aircrack-ng | 遗留网络 |
| **WPA3-SAE 纯** | — | 离线 22000 不可行 | — | 仅提示；Transition 可打 WPA2 侧 |

## 推荐包

```bash
sudo apt install aircrack-ng hashcat hcxtools hcxdumptool \
  reaver bully tshark python3-scapy macchanger
# 可选 recon
sudo apt install kismet bettercap
```

## 调度默认

- PMKID ≥60s，其它路径 ≥45s；单目标预算默认 210s
- 捕获后字典默认**独立窗口/后台**全量（`--no-bg-crack` 可关）
- 有效哈希校验；同 AP 多包相同取一、不同取最新
