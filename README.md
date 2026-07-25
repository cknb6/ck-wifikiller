# ck-wifikiller

**Modern Kali wireless auditor** — maintained fork of [wifite2](https://github.com/derv82/wifite2) (last upstream ~2018).

> **Authorized security testing only.** Unauthorized attacks may be illegal.

```
Version: 2.3.0-ck
GitHub:  https://github.com/cknb6/ck-wifikiller
Author:  传康Kk（万能程序员）
WeChat:  1837620622  （赞助备注「wifi赞助」/ 商务备注「商务合作」）
Email:   2040168455@qq.com
```

## Why this fork?

| 2018 wifite2 | ck-wifikiller (2026 Kali) |
|--------------|---------------------------|
| `hcxpcaptool` | **`hcxpcapngtool`** |
| hashcat `-m 2500` / `16800` | **`-m 22000`** (PMKID+EAPOL) |
| hcxdumptool `--filterlist` | **BPF `--bpf=`** (+ legacy fallback) |
| small top4800 wordlist | **ck-default-wpa** (~25万高优先级) |
| no recon layer | **`--recon`** → Kismet / bettercap matrix |

## Install (Kali)

```bash
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark

# from Release .deb
sudo apt install ./ck-wifikiller_*.deb

# or from source
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller && sudo pip3 install -e .
```

## Usage

```bash
sudo ck-wifikiller
sudo ck-wifikiller --recon status      # L1 tool matrix
sudo ck-wifikiller --recon kismet      # Kismet guide + REST probe
sudo ck-wifikiller --recon bettercap   # write bettercap caplet
sudo ck-wifikiller --pmkid             # prefer PMKID path
sudo ck-wifikiller --dict /path/wl.txt
```

## Architecture (2026 toolchain)

See [docs/TOOLCHAIN-2026.md](docs/TOOLCHAIN-2026.md).

1. **Recon (L1):** Kismet (Wi‑Fi/BT/Zigbee WIDS), bettercap, airodump-ng  
2. **Capture (L2):** hcxdumptool / airodump + aireplay  
3. **Crack (L3):** hashcat `-m 22000` + built-in wordlist  

## Credits

- Original [wifite2](https://github.com/derv82/wifite2) by derv82 & contributors (GPL-2.0)
- [hcxdumptool](https://github.com/ZerBea/hcxdumptool) / [hcxtools](https://github.com/ZerBea/hcxtools) by ZerBea
- [hashcat](https://hashcat.net/), [Kismet](https://www.kismetwireless.net/), [bettercap](https://www.bettercap.org/)

## License

GNU GPL v2 — same as wifite2. See `LICENSE` and `debian/copyright`.
