# ck-wifikiller

Modern Kali wireless auditor — maintained fork of [derv82/wifite2](https://github.com/derv82/wifite2)

**hashcat `-m 22000` · PMKID · hcxpcapngtool · Kismet recon · CN audit profile**

Authorized security testing only. 仅限授权安全测试。

[![Kali](https://img.shields.io/badge/Kali-Rolling-1793D1?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![hashcat](https://img.shields.io/badge/hashcat-m%2022000-49A942)](https://hashcat.net/)
[![License](https://img.shields.io/badge/License-GPL--2.0-A42E2B)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v2.5.30-success)](https://github.com/cknb6/ck-wifikiller/releases)

```
GitHub:  https://github.com/cknb6/ck-wifikiller
Version: CK_WIFI_VERSION env > git describe > 2.5.30-ck
Author:  传康Kk（万能程序员）
WeChat:  1837620622  (赞助备注「wifi赞助」/ 商务「商务合作」)
Email:   2040168455@qq.com
License: GNU GPL v2 (same as wifite2)
```

---

## Compliance / 合规

Only use this tool on networks you own or are explicitly authorized to assess.
Unauthorized interception or attacks against wireless networks may be illegal.
You are solely responsible for how you use this software.

仅限在**已获授权**的网络上进行安全评估。未授权拦截/攻击无线网络可能违法，使用者自行承担法律责任。

---

## Overview / 简介

`ck-wifikiller` is a **modern maintenance fork** of wifite2 (upstream largely stalled around 2018), adapted for **current Kali Linux** toolchains (2024–2026).

It is **not** a rewrite of Kismet, hashcat, or aircrack-ng. It is an **orchestration shell**: it drives maintained Kali tools and fixes upstream gaps that break on modern packages.

| Gap in 2018 wifite2 | What this fork does |
|---------------------|---------------------|
| `hcxpcaptool` (removed/renamed) | Uses `hcxpcapngtool` |
| hashcat `-m 2500` / `-m 16800` | Unified **`-m 22000`** (PMKID + EAPOL) |
| hcxdumptool `--filterlist` | **BPF** (`--bpf`) + undirected probe; `--exitoneapol 7` with BPF |
| Small top4800 wordlist only | Bundled `ck-default-wpa.txt` (~400k+ lines, WPA 8–63, CN-first) |
| `--dict <file>` only, dirs rejected | `--dict [file\|dir]` + `CK_WIFI_WORDLIST` env (dir auto-picks rockyou/combined lists) |
| No recon layer | `--recon` → Kismet / bettercap / status matrix + **`--recon clients` online-client scan** |
| Handshake check trusts tshark/pyrit only | **aircrack-ng fallback** — works on stock Kali (no tshark/pyrit) |
| PMKID BSSID match bug (upstream) | Colon-normalized MAC matching in `hcxpcapngtool` output |
| Single dictionary crack | rules / mask / increment + optional CN profile |
| No vendor context | OUI fingerprint + brand-ordered attack paths |
| No WPA3 awareness | Detect SAE / Transition Mode and warn |
| Hardcoded version | Dynamic version (env / git describe) |
| No update check | Optional non-blocking GitHub Release check |
| Interactive-only select | `--auto` / `-p` closed-loop: scan then attack all |
| Crack overruns path budget | Capture-first full slice; crack uses remaining wall-clock |
| Equal path slices | Weighted: handshake/PMKID > Pixie > PIN; default 90s/AP |

---

## Features / 功能

### Capture and crack

- PMKID path via `hcxdumptool` → `hcxpcapngtool` → hashcat `-m 22000`
- BPF filter retains undirected probes (`addr3` target **or** broadcast); `--exitoneapol 7` only with BPF
- WPA handshake path via airodump/aireplay + aircrack/hashcat/john/cowpatty
  - Handshake validation falls back to **aircrack-ng** when tshark/pyrit are absent (stock Kali)
  - Capture loop throttled: re-checks the cap only when it grows (no 0.4s full-file rescans)
- WPS Pixie-Dust / PIN via reaver (or bully); brand-ordered **weighted** path slices (min 15s, default 90s/AP)
- Capture-first: full slice for capture; early success leaves wall-clock for hashcat/aircrack
- Handshake deauth: Scapy bidirectional burst + aireplay (`--deauth-engine auto`); stronger on weak USB NICs
- Handshake deauth interval synced to capture window (deauth at start)
- Offline crack: `--rules`, `--mask`, `--increment`, `--hc-args`; budget exhausted → skip crack
- Closed loop: `--auto` (scan 15s then all) or `-p N` pillage

### Recon: online client scan (`--recon clients`)

- Scans for APs and lists **currently connected clients** (online first, then idle APs)
- Per-AP rows: BSSID / ESSID / channel / encryption / power / client count
- Client vendor via OUI database (best-effort); hidden SSIDs flagged
- Saves a plain-text report `ck-clients-report.txt` in the working directory
- Requires root (monitor mode); duration via `--scan-time` (default 15s)

### CN audit profile (`--cn`)

- After dictionary failure, runs a **bounded mask pipeline** (digit/letter templates, WPA min length 8)
- Auto-enable only when IANA timezone is clearly CN-related (`Asia/Shanghai`, etc.); not by UTC offset alone
- Override: `--cn` / `--no-cn` / `CK_WIFI_REGION`
- Does **not** invent device default passwords or claim vendor CVEs from OUI alone

### Passive intel (advisory only)

- OUI lookup (system ieee-data / manuf / nmap prefixes first, small fallback table)
- Optional SSID operator/vendor **hints** with conflict handling
- Prints recommended attack **order** by brand (PMKID / Pixie / PIN / handshake)
- Explicitly does not claim “this AP is vulnerable”

### WPA3 awareness

- Transition Mode (SAE+PSK): notes downgrade feasibility (offline WPA2 path may still exist)
- Pure SAE: notes offline dictionary attack is not applicable

### Ops

- Startup update check against GitHub Releases (3s timeout, silent on failure; disable with `--no-update`)
- Session logs under `~/.ck-wifikiller/logs/` (disable with `CK_WIFI_NO_LOG=1`)
- Tag-triggered CI: build `.deb`, publish Release, refresh apt repo on GitHub Pages

---

## Install / 安装

### 1) apt repository (recommended)

Kali 默认源**不包含**本包。若只运行 `sudo apt install ck-wifikiller` 而不添加源，会报：

`错误：无法定位软件包 ck-wifikiller`

必须先添加第三方源，再安装：

```bash
# step 1: add repository (once)
echo "deb [trusted=yes] https://cknb6.github.io/ck-wifikiller stable main" \
  | sudo tee /etc/apt/sources.list.d/ck-wifikiller.list

# step 2: refresh index
sudo apt update

# step 3: install
sudo apt install -y ck-wifikiller

# upgrade later
sudo apt update && sudo apt install --only-upgrade ck-wifikiller
```

Verify the source is present:

```bash
cat /etc/apt/sources.list.d/ck-wifikiller.list
apt-cache policy ck-wifikiller
```

Hard dependencies pulled by the package: `aircrack-ng`, `hashcat`, `hcxtools`, `hcxdumptool`, `tshark` (or `wireshark-common`), `iw`, `net-tools`.

The package installs a **desktop launcher** (`/usr/share/applications/ck-wifikiller.desktop`, icon in
`/usr/share/icons/hicolor/scalable/apps/`) so Kali shows "CK WifiKiller" in the application menu;
it opens a terminal for the interactive scan flow. Handshake validation needs no tshark on Kali —
aircrack-ng is used as fallback.

### 2) Manual `.deb` from Releases (no apt repo)

```bash
curl -LO https://github.com/cknb6/ck-wifikiller/releases/download/v2.5.15/ck-wifikiller_2.5.11_all.deb
sudo apt install -y ./ck-wifikiller_2.5.11_all.deb
```

### 3) From source

```bash
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller
sudo pip3 install -e .
```

### 4) Docker

```bash
docker build -t ck-wifikiller .
# wireless capture needs host network + privileges
docker run --rm --net=host --privileged ck-wifikiller --recon status
```

### Optional tools

```bash
sudo apt install -y \
  reaver bully macchanger \
  kismet kismet-capture-linux-wifi kismet-capture-linux-bluetooth \
  bettercap
```

---

## Usage / 用法

Root is required for monitor mode / injection paths. Recon-only modes may still need root for Kismet/bettercap.

```bash
sudo ck-wifikiller                          # scan + attack flow
sudo ck-wifikiller --recon status           # tool matrix + dependency probe
sudo ck-wifikiller --recon kismet           # Kismet guidance / REST probe
sudo ck-wifikiller --recon bettercap        # generate bettercap caplet
sudo ck-wifikiller --recon report           # summary JSON report
sudo ck-wifikiller --recon clients          # online-client scan → ck-clients-report.txt
sudo ck-wifikiller --recon clients --scan-time 30   # longer client scan window
sudo ck-wifikiller --pmkid                  # PMKID-only path
sudo ck-wifikiller --dict /path/wl.txt      # custom wordlist file
sudo ck-wifikiller --dict /path/wl-dir/     # custom wordlist DIRECTORY (auto-pick)
CK_WIFI_WORDLIST=/path/wl.txt sudo ck-wifikiller   # wordlist via environment variable
sudo ck-wifikiller --cn                     # force CN audit profile
sudo ck-wifikiller --no-cn                  # disable CN profile + auto detect
sudo ck-wifikiller --rules /usr/share/hashcat/rules/best64.rule
sudo ck-wifikiller --mask '?d?d?d?d?d?d?d?d'
sudo ck-wifikiller --increment --increment-max 8
sudo ck-wifikiller --no-update              # skip release check
sudo ck-wifikiller --crack                  # crack saved handshake / PMKID
sudo ck-wifikiller --check hs/handshake.cap
sudo ck-wifikiller --cracked                # show saved results
```

Wordlist resolution order (first existing wins):

1. `CK_WIFI_WORDLIST` env (highest priority)
2. `--dict [file|dir]` — dir auto-picks: exact common names (`rockyou.txt`, `*_combined.txt`, …), then `wifi*.txt` / `*.txt` / `*.lst` glob
3. `wordlists/ck-default-wpa.txt` (repo / package: WPA 8–63 only, CN-first, ~500k+)
4. `wordlists/wpa-top4800.txt`
5. system paths under `/usr/share/ck-wifikiller/...` and common dict locations

Regenerate the default list with:

```bash
python3 scripts/build-wordlist.py --target 520000
```

---

## Architecture / 架构

See [docs/TOOLCHAIN-2026.md](docs/TOOLCHAIN-2026.md).

```
+------------------------------------------------------------------+
|  L1 Recon                                                         |
|  Kismet · bettercap · airodump-ng                                 |
+------------------------------------------------------------------+
|  L2 Capture                                                       |
|  hcxdumptool + BPF · airodump-ng + aireplay-ng                    |
+------------------------------------------------------------------+
|  L3 Crack                                                         |
|  hashcat -m 22000 · aircrack-ng · optional john/cowpatty          |
|  rules / mask / increment · CN bounded masks · OUI advisory       |
+------------------------------------------------------------------+
```

| Layer | Role | Tool | ck-wifikiller hook |
|------:|------|------|--------------------|
| L1 | WIDS / inventory | Kismet | `--recon kismet\|status\|report` |
| L1 | active recon helper | bettercap | `--recon bettercap` (caplet) |
| L1 | classic AP table | airodump-ng | built-in scanner |
| L2 | PMKID + EAPOL | hcxdumptool | modern PMKID attack |
| L2 | hash export | hcxpcapngtool | `*.hc22000` |
| L3 | GPU crack | hashcat `-m 22000` | wordlist + rules/mask |
| L3 | intel | OUI/SSID advisory | print-only guidance |

### Deprecation map (2018 → modern)

| Old | New |
|-----|-----|
| hashcat `-m 2500` / hccapx | `-m 22000` / hc22000 |
| hashcat `-m 16800` | `-m 22000` (`WPA*01*` PMKID) |
| `hcxpcaptool` | `hcxpcapngtool` |
| hcxdumptool `--filterlist` | `--bpf` (+ fallback) |
| pyrit | optional; often absent on Kali |

---

## Security notes (implementation)

Recent hardening (v2.5.1) includes:

- External tools run as argv arrays (`shell=True` disabled)
- Interface / BSSID / channel input validation
- Temp paths strip directory components (no `../` escape)
- Decloak deauth targets **client station MAC**, not AP BSSID
- `cracked.txt` atomic write + tolerant load of corrupt JSON
- `Process.devnull()` uses `subprocess.DEVNULL` (no FD leak)

This is a privileged wireless audit tool. Treat it as root-equivalent software on your lab machine.

---

## Release / 发布

Tag-triggered CI (`.github/workflows/build-deb.yml`):

1. **build-deb** — `dpkg-buildpackage` in Debian container, lintian, artifact upload
2. **apt-repo** — packages + `Packages`/`Release` on `gh-pages` (GitHub Pages apt source)
3. **publish-release** — GitHub Release with `.deb` and `SHA256SUMS`

```bash
git tag v2.5.30 && git push origin v2.5.30
```

Local `.deb` build is optional via `scripts/build-deb.sh` on Debian/Kali; CI is the canonical path.

---

## Tests / 测试

```bash
./runtests.sh
# or
python3 -m unittest discover -s tests -v
```

Coverage includes: argv/shell safety, BSSID validation, hashcat argument ordering, CN region detection, OUI advisory constraints, process wrapper, temp path safety, deauth station MAC, cracked-file robustness, CLI entrypoint, wordlist resolution (file/dir/env), client-scan reporting, PMKID MAC matching (130+ tests).

See [CHANGELOG.md](CHANGELOG.md) for the version history.

---

## Docs

| File | Content |
|------|---------|
| [CHANGELOG.md](CHANGELOG.md) | Version history / 版本报告 |
| [docs/INSTALL-KALI.md](docs/INSTALL-KALI.md) | Kali install notes |
| [docs/TOOLCHAIN-2026.md](docs/TOOLCHAIN-2026.md) | Toolchain layering |
| [PMKID.md](PMKID.md) | PMKID notes |
| [EVILTWIN.md](EVILTWIN.md) | Evil Twin design notes (not fully implemented) |
| [AGENTS.md](AGENTS.md) | Repo agent notes |

---

## Credits

- Original [wifite2](https://github.com/derv82/wifite2) by derv82 and contributors (GPL-2.0)
- [hcxdumptool](https://github.com/ZerBea/hcxdumptool) / [hcxtools](https://github.com/ZerBea/hcxtools) by ZerBea
- [hashcat](https://hashcat.net/) · [Kismet](https://www.kismetwireless.net/) · [bettercap](https://www.bettercap.org/) · aircrack-ng suite

## License

GNU GPL v2 — same as wifite2. See `LICENSE` and `debian/copyright`.
