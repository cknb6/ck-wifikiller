# Kali Linux — New Tool Request (draft for bugs.kali.org)

**Submitted:** https://bugs.kali.org/view.php?id=9799  
**Reporter:** chuankangkk (cknb)  
**Category:** New Tool Requests  
**Status:** open / new  

Use this text when filing: https://bugs.kali.org/

**Category:** New Tool Requests  
**Reproducibility:** N/A  
**Severity:** minor  
**Priority:** normal  
**Summary:** ck-wifikiller — modern wireless audit orchestrator (wifite2 fork for current Kali toolchain)

---

## Description (paste into bug tracker)

```
[Name] - ck-wifikiller

[Version] - 2.5.9
- Git tag: https://github.com/cknb6/ck-wifikiller/releases/tag/v2.5.9
- Source: https://github.com/cknb6/ck-wifikiller

[Homepage] - https://github.com/cknb6/ck-wifikiller
- Third-party apt (unsigned, trusted=yes): https://cknb6.github.io/ck-wifikiller/
- Install docs: https://github.com/cknb6/ck-wifikiller/blob/master/docs/INSTALL-KALI.md

[Download] - https://github.com/cknb6/ck-wifikiller/releases/latest
- Debian package: ck-wifikiller_2.5.9_all.deb (also built via GitHub Actions)

[Author] - 传康Kk (maintainer of this fork)
- Contact email: 2040168455@qq.com
- GitHub org/user: https://github.com/cknb6
- Upstream lineage: fork of derv82/wifite2 (GPL-2.0)

[Licence] - GNU General Public License v2.0 (same as wifite2)
- LICENSE file in repository root

[Description]
ck-wifikiller is a wireless auditing *orchestrator* for authorized penetration testing on modern Kali Linux (2024–2026 toolchains). It is a maintained fork of wifite2 focused on driving current packages rather than re-implementing capture/crack engines.

It coordinates:
- PMKID / EAPOL capture via modern hcxdumptool (BPF + optional --exitoneapol) and hcxpcapngtool
- Offline cracking with hashcat mode 22000 (unified PMKID+EAPOL; not deprecated 2500/16800)
- WPA handshake path via aircrack-ng suite
- WPS Pixie-Dust / PIN via reaver or bully
- Optional Scapy L2 deauth/disassoc burst (stronger injection on some USB NICs) with aireplay fallback
- Optional Layer-1 recon hooks (Kismet / bettercap status)
- Time-sliced multi-path schedule (brand-weighted paths, capture-first budget)
- Optional mainland-China weak-password mask profile (--cn), timezone-gated

Important compliance note: the tool is intended ONLY for networks the operator owns or is explicitly authorized to test.

Why a separate package from the existing "wifite" package?
- Kali already ships "wifite" (kimocoder/wifite2 lineage). We acknowledge the overlap.
- This fork emphasizes: (1) strict modern hcx BPF / 22000-only path; (2) Scapy dual-channel deauth for weak USB adapters (e.g. MT7921U-class); (3) closed-loop --auto scheduling with weighted path budgets; (4) optional CN mask pipeline and bilingual UI (zh/en).
- We are open to: (a) packaging as a distinct tool if the team sees value for users who need these paths; or (b) contributing patches upstream into the packaged wifite if preferred. Please advise which path is better for Kali.

[Dependencies]
Runtime (Debian/Kali package names):
- python3
- aircrack-ng
- hashcat
- hcxtools
- hcxdumptool
- tshark | wireshark-common
- iw
- net-tools

Recommends:
- reaver, bully, macchanger, kismet, bettercap, python3-scapy

[Similar tools]
- wifite (already in Kali; primary similar tool — see above)
- airgeddon
- fluxion (different approach; social engineering / evil twin focus)
- bettercap (broader framework; not a drop-in wifite-style scheduler)
- hcxdumptool / hashcat (underlying engines; this tool orchestrates them)

[Activity]
- Project started as a wifite2 fork for modern Kali package renames and hash modes.
- Actively developed through 2026; regular tagged releases (v2.5.0–v2.5.9) with GitHub Actions building .deb and a third-party apt repository.
- Latest release: v2.5.9 (2026).

[How to install]
Preferred for evaluation (release tarball / tag — not git HEAD):
1) From GitHub Release .deb:
   curl -LO https://github.com/cknb6/ck-wifikiller/releases/download/v2.5.9/ck-wifikiller_2.5.9_all.deb
   sudo apt install -y ./ck-wifikiller_2.5.9_all.deb
2) Or from tagged source:
   git clone --branch v2.5.9 https://github.com/cknb6/ck-wifikiller.git
   cd ck-wifikiller
   # package already includes debian/; or: sudo pip3 install -e .
   sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark reaver bully python3-scapy

Third-party apt (optional):
   echo "deb [trusted=yes] https://cknb6.github.io/ck-wifikiller stable main" | sudo tee /etc/apt/sources.list.d/ck-wifikiller.list
   sudo apt update && sudo apt install -y ck-wifikiller

Packaging status:
- Upstream repository already contains a debian/ directory (debhelper, pybuild).
- Built as Architecture: all.
- Not currently in Debian or official Kali archives (this request).

[How to use]
Authorized testing only.

  sudo ck-wifikiller -h
  sudo ck-wifikiller --auto
  sudo ck-wifikiller --pmkid
  sudo ck-wifikiller --cn
  sudo ck-wifikiller --deauth-engine scapy   # if python3-scapy installed
  sudo ck-wifikiller --recon status

[Packaged] - Not packaged for Debian official. Local debian/ packaging exists and produces .deb via CI; not in Debian/Kali yet.
```

---

## Submit checklist (bugs.kali.org)

1. Create / login account: https://bugs.kali.org/signup_page.php  
2. Report Issue → Category **New Tool Requests**  
3. Reproducibility **N/A**, Severity **minor**, Priority **normal**  
4. Paste Summary + Description above  
5. Submit Report  
6. Reply here with the issue URL (e.g. https://bugs.kali.org/view.php?id=XXXX)
