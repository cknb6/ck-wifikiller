# Changelog

所有重要改动都记录在此文件 / All notable changes are documented here.

## [v2.5.30] - 未发布 / Unreleased

**EN**: Offline commands (`--check`/`--cracked`/`--crack`) exempt from root & hard
dependency checks; `airmon-ng`/`airodump-ng` added to dependency check; `--recon
audit` aligned with `status`; `--recon report` tolerates Kismet write failure;
corrupted `cracked.txt` backed up to `.bak` before rewrite; CI apt-repo history
completed 2.5.15–2.5.29; removed duplicate config assignment.

### 修复 / Fixes

- `--check`/`--cracked`/`--crack` 纯离线命令不再被全局 root 检查与依赖检查拦截（非 root、缺 aircrack-ng 等工具时也能运行，各自实现内已有降级）
- 依赖检查补入 `airmon-ng`/`airodump-ng`（此前被 import 却未纳入检查列表）
- `--recon audit` 与 `status` 行为一致（补 Kismet 提示）；`--recon report` 写盘失败不再阻断主流程
- `cracked.txt` 损坏（非 JSON）时先备份为 `.bak` 再写入，避免覆盖丢失历史破解记录
- apt 仓库历史 deb 合并列表补全 2.5.15–2.5.29（原停在 2.5.14）
- `config.py` 删除 `wep_crack_at_ivs` 重复赋值

## [v2.5.29] - 已发布 / Released

**EN**: New `--recon clients` online-client scan; `--dict [file|dir]` + `CK_WIFI_WORDLIST`;
Kali desktop launcher. Root fix: handshake check now falls back to aircrack-ng
(stock Kali lacks tshark/pyrit) so deauth no longer times out waiting forever;
PMKID BSSID colon-normalization fix; aircrack crack deadlock fixed via select
polling; capture re-validation throttled to file-change only; `--scan-time`/
`--version` registered; PMKID regression tests added (132 tests pass).

### 新增功能

- `--recon clients`：在线客户端扫描（需 root + 监听网卡），时长用 `--scan-time`（默认 15s）
- `--dict [file|dir]`：字典路径支持目录（目录下全部 `.txt` 文件合并），未指定时回退 `CK_WIFI_WORDLIST` 环境变量 → 内置字典列表
- Kali 桌面快捷方式：`packaging/ck-wifikiller.desktop` + 图标，`pip install .` 后可从应用菜单启动

### 修复

- **握手包检测根因修复**：`has_handshake()` 原只信任 tshark/pyrit，二者在 Kali 默认环境都缺失（pyrit 已移出 Kali 仓库）→ 校验链为空 → 踢下线成功也永远显示"等待握手"直到超时。现启用 aircrack-ng 兜底校验（tshark → pyrit → aircrack 任一确认即有效）
- **PMKID 永远抓不到（高）**：`HcxPcapTool.get_pmkid_hash` 的 BSSID 比较未归一化冒号，hcxpcapngtool 输出带冒号导致恒不匹配，PMKID 攻击每目标白跑 60s。已修复并新增回归测试
- **aircrack 爆破死锁（高）**：`stdout.readline()` 阻塞导致 `max_seconds` 预算失效与双向死锁（aircrack 进度用 `\r` 不换行）。改 `select.select` 轮询
- **握手等待轮询节流**：`attack/wpa.py` 仅当 cap 文件 `(size, mtime)` 变化才复制并调用 aircrack 判定（原每 0.4s 全量复制+扫描）；`attack/pmkid.py` 仅当 pcapng 增长才重跑 hcxpcapngtool（原每 1s 全量转换）
- `--scan-time` 长选项注册（原只有 `-p`）；`--version` 参数注册（原报 unrecognized）
- `tools/airodump.py` 临时文件清理括号优先级；`recon/clients.py` 移除死代码
- `model/handshake.py`：aircrack-ng 缺失时返回空而不是 FileNotFoundError

### 测试

- 新增 `tests/test_PmkidMatch.py`（PMKID BSSID 匹配回归）、`tests/test_ClientsScan.py`、`tests/test_Wordlist.py` 修复
- 全套 132 个测试通过（4 个 skip：本机缺 tshark/pyrit/cowpatty）

## [v2.5.28]

- WPS: `_extract_psk` 兼容 reaver 分支不加引号的 `WPA PSK: password` 输出

## [v2.5.27]

- WPS: 破解 PIN 后先停主 reaver 进程再取 PSK，避免两个 reaver 实例争抢

## [v2.5.26]

- WPS: PIN 破解后自动取回 WPA PSK（reaver 1.6.x 破解 PIN 不返回 PSK）

## [v2.5.25]

- deauth: 提高发包量确保踢下线（scapy 定向 16→64 / 广播 32→128）

## [v2.5.24]

- WPA deauth: 首轮发包前用 airodump 扫描预填已知客户端，修复 `wait_for_target` 后客户端列表被清空的问题

## [v2.5.23] 及更早

历史版本见 `debian/changelog` 与 GitHub Releases。
