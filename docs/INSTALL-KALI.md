# Kali 安装 · ck-wifikiller

## 方式 A：.deb（推荐）

```bash
# 依赖
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark reaver

# 安装本包（从 Release 下载）
sudo apt install ./ck-wifikiller_*.deb
# 或
sudo dpkg -i ck-wifikiller_*.deb && sudo apt -f install
```

## 方式 B：源码

```bash
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller
sudo python3 setup.py install
# 或开发模式
sudo pip3 install -e .
```

## 运行

```bash
sudo ck-wifikiller
sudo ck-wifikiller --recon status    # 工具链矩阵
sudo ck-wifikiller --recon kismet    # Kismet 侦察指南
sudo ck-wifikiller --pmkid           # 偏 PMKID
sudo ck-wifikiller --dict /path/to/wordlist.txt
```

## 构建 .deb（维护者）

在 **Kali/Debian** 环境：

```bash
sudo apt install -y build-essential debhelper dh-python python3-all devscripts
./scripts/build-deb.sh
```
