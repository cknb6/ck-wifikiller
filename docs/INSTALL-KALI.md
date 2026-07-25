# Kali 安装 · ck-wifikiller / Kali Install

## 方式 A：apt 仓库（推荐，自动更新） / apt repository (recommended)

仓库由 GitHub Actions 自动构建并发布到 GitHub Pages。
Repo is auto-built by GitHub Actions and published to GitHub Pages.

```bash
echo "deb [trusted=yes] https://cknb6.github.io/ck-wifikiller stable main" \
  | sudo tee /etc/apt/sources.list.d/ck-wifikiller.list
sudo apt update
sudo apt install -y ck-wifikiller

# 升级 / upgrade
sudo apt update && sudo apt install --only-upgrade ck-wifikiller
```

## 方式 B：.deb 手动安装 / Option B: manual .deb

```bash
# 依赖 / deps
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark reaver

# 安装本包（从 Release 下载） / install from Release
sudo apt install ./ck-wifikiller_*.deb
# 或 / or
sudo dpkg -i ck-wifikiller_*.deb && sudo apt -f install
```

## 方式 C：源码 / Option C: source

```bash
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller
sudo python3 setup.py install
# 或开发模式 / or dev mode
sudo pip3 install -e .
```

## 运行 / Run

```bash
sudo ck-wifikiller
sudo ck-wifikiller --recon status    # 工具链矩阵 / tool matrix
sudo ck-wifikiller --recon kismet    # Kismet 侦察指南 / Kismet recon guide
sudo ck-wifikiller --pmkid           # 偏 PMKID / prefer PMKID
sudo ck-wifikiller --dict /path/to/wordlist.txt
sudo ck-wifikiller --cn              # 国内 WiFi 智能优化 / CN optimization
sudo ck-wifikiller --no-update       # 关闭启动更新检测 / disable update check
```

## 构建 .deb（维护者） / Build .deb (maintainer)

> 维护者现已通过 **GitHub Actions** 自动构建 `.deb` 并自动发布 apt 仓库，本地无需构建。
> Maintainers now build `.deb` and publish the apt repo via **GitHub Actions**; no local build needed.

打 tag 触发（构建 .deb → Release → apt 仓库）/ tag-triggered:

```bash
git tag v2.5.0 && git push origin v2.5.0
```

如需本地构建（Kali/Debian）/ manual local build:

```bash
sudo apt install -y build-essential debhelper dh-python python3-all devscripts
./scripts/build-deb.sh
```

