# Kali 安装 · ck-wifikiller

## 方式 A：apt 仓库（推荐）

Kali 官方源**不包含** `ck-wifikiller`。  
若直接执行 `sudo apt install ck-wifikiller` 而未添加本仓库，会报：

```text
错误：无法定位软件包 ck-wifikiller
```

### 正确步骤

```bash
# 1) 添加源（只做一次；trusted=yes 不可省略）
echo "deb [trusted=yes] https://cknb6.github.io/ck-wifikiller stable main" \
  | sudo tee /etc/apt/sources.list.d/ck-wifikiller.list

# 2) 更新索引
sudo apt update

# 3) 确认能看到候选包
apt-cache policy ck-wifikiller

# 4) 安装
sudo apt install -y ck-wifikiller
```

升级：

```bash
sudo apt update
sudo apt install --only-upgrade ck-wifikiller
```

排查：

```bash
cat /etc/apt/sources.list.d/ck-wifikiller.list
apt-cache policy ck-wifikiller
ls /etc/apt/sources.list.d/
```

`apt-cache policy` 成功时应出现 `https://cknb6.github.io/ck-wifikiller` 候选版本。

---

## 方式 B：GitHub Release `.deb`（不配源）

```bash
curl -LO https://github.com/cknb6/ck-wifikiller/releases/download/v2.5.12/ck-wifikiller_2.5.11_all.deb
sudo apt install -y ./ck-wifikiller_2.5.11_all.deb
```

若 tag 尚未构建完成，打开 Releases 页面下载最新 `.deb`：

https://github.com/cknb6/ck-wifikiller/releases

---

## 方式 C：源码

```bash
git clone https://github.com/cknb6/ck-wifikiller.git
cd ck-wifikiller
sudo pip3 install -e .
```

依赖仍建议：

```bash
sudo apt install -y aircrack-ng hashcat hcxtools hcxdumptool tshark reaver bully
```

---

## 运行

```bash
sudo ck-wifikiller
sudo ck-wifikiller --auto
sudo ck-wifikiller -p 20
sudo ck-wifikiller --recon status
sudo ck-wifikiller --pmkid
sudo ck-wifikiller --cn
sudo ck-wifikiller --no-update
```

---

## 维护者：发布 apt

Tag 触发 GitHub Actions：构建 `.deb` → 更新 `gh-pages` apt 仓库 → 创建 Release。

```bash
git tag v2.5.12
git push origin v2.5.12
```

本地构建（可选）：

```bash
sudo apt install -y build-essential debhelper dh-python python3-all devscripts
./scripts/build-deb.sh
```
