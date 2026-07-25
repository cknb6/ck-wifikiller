# ck-wifikiller apt repository

Apt repo populated by GitHub Actions on tag push.

Usage:
```
echo "deb [trusted=yes] https://cknb6.github.io/ck-wifikiller stable main" | sudo tee /etc/apt/sources.list.d/ck-wifikiller.list
sudo apt update && sudo apt install ck-wifikiller
```
