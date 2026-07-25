#!/bin/bash
# 在 Debian/Kali 上构建 .deb
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
chmod +x debian/rules
dpkg-buildpackage -us -uc -b
echo "Built packages in parent dir: $ROOT/../ck-wifikiller_*.deb"
