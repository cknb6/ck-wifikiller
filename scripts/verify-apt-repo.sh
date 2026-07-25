#!/usr/bin/env bash
# 校验线上 apt 仓库是否结构正确、deb 可下载（本机无需 apt）。
set -euo pipefail

BASE="${1:-https://cknb6.github.io/ck-wifikiller}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[*] base: $BASE"

curl -fsSL "$BASE/dists/stable/Release" -o "$TMP/Release"

# 未签名仓库不得存在伪 InRelease（非 PGP clearsign）
code="$(curl -sL -o "$TMP/InRelease.try" -w '%{http_code}' "$BASE/dists/stable/InRelease" || true)"
if [[ "$code" == "200" ]]; then
  if ! head -c 14 "$TMP/InRelease.try" | grep -q 'BEGIN PGP'; then
    echo "[!] FAIL: unsigned pseudo-InRelease present (apt NOSPLIT risk)" >&2
    exit 1
  fi
  echo "[+] InRelease is clearsigned"
else
  echo "[+] no InRelease (OK for trusted=yes unsigned repo) HTTP=$code"
fi

for arch in amd64 arm64 all; do
  curl -fsSL "$BASE/dists/stable/main/binary-${arch}/Packages" -o "$TMP/Packages.$arch"
  if grep -q '^Filename: repo/' "$TMP/Packages.$arch"; then
    echo "[!] FAIL: Packages.$arch still has Filename: repo/..." >&2
    exit 1
  fi
  if ! grep -q '^Filename: pool/' "$TMP/Packages.$arch"; then
    echo "[!] FAIL: Packages.$arch missing Filename: pool/..." >&2
    exit 1
  fi
  echo "[+] Packages $arch Filename OK"
done

# 取最新版本 deb（按 Version 文本排序，简单 V 序）
latest="$(
  awk -F': ' '
    /^Package:/{pkg=$2}
    /^Version:/{ver=$2}
    /^Filename:/{file=$2}
    /^SHA256:/{
      sha=$2
      if (pkg == "ck-wifikiller" && ver != "" && file != "") {
        print ver "\t" file "\t" sha
      }
    }
  ' "$TMP/Packages.amd64" | sort -t$'\t' -k1,1V | tail -1
)"
if [[ -z "$latest" ]]; then
  echo "[!] FAIL: no ck-wifikiller entries" >&2
  exit 1
fi

ver="$(printf '%s' "$latest" | cut -f1)"
file="$(printf '%s' "$latest" | cut -f2)"
sha="$(printf '%s' "$latest" | cut -f3)"
echo "[*] latest: $ver  $file"

curl -fsSL "$BASE/$file" -o "$TMP/pkg.deb"
if command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$TMP/pkg.deb" | awk '{print $1}')"
else
  actual="$(sha256sum "$TMP/pkg.deb" | awk '{print $1}')"
fi
if [[ "$actual" != "$sha" ]]; then
  echo "[!] FAIL: SHA256 mismatch actual=$actual expected=$sha" >&2
  exit 1
fi
if command -v file >/dev/null 2>&1; then
  if ! file "$TMP/pkg.deb" | grep -qi 'Debian binary package'; then
    echo "[!] FAIL: not a deb package" >&2
    exit 1
  fi
fi

echo "[+] deb download + SHA256 OK ($ver)"
echo "[OK] apt repository looks installable with:"
echo "    deb [trusted=yes] $BASE stable main"
