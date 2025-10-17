#!/usr/bin/env bash
set -euo pipefail

# Quick local Debian package build using python -m build + stdeb or dh (simple route: build wheel and make deb using fpm)
# Requires: sudo apt install ruby-dev rubygems build-essential && sudo gem install --no-document fpm

PKGNAME=socguard
VERSION=$(grep -m1 __version__ src/socguard/version.py | cut -d'"' -f2)

echo "[*] Building wheel..."
python3 -m pip install --upgrade build >/dev/null
python3 -m build

WHEEL=$(ls -1 dist/${PKGNAME}-${VERSION}-*.whl | head -n1)
if [ -z "$WHEEL" ]; then
  echo "Wheel not found"; exit 1
fi

echo "[*] Building .deb with fpm..."
fpm -s python -t deb "${WHEEL}" --deb-no-default-config-files \
  --name "${PKGNAME}" --version "${VERSION}" \
  --description "SOCguard: Remote Windows log collection orchestrator" \
  --license MIT --maintainer "you@example.com" --url "https://github.com/<your-user>/socguard"

echo ""
echo "[*] Install with:"
echo "    sudo apt install ./${PKGNAME}_${VERSION}_all.deb"
