#!/usr/bin/env bash
set -euo pipefail

# One-liner installer for Kali/Ubuntu-like
#   curl -fsSL https://raw.githubusercontent.com/<your-user>/socguard/main/install.sh | bash

echo "[*] Installing SOCguard prerequisites..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip pipx

echo "[*] Ensuring pipx is in PATH..."
export PIPX_BIN_DIR="${HOME}/.local/bin"
python3 -m pipx ensurepath >/dev/null 2>&1 || true
export PATH="${PIPX_BIN_DIR}:${PATH}"

echo "[*] Installing SOCguard from GitHub..."
pipx install "git+https://github.com/<your-user>/socguard.git@main"

echo "[*] Done. Try: socguard --help"
