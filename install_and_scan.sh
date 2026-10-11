#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "Installing scanner dependencies..."
pkg update -y
pkg install -y python coreutils apksigner

if [ ! -d "$HOME/storage/shared" ]; then
    echo
    echo "Android will be asked to grant Termux access to shared storage."
    echo "Grant the permission, then return to Termux."
    termux-setup-storage || true
fi

echo
echo "Starting read-only scan..."
bash "$PROJECT_DIR/scan.sh"
