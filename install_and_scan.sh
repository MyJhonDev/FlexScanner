#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "Preparando o FlexScanner..."
pkg update -y
pkg install -y python coreutils apksigner

if [ ! -d "$HOME/storage/shared" ]; then
    echo
    echo "O Android vai pedir permissão para o Termux acessar os arquivos."
    echo "Permita o acesso e volte para o Termux."
    termux-setup-storage || true
fi

echo
echo "Iniciando varredura..."
bash "$PROJECT_DIR/scan.sh"
