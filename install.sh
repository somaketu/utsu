#!/usr/bin/env bash
# Utsu Framework - Automated Installer

set -e

echo "[*] Initializing Utsu deployment sequence..."

# 1. Dependency Validation
if ! command -v cargo &> /dev/null; then
    echo "[-] FATAL: Rust toolchain not found. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "[-] FATAL: Python3 not found. Please install Python 3.9+."
    exit 1
fi

# 2. Virtual Environment Sandboxing
echo "[*] Cleaning previous state..."
rm -rf venv

echo "[*] Creating isolated Python environment..."
python3 -m venv venv
source venv/bin/activate

# 3. Build Tooling
echo "[*] Installing build orchestration..."
pip install --upgrade pip setuptools wheel maturin --quiet

# 4. Production Compilation
echo "[*] Compiling high-speed Rust core (Release Mode)..."
# We use standard pip installation. Maturin acts as the backend automatically.
pip install . --no-cache-dir

# 5. Global Command Wiring
echo "[*] Wiring global command..."
mkdir -p ~/.local/bin
REPO_DIR=$(pwd)

cat << EOF > ~/.local/bin/utsu
#!/usr/bin/env bash
source "${REPO_DIR}/venv/bin/activate"
exec "${REPO_DIR}/venv/bin/utsu" "\$@"
EOF

chmod +x ~/.local/bin/utsu

echo ""
echo "[+] Deployment successful."
echo "[+] The 'utsu' command is now globally available."
echo "[!] Note: If the command is not found, ensure ~/.local/bin is in your system PATH."