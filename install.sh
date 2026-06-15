#!/usr/bin/env bash
# Utsu Framework - Automated Production Installer

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

# 2. Virtual Environment Sandboxing (Enforce clean state)
echo "[*] Cleaning previous state..."
rm -rf venv

echo "[*] Creating isolated Python environment..."
python3 -m venv venv
source venv/bin/activate

# 3. Build Tooling
echo "[*] Installing build orchestration..."
pip install --upgrade pip setuptools wheel maturin --quiet

# 4. Production Compilation (Stable ABI target)
echo "[*] Compiling high-speed Rust core (Release Mode)..."
pip install -e .[dev] --no-cache-dir

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

# 6. Automated PATH Detection and Injection
DETECTED_SHELL=$(basename "$SHELL")
CONFIG_FILE=""

if [ "$DETECTED_SHELL" = "zsh" ]; then
    CONFIG_FILE="$HOME/.zshrc"
elif [ "$DETECTED_SHELL" = "bash" ]; then
    if [ -f "$HOME/.bash_profile" ]; then
        CONFIG_FILE="$HOME/.bash_profile"
    else
        CONFIG_FILE="$HOME/.bashrc"
    fi
fi

echo ""
echo "[+] Deployment successful."

# Check if ~/.local/bin is already active in the host PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        echo "[*] Environment anomaly: ~/.local/bin is missing from your PATH."
        echo "[*] Automatically patching $CONFIG_FILE..."
        
        # Append via a clean, literal multi-line block
        cat << 'EOF' >> "$CONFIG_FILE"

# Utsu Framework Binary Path
export PATH="$HOME/.local/bin:$PATH"
EOF
        
        echo "[+] Patch applied successfully."
        echo "[!] ACTION REQUIRED: Run 'source $CONFIG_FILE' or restart your terminal to activate the 'utsu' command."
    else
        echo "[!] WARNING: ~/.local/bin is not in your PATH. Please add it manually to your shell profile."
    fi
else
    echo "[+] The 'utsu' command is globally active and ready."
fi