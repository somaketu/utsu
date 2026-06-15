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