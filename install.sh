#!/bin/bash
set -e

# ExaAiAgent Installation Script
# Supports: bash, zsh, fish

echo "🛡️  Installing ExaAiAgent..."

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGW;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo "✅ Detected OS: ${MACHINE}"

# check python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found."
    exit 1
fi

REPO_URL="git+https://github.com/hleliofficiel/ExaAiAgent.git"

# Install with pipx (recommended) or pip
if command -v pipx &> /dev/null; then
    echo "📦 Installing via pipx..."
    pipx install "$REPO_URL" --force
    INSTALL_METHOD="pipx"
else
    echo "⚠️  pipx not found. Falling back to pip (user install)..."
    pip install "$REPO_URL" --user --break-system-packages
    INSTALL_METHOD="pip"
fi

# PATH Handling
echo "🔧 Configuring PATH..."

SHELL_NAME=$(basename "$SHELL")
RC_FILE=""

case "$SHELL_NAME" in
    bash)
        RC_FILE="$HOME/.bashrc"
        if [ "$MACHINE" == "Mac" ]; then
            RC_FILE="$HOME/.bash_profile"
        fi
        ;;
    zsh)
        RC_FILE="$HOME/.zshrc"
        ;;
    fish)
        RC_FILE="$HOME/.config/fish/config.fish"
        ;;
    *)
        echo "⚠️  Unknown shell: $SHELL_NAME"
        ;;
esac

# Function to add to path if not exists
add_to_path() {
    local PATH_DIR="$1"
    local CONFIG_FILE="$2"

    if [[ ":$PATH:" != *":$PATH_DIR:"* ]]; then
        echo "   Adding $PATH_DIR to $CONFIG_FILE"
        if [ "$SHELL_NAME" == "fish" ]; then
            echo "fish_add_path $PATH_DIR" >> "$CONFIG_FILE"
        else
            echo "export PATH=\"\$PATH:$PATH_DIR\"" >> "$CONFIG_FILE"
        fi
    else
        echo "   $PATH_DIR is already in PATH."
    fi
}

# Add local bin to path
if [ "$INSTALL_METHOD" == "pip" ]; then
    USER_BASE=$(python3 -m site --user-base)
    BIN_DIR="$USER_BASE/bin"
    if [ -n "$RC_FILE" ]; then
        add_to_path "$BIN_DIR" "$RC_FILE"
    fi
fi

echo "✅ Installation complete!"
echo ""
cat << 'BANNER'
   ______  _  _   ____    ____   _____
  |  ____|| || | / __ \  / __ \ |_   _|
  | |__   | || || |  | || |  | |  | |
  |  __|  |__   || |  | || |  | |  | |
  | |____    | || |__| || |__| | _| |_
  |______|   |_| \____/  \____/ |_____|

   Advanced AI-Powered Cybersecurity Agent  ·  v3.1.1
BANNER
echo ""
echo "🎉 Welcome to ExaAiAgent!"
echo ""
echo "Next steps:"
echo "   1. Reload your shell:      source ${RC_FILE}   (or restart the terminal)"
echo "   2. Verify it works:        exaai --version"
echo "   3. Show all options:       exaai --help"
echo "   4. Run your first scan:    exaai --target https://example.com"
echo ""
echo "📖 Full guide: https://github.com/hleliofficiel/ExaAiAgent"
echo ""

# Post-install sanity check (non-fatal)
if command -v exaai &> /dev/null; then
    echo "✅ exaai is on your PATH and ready to use."
else
    echo "ℹ️  exaai is installed but not yet on your PATH in this shell."
    echo "   Open a new terminal or run: source ${RC_FILE}"
fi
echo ""
