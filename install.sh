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

# Install with pipx (recommended) or pip
if command -v pipx &> /dev/null; then
    echo "📦 Installing via pipx..."
    pipx install . --force
    INSTALL_METHOD="pipx"
else
    echo "⚠️  pipx not found. Falling back to pip (user install)..."
    pip install . --user --break-system-packages
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
echo "🎉 To start using ExaAiAgent:"
echo "   1. Restart your terminal OR run: source $RC_FILE"
echo "   2. Run command: exaai --help"
echo ""
