#!/bin/bash

# EmailDawg Bridge Setup Script
set -euo pipefail

echo "🐕 EmailDawg Bridge Setup"
echo "========================="

# Check if running on macOS and install libolm if needed
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📦 Checking for libolm..."
    if ! brew list libolm >/dev/null 2>&1; then
        echo "Installing libolm via Homebrew..."
        brew install libolm
    else
        echo "✅ libolm already installed"
    fi
fi

# Build the bridge
echo "🔨 Building EmailDawg bridge..."
make build

if [ ! -f mautrix-emaildawg ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful!"

# Check if bbctl is available
if ! command -v bbctl &> /dev/null; then
    echo "❌ bbctl not found. Please install Beeper bridge manager."
    echo "   Visit: https://github.com/beeper/bridge-manager"
    exit 1
fi

echo "✅ bbctl found"

# Generate config skeleton via Bridge Manager (bbctl)
mkdir -p ./data
echo "📝 Generating bridgev2 config skeleton to ./data/config.yaml..."
bbctl config --type bridgev2 --output ./data/config.yaml

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Register bridge: bbctl register --output registration.yaml sh-emaildawg"  
echo "2. Edit ./data/config.yaml with your homeserver details"
echo "3. Start bridge: ./mautrix-emaildawg --config ./data/config.yaml"
echo ""
echo "For Beeper users:"
echo "• Use homeserver address: https://matrix.beeper.com/_hungryserv/YOUR_USERNAME"
echo "• Use domain: beeper.local" 
echo "• Enable websockets and encryption"
echo ""
echo "Documentation: https://github.com/iFixRobots/emaildawg"
