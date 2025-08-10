#!/bin/bash

# EmailDawg Bridge Setup Script
set -euo pipefail

echo "🐕 EmailDawg Bridge Setup"
echo "========================="

# Check if running on macOS and install libolm if needed
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📦 Checking for libolm..."
    if ! brew list libolm > /dev/null 2>&1; then
        echo "Installing libolm via Homebrew..."
        brew install libolm
    else
        echo "✅ libolm already installed"
    fi
fi

# Build the bridge
echo "🔨 Building EmailDawg bridge..."
make build

if [ ! -f emaildawg ]; then
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

# Ask for a bridge name (required by bbctl). Use a safe default if empty.
read -r -p "Enter a bridge name to use with bbctl (e.g., sh-emaildawg-local): " BRIDGE_NAME
BRIDGE_NAME=${BRIDGE_NAME:-sh-emaildawg-local}

echo "📝 Generating bridgev2 config for ${BRIDGE_NAME} to ./data/config.yaml..."
# Use the generic bridgev2 template with a custom name. Do not rely on a per-bridge template.
bbctl config --type bridgev2 --output ./data/config.yaml "$BRIDGE_NAME"

cat <<'EONOTE'

🎉 Setup complete!

Next steps:
1) Edit ./data/config.yaml if needed.
   - The generated config uses Beeper websocket mode and includes double puppeting defaults.
   - SQLite DB path defaults to ./data/ relative to where you run the binary.
2) Start the bridge:
   ./emaildawg --config ./data/config.yaml

Notes:
- In Beeper websocket mode, a registration.yaml is NOT required.
- If you plan to run against a standard homeserver via HTTP appservice,
  generate a registration with:
    ./emaildawg --generate-registration
  and add it to your homeserver config.
EONOTE

echo "Documentation: https://github.com/iFixRobots/emaildawg"
