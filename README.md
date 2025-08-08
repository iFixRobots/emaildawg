# emaildawg

A Matrix–Email bridge built on mautrix bridgev2. Focused on reliable email consumption in Matrix rooms (not chat features).

## Status

This project is usable and under active development. Core features work and the bridge is suitable for personal use and small deployments.

## Features

- Email login with provider auto-detection
- IMAP processing with attachments
- Email threading and participant mapping
- Matrix room creation with read-only policy for users
- Participant change notices (join/leave based on headers)
- Docker and Bridge Manager support

## Architecture

- Implemented in Go using the mautrix bridgev2 framework
- One email thread maps to one Matrix room
- Participants (To/CC/BCC) are represented as Matrix ghost users
- Attachments are uploaded to the homeserver media repo

## Quick start

### One-command setup
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
./setup.sh
```

### Bridge Manager
```bash
bbctl register sh-emaildawg https://github.com/iFixRobots/emaildawg
bbctl run sh-emaildawg
```

### Docker Compose
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
./emaildawg --generate-example-config
./emaildawg --generate-registration
# Edit config.yaml with your Matrix homeserver details
# IMPORTANT: The default SQLite DB URI is file:./data/emaildawg.db; ensure ./data exists and is writable.
mkdir -p ./data
docker-compose up -d
```

### Manual build

Prerequisites:
- Go 1.21+
- libolm (for end-to-end encryption)
- Matrix homeserver access

Install libolm on macOS (Homebrew):
```bash
brew install libolm
```

On Ubuntu/Debian:
```bash
sudo apt install libolm-dev build-essential
```

On Fedora:
```bash
sudo dnf install libolm-devel gcc
```

On Arch:
```bash
sudo pacman -S libolm base-devel
```

Build and run:
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
make build
./emaildawg --generate-example-config
./emaildawg --generate-registration
# Edit config.yaml with your homeserver details
# Register registration.yaml with your Matrix homeserver
./emaildawg
```

## Configuration

Initial setup:
1. Generate configuration: `./emaildawg --generate-example-config`
2. Edit homeserver settings in config.yaml
3. Generate registration: `./emaildawg --generate-registration`
4. Register with your homeserver (add registration.yaml to the homeserver config)
5. Start the bridge

User commands (send in DM to the bot):
- `!email login` — Add an email account (guided)
- `!email list` — List configured accounts
- `!email logout` — Remove an account
- `!email status` — Show connection status
- `!email ping` — Health check

## Email provider support

Auto-configured providers:
- Gmail (app password)
- Yahoo (app password)
- Outlook/Hotmail (app password)
- iCloud (app password)
- Custom IMAP (auto-detected settings)

App password setup guidance is provided during login.

## How it works

1. Threads map to rooms.
2. Real-time delivery via IMAP IDLE.
3. Participants come from To/CC/BCC.
4. Threading uses Message-ID, References, and In-Reply-To.
5. Rooms are read-only for users (bridge posts messages).
6. Attachments are uploaded to Matrix media.
7. Participant changes are posted as notices.

## License

AGPL-3.0-or-later. See LICENSE.

Portions derived from mautrix-whatsapp (AGPL-3.0-or-later) by Tulir Asokan and contributors.
