# mautrix-emaildawg

A Matrix-Email puppeting bridge based on the mautrix bridgev2 framework.

## Status

✅ **Production Ready:**
- Email login with auto-provider detection
- IMAP message processing with attachments
- Email threading and participant management
- Matrix room creation with proper permissions
- Smart participant change notifications
- Bridge manager integration complete
- Docker deployment ready
- Full CLI interface implemented

## Features

### ✅ Core Features
- **Advanced Login Flow** - Super easy email setup with provider detection
- **Attachment Support** - Full email attachment handling (images, files, etc.)
- **Smart Threading** - Proper email thread → Matrix room mapping
- **Participant Management** - CC/BCC users become Matrix ghosts with join/leave notifications
- **Provider Auto-Detection** - Gmail, Yahoo, Outlook, iCloud support with App Password guidance
- **Read-Only Matrix Rooms** - Only bridge can send messages, users see email content
- **IMAP IDLE** - Real-time email delivery
- **Registration Generation** - Automated via CLI commands
- **Bridge Management** - Full CLI interface with all standard commands
- **Docker Support** - Ready-to-deploy containers

## Architecture

This bridge follows the modern mautrix bridgev2 architecture:

- **Built in Go** using the mautrix bridgev2 framework
- **Compatible with bridge manager** for easy deployment on Beeper
- **Uses IMAP IDLE** for real-time email delivery
- **One email thread = one Matrix room**
- **Email participants become Matrix room ghosts**
- **Comprehensive attachment handling**
- **Smart participant change tracking**

## Quick Start

### Option 1: One-Command Setup (Easiest)
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
./setup.sh
```
This automatically installs dependencies, builds with encryption, and shows next steps.

### Option 2: Bridge Manager (Ready for Integration!)
```bash
bbctl register emaildawg https://github.com/iFixRobots/emaildawg
bbctl run emaildawg
```

### Option 2: Docker Compose (Fully Working)
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
./mautrix-emaildawg --generate-example-config
./mautrix-emaildawg --generate-registration
# Edit config.yaml with your Matrix homeserver details
docker-compose up -d
```

### Option 3: Manual Build (Tested)

#### Prerequisites
- Go 1.21+
- **libolm** (for end-to-end encryption support)
- Matrix homeserver with admin access

#### Install libolm
**macOS (Homebrew):**
```bash
brew install libolm
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install libolm-dev build-essential
```

**Linux (Fedora):**
```bash
sudo dnf install libolm-devel gcc
```

**Linux (Arch):**
```bash
sudo pacman -S libolm base-devel
```

#### Build & Setup
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
make build
./mautrix-emaildawg --generate-example-config
./mautrix-emaildawg --generate-registration
# Edit config.yaml with your homeserver details
# Register registration.yaml with your Matrix homeserver
./mautrix-emaildawg
```

## Configuration

### Initial Setup
1. **Generate configuration:** `./mautrix-emaildawg --generate-example-config`
2. **Edit homeserver settings** in config.yaml
3. **Generate registration:** `./mautrix-emaildawg --generate-registration`
4. **Register with Matrix homeserver** (add registration.yaml to homeserver config)
5. **Start bridge**

### User Commands
After bridge is running, users can DM the bridge bot:

- `!email login` - Add an email account (guided setup)
- `!email list` - List configured accounts  
- `!email logout` - Remove email accounts
- `!email status` - Show connection status
- `!email ping` - Test bridge connection

## Email Provider Support

### ✅ Auto-Configured Providers
- **Gmail** (gmail.com) - App Password required
- **Yahoo** (yahoo.com) - App Password required  
- **Outlook/Hotmail** (outlook.com, hotmail.com) - App Password required
- **iCloud** (icloud.com, me.com) - App Password required
- **Custom IMAP** - Auto-detected settings

### App Password Setup
The bridge provides automatic guidance for setting up App Passwords:
- **Gmail:** Settings → Security → 2-Step Verification → App passwords
- **Yahoo:** Account Info → Account security → Generate app password
- **Outlook:** Security → Sign-in options → App passwords

## How it works

1. **Email threads** → Matrix rooms (1:1 mapping)
2. **Real-time delivery** via IMAP IDLE  
3. **Participants** synced from To/CC/BCC headers
4. **Threading** uses Message-ID/References/In-Reply-To
5. **Rooms are read-only** for Matrix users (bridge-only messaging)
6. **Attachments** uploaded to Matrix media repository
7. **Participant changes** show as timeline notifications
8. **Smart error handling** with provider-specific troubleshooting

## License

AGPL-3.0
