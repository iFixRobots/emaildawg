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

### One-command setup (Bridge Manager)
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
./setup.sh
```
This script builds the bridge and generates a Bridge Manager config at ./data/config.yaml via `bbctl`.

### Bridge Manager (manual)
```bash
bbctl register sh-emaildawg https://github.com/iFixRobots/emaildawg
bbctl run sh-emaildawg
```

### Docker Compose
Recommended when running with SQLite (default). The image runs as a non-root user and writes to /home/nonroot/app/data inside the container (mapped to a named volume by compose).

```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
# Generate config and registration in the project root
make build
./emaildawg --generate-example-config
./emaildawg --generate-registration
# Edit config.yaml with your Matrix homeserver details
# Note: The default SQLite DB path is file:./data/emaildawg.db (inside the container).
# docker-compose creates a named volume mounted at /home/nonroot/app/data automatically.

docker-compose up -d
```

Notes:
- Config path: docker-compose mounts ./config.yaml into /opt/emaildawg/config.yaml and sets MAUTRIX_CONFIG_PATH accordingly.
- Data path: no need to create ./data on the host. The container writes to /home/nonroot/app/data, a volume owned by the nonroot user.
- Postgres: optional. By default, the bridge uses SQLite. The compose file includes a Postgres service as an example only.

### Manual build (host)

Prerequisites:
- Go 1.22+
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

Deployment-specific paths:
- Docker Compose: place config.yaml and registration.yaml in the project root; compose mounts them read-only into the container.
- Bridge Manager: setup.sh/`bbctl` writes ./data/config.yaml by default; follow bbctl’s guidance to run.

### Database configuration (IMPORTANT)
The bridge needs a persistent database path. If you use SQLite (default), set the database URI to the data folder used by your deployment mode.

Docker Compose (distroless nonroot):
```yaml
# config.yaml (bridgev2)
database:
  type: sqlite3
  uri: "file:/home/nonroot/app/data/emaildawg.db?_fk=1"
```

Host/manual (runs in repo working directory):
```yaml
# config.yaml (bridgev2)
database:
  type: sqlite3
  uri: "file:./data/emaildawg.db?_fk=1"
```

Notes:
- The container data directory is /home/nonroot/app/data (a named volume). Do not point the URI to /opt/emaildawg.
- The host data directory is ./data. Ensure it exists and is writable.
- For Postgres, set type: postgres and provide a proper DSN instead of sqlite3.

## Security and runtime notes
- Never build or run with nocrypto. libolm is required for proper E2EE support.
- The Docker image runs as a non-root user; data directory permissions are handled by the image and compose volume mapping.

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
