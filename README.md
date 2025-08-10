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

You can run EmailDawg in two supported ways. Pick one and follow it end-to-end.

### A) With Beeper Bridge Manager (recommended for Beeper)
Prerequisites:
- bbctl installed and logged in: `bbctl login`
- Go 1.22+ and libolm installed (for building this bridge)

Steps:
```bash
# Get the source and build
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
./setup.sh

# Edit the generated config if needed
sed -n '1,160p' ./data/config.yaml

# Run the bridge using the local binary and the bbctl-generated config
./emaildawg --config ./data/config.yaml
```
Notes:
- setup.sh builds the bridge and generates a bridgev2 config at ./data/config.yaml using `bbctl config` so it matches Bridge Manager conventions (hungry websocket, encryption defaults, double puppeting secrets, etc.).
- No registration.yaml is required when using Beeper’s appservice websocket (the default in the generated config).
- To run the bridge under a process manager, point it to `./emaildawg --config ./data/config.yaml`.
- bbctl is only used to generate the config and manage Beeper auth. It does not run this bridge; start it yourself using the local binary or Docker.
- Important: Use the generic bridgev2 template with a custom bridge name. Run `bbctl config --type bridgev2 --output ./data/config.yaml sh-emaildawg-local`. Do not use a per-bridge name unless it’s officially supported by your bbctl build.

### B) Standalone (no Bridge Manager)
Prerequisites:
- Go 1.22+
- libolm
- A Matrix homeserver you control (standard mode) or Beeper hungryserv (websocket mode)

Steps:
```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
make build
./emaildawg --generate-example-config
# Edit config.yaml with your homeserver details
# If you are using a standard homeserver over HTTP appservice:
#   ./emaildawg --generate-registration
#   Add registration.yaml to your homeserver and set appservice -> address/hostname/port accordingly.
./emaildawg
```

### C) Docker Compose (standalone)
Use this if you want to run the compiled image with SQLite (default). This flow does not use Bridge Manager.

```bash
git clone https://github.com/iFixRobots/emaildawg
cd emaildawg
make build
./emaildawg --generate-example-config
# Edit config.yaml, especially database.uri for container path (see below)

docker-compose up -d
```

Notes:
- Config path: docker-compose mounts ./config.yaml into /opt/emaildawg/config.yaml and sets MAUTRIX_CONFIG_PATH accordingly.
- Registration: NOT needed when using websocket mode. Only generate and mount registration.yaml if you run in HTTP appservice mode on a standard homeserver.
- Data path: The container writes to /home/nonroot/app/data, a volume owned by the nonroot user. No need to create ./data on the host.
- Postgres: optional. The compose file focuses on SQLite. Add Postgres yourself if desired.

## Configuration

Initial setup (summary):
1. Generate a config (with setup.sh via Bridge Manager or with `--generate-example-config`).
2. Edit homeserver settings in config.yaml.
3. If using a standard homeserver over HTTP appservice, generate and register registration.yaml with your homeserver.
4. Start the bridge.

User commands (send in DM to the bot):
- `!email login` — Add an email account (guided)
- `!email list` — List configured accounts
- `!email logout` — Remove an account
- `!email status` — Show connection status
- `!email ping` — Health check

Deployment-specific paths:
- Docker Compose: place config.yaml in the project root; compose mounts it read-only into the container. registration.yaml is only needed for HTTP appservice mode.
- Bridge Manager: setup.sh writes ./data/config.yaml; run the binary with `--config ./data/config.yaml`.

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
