# emaildawg

A Matrix–Email bridge built on mautrix bridgev2. Focused on reliable email consumption in Matrix rooms (not chat features).

## Status

This project is usable and under active development. Core features work and the bridge is suitable for personal use and small deployments.

## What this bridge does for you

- **Easy setup:** Just give it your email and password (or app password) and it figures out the server settings
- **Real-time email delivery:** New emails show up in Matrix immediately - no waiting or manual syncing
- **Handles attachments:** Photos, PDFs, documents all get uploaded to Matrix automatically  
- **Smart conversation threading:** Emails in the same thread become one Matrix room
- **Monitors both folders:** Watches your inbox AND sent folder, so you see both sides of conversations
- **Reliable connections:** Automatically reconnects if your internet hiccups or email server has issues
- **Cleans up messy emails:** Filters out tracking pixels and tiny placeholder images that clutter your conversations
- **Secure storage:** Your email credentials are encrypted on your machine
- **Read-only Matrix rooms:** Other Matrix users can see the emails but can't accidentally send replies through the bridge

## Architecture

- Implemented in Go using the mautrix bridgev2 framework
- One email thread maps to one Matrix room
- Participants (To/CC/BCC) are represented as Matrix ghost users
- Attachments are uploaded to the homeserver media repo

## Quick start

You can run EmailDawg in two supported ways. Pick one and follow it end-to-end.

### A) With Beeper Bridge Manager (recommended for Beeper users)

This is the easiest way if you're already using Beeper's bridge system.

**What you need first:**
- Beeper Bridge Manager installed and logged in: `bbctl login`
- Go 1.22+ and libolm on your system

**Step-by-step setup:**

1. **Get the code and run setup:**
   ```bash
   git clone https://github.com/iFixRobots/emaildawg
   cd emaildawg
   ./setup.sh
   ```
   
2. **What setup.sh does:**
   - Installs libolm if you're on macOS and don't have it
   - Builds the bridge binary (creates `./emaildawg`)
   - Creates a `./data/` folder in your project directory
   - Asks you for a bridge name (just pick something like `my-email-bridge` - this is NOT your email address)
   - Uses bbctl to generate `./data/config.yaml` with Beeper's websocket settings

3. **Important: setup.sh does NOT configure your email accounts**
   The config file it creates connects to Beeper's infrastructure, but you'll add your actual email accounts later using bot commands.

4. **Start the bridge:**
   ```bash
   ./emaildawg --config ./data/config.yaml
   ```

5. **Add your email account:**
   - Find the bot in your Matrix client
   - Send it: `!email login`
   - Follow the guided setup for your Gmail/Yahoo/Outlook account

**Where things are stored:**
- **Config file:** `./data/config.yaml` (in your emaildawg folder)
- **Database:** `./data/emaildawg.db` (created when you first add an email account)
- **Logs:** `./logs/bridge.log` (created when the bridge starts)

**If something goes wrong:**
- Check the logs in your emaildawg folder at `./logs/bridge.log`
- Make sure bbctl is logged in: `bbctl whoami`
- The bridge name you picked doesn't matter - it's just an identifier for bbctl

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

## Using the Bridge

Once your bridge is running, send these commands in a DM to the bot:

### Getting Started
- `!email login` — Connect your email account (walks you through the setup)
- `!email login email:you@gmail.com password:yourapppassword` — Quick setup if you know your details
- `!email help` — Show available commands and help

### Managing Your Accounts  
- `!email list` — See all your connected email accounts and their status
- `!email logout` — Disconnect all email accounts
- `!email logout you@gmail.com` — Disconnect just one specific account
- `!email status` — Check if everything's working (connection health, monitoring status)

### Troubleshooting
- `!email sync` — Force check for new emails on all accounts
- `!email sync you@gmail.com` — Force sync just one account
- `!email reconnect` — Fix connection issues for all accounts
- `!email reconnect you@gmail.com` — Reconnect just one account
- `!email ping` — Basic bridge health check

### Advanced
- `!email passphrase` — Manage the password that encrypts your email credentials
- `!email passphrase generate` — Create a new secure encryption password

Deployment-specific paths:
- Docker Compose: place config.yaml in the project root; compose mounts it read-only into the container. registration.yaml is only needed for HTTP appservice mode.
- Bridge Manager: setup.sh writes ./data/config.yaml; run the binary with `--config ./data/config.yaml`.

### Database setup (where your data gets stored)

The bridge needs somewhere to store your email account info and message history. Most people can use the default SQLite setup.

**If you used setup.sh (Bridge Manager setup):**
Your config is already set up correctly. The database will be created at `./data/emaildawg.db` in your emaildawg folder.

**If you're doing Docker Compose:**
Use this in your config.yaml:
```yaml
database:
  type: sqlite3
  uri: "file:/home/nonroot/app/data/emaildawg.db?_fk=1"
```
This tells the bridge to store data in the Docker volume we set up.

**If you're running manually without Bridge Manager:**
Use this in your config.yaml:
```yaml
database:
  type: sqlite3
  uri: "file:./data/emaildawg.db?_fk=1"
```
This creates the database file in a `data` folder next to your bridge.

**Want to use PostgreSQL instead?**
```yaml
database:
  type: postgres
  uri: "postgresql://username:password@localhost/emaildawg_db?sslmode=require"
```
Replace the connection details with your actual Postgres server info.

## Security and runtime notes
- Never build or run with nocrypto. libolm is required for proper E2EE support.
- The Docker image runs as a non-root user; data directory permissions are handled by the image and compose volume mapping.

## Email provider support

The bridge automatically detects and configures settings for these providers:

### Major Providers (App Password Required)
- **Gmail:** gmail.com, googlemail.com  
- **Yahoo:** yahoo.com, yahoo.co.uk, yahoo.fr, yahoo.de
- **Microsoft:** outlook.com, hotmail.com, live.com, msn.com
- **Apple iCloud:** icloud.com, me.com, mac.com

### Other Supported Providers
- **FastMail:** fastmail.com

### Unknown Providers
For email providers not in the list above, the bridge will:
- Try to auto-detect your IMAP settings (usually works)
- Show you exactly what server it's trying to connect to
- Give helpful troubleshooting tips if the connection fails
- Suggest common IMAP server patterns your provider might use

**About App Passwords:**
Most major email providers require you to generate a special "App Password" instead of using your regular login password. The bridge will guide you through this during setup and provide links to the right settings pages.

**The bridge tells you what's happening:**
- When it recognizes your email provider and uses optimized settings
- When it's trying to auto-detect settings for an unknown provider
- Exactly which server and port it's attempting to connect to

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
