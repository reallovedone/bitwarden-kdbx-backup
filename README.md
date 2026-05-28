# bitwarden-kdbx-backup

Backs up your Bitwarden/[Vaultwarden](https://github.com/dani-garcia/vaultwarden) vault — personal items and all organizations — into a single encrypted [KeePass](https://keepass.info/) `.kdbx` file.

Runs as a single long-lived Docker container with a built-in cron scheduler and an always-on web setup UI.

The KeePass file mirrors your Bitwarden structure: personal folders become KeePass groups, and organization collections become subgroups. Nested paths (e.g. `Work/Company/VMs`) are preserved.

## What it does

- Exports personal vault and all organizations using the Bitwarden CLI
- Supports item types: Login, Card, Identity, Secure Note — including custom fields
- Produces a single `.kdbx` file (AES-256, compatible with KeePass 2, KeePassXC, Strongbox, etc.)
- Built-in cron scheduler — no external scheduler needed
- Always-on setup UI on port 8080 — reconfigure without restarting
- Notifications via [Apprise](https://github.com/caronc/apprise) (100+ services: Telegram, Slack, Discord, ntfy, email, and more)
- Optionally uploads the `.kdbx` to any WebDAV server (Nextcloud, etc.)
- Runs as a non-root container

## Requirements

- Docker ≥ 24 with Compose v2
- A Bitwarden or Vaultwarden instance with API access enabled
- A Bitwarden API key — find it under **Settings → Security → Keys → API Key**

## Getting started

```bash
git clone https://github.com/reallovedone/bitwarden-kdbx-backup.git
cd bitwarden-kdbx-backup

mkdir -p config backups
docker compose up -d
```

The container starts immediately. Open the setup UI at:

```
http://localhost:8080/?token=<token printed in docker logs>
```

Check logs for the token:

```bash
docker logs bitwarden-kdbx-backup
```

Fill in the form, click **Save** — the container picks up the config on the next scheduled run (no restart needed).

### Manual `.env` / environment variable override

All config values can be set via environment variables. They override `config.toml`.

| Variable | Overrides |
|---|---|
| `BW_URL` | `bitwarden.url` |
| `BW_CLIENTID` | `bitwarden.client_id` |
| `BW_CLIENTSECRET` | `bitwarden.client_secret` |
| `BW_MASTER_PASSWORD` | `bitwarden.master_password` |
| `KEEPASS_PASSWORD` | `keepass.password` |
| `BACKUP_OUTPUT_DIR` | `keepass.output_dir` |
| `BACKUP_SCHEDULE` | `schedule.cron` |
| `TZ` | `schedule.timezone` |
| `NOTIFY_URLS` | `notify.urls` (comma-separated) |
| `WEBDAV_URL` | `webdav.url` |

### Manual config file

Copy `config.example.toml` to `./config/config.toml` and edit it directly:

```bash
cp config.example.toml config/config.toml
```

## Configuration reference

| Field | Required | Default | Description |
|---|---|---|---|
| `bitwarden.url` | ✅ | — | Bitwarden / Vaultwarden URL |
| `bitwarden.client_id` | ✅ | — | API key `client_id` |
| `bitwarden.client_secret` | ✅ | — | API key `client_secret` |
| `bitwarden.master_password` | ✅ | — | Master password |
| `keepass.password` | ✅ | — | Password for the output `.kdbx` file |
| `keepass.output_dir` | — | `/backups` | Output path inside container |
| `schedule.cron` | — | `0 2 * * *` | Cron expression |
| `schedule.timezone` | — | `UTC` | Timezone for cron |
| `notify.urls` | — | `[]` | Apprise notification URLs |
| `webdav.url` | — | `""` | WebDAV URL with embedded credentials |

### Schedule examples

```
0 2 * * *     daily at 02:00 (default)
0 */6 * * *   every 6 hours
30 3 * * 1    every Monday at 03:30
```

Use [crontab.guru](https://crontab.guru) to build expressions.

## Notifications

Set `notify.urls` (or `NOTIFY_URLS`) to one or more [Apprise](https://github.com/caronc/apprise/wiki) URLs, comma-separated or one per line in the UI. Leave empty to disable.

| Service | URL format |
|---|---|
| Telegram | `tgram://BOT_TOKEN/CHAT_ID` |
| Slack | `slack://TOKEN_A/TOKEN_B/TOKEN_C/CHANNEL` |
| Discord | `discord://WEBHOOK_ID/WEBHOOK_TOKEN` |
| ntfy | `ntfy://hostname/topic` |
| Gotify | `gotify://hostname/token` |
| Email | `mailto://user:password@gmail.com` |
| Generic webhook | `json://hostname/path` |

Full list: [github.com/caronc/apprise/wiki](https://github.com/caronc/apprise/wiki)

**Telegram setup:** message `@BotFather` to create a bot → get `BOT_TOKEN`. Message `@userinfobot` → get `CHAT_ID`.

## Backup storage

**Local (always active):** backups are saved to `./backups/` in your project directory. The folder is created automatically. To change the host path, edit the `volumes:` section in `docker-compose.yml`:

```yaml
volumes:
  - /your/custom/path:/backups
  - ./config:/config
```

**Remote (optional):** after each backup, the `.kdbx` is also uploaded to a WebDAV server. Embed credentials in the URL:

```toml
[webdav]
url = "https://user:apptoken@nextcloud.example.com/remote.php/dav/files/user/Backups/"
```

For Nextcloud, generate a dedicated **App Password** under **Settings → Security → Devices & sessions**. Both local and remote storage happen simultaneously.

## Building locally

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml up
```

## One-shot and dry run

Run one backup immediately without waiting for the cron schedule:

```bash
docker compose run --rm bw-backup --run-now
```

Count items without writing any file:

```bash
docker compose run --rm bw-backup --dry-run
```

## Security

**Port 8080 — setup UI**

> **Warning:** The setup UI runs over plain HTTP. Do not expose port 8080 to the internet or untrusted networks — credentials submitted via the form would be visible to anyone on the path.

For local use (recommended): bind only to localhost in `docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:8080:8080"
```

For remote access: place a reverse proxy (Nginx, Caddy, Traefik) with HTTPS + HTTP Basic Auth in front. Never expose port 8080 directly.

**Other security properties:**

- `config.toml` is written with permissions `0600` (owner-read only) and never committed — keep `./config/` in `.gitignore`
- `.kdbx` files are created and written with permissions `0600`
- Setup UI token: 256-bit random (`secrets.token_urlsafe(32)`), regenerated on each container start, constant-time comparison
- Token is in the URL for GET requests (browser history) but **not** in POST requests (submitted in hidden form field)
- Credentials are never passed as CLI arguments — only via subprocess environment variables
- Session tokens from `bw unlock` are never logged
- WebDAV credentials are stripped from log output
- Container runs as non-root (`appuser`) with no login shell

**Verifying the Bitwarden CLI binary (recommended for production):**

The Dockerfile accepts a `BW_CLI_SHA256` build arg. Find the checksum on the [Bitwarden CLI releases page](https://github.com/bitwarden/clients/releases), then build with:

```bash
docker compose -f docker-compose.dev.yml build \
  --build-arg BW_CLI_VERSION=2026.1.0 \
  --build-arg BW_CLI_SHA256=<sha256_from_release_page>
```

The build will fail if the checksum does not match. Leave `BW_CLI_SHA256` empty to skip verification (default).

## License

MIT — see [LICENSE](LICENSE).
