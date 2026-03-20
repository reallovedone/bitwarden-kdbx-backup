# bitwarden-kdbx-backup

Backs up your Bitwarden/[Vaultwarden](https://github.com/dani-garcia/vaultwarden) vault — personal items and all organizations — into a single encrypted [KeePass](https://keepass.info/) `.kdbx` file. Runs as a one-shot Docker container, optionally scheduled via [Ofelia](https://github.com/mcuadros/ofelia).

The KeePass file mirrors your Bitwarden structure: personal folders become KeePass groups, and organization collections become subgroups. Nested paths (e.g. `Work/Company/VMs`) are preserved.

## What it does

- Exports personal vault and all organizations using the Bitwarden CLI
- Supports item types: Login, Card, Identity, Secure Note — including custom fields
- Produces a single `.kdbx` file (AES-256, compatible with KeePass 2, KeePassXC, Strongbox, etc.)
- Sends a success/failure notification via webhook or email (both optional)
- Runs as a non-root container, no ports exposed

## Requirements

- Docker ≥ 24 with Compose v2
- A Bitwarden or Vaultwarden instance with API access enabled
- A Bitwarden API key — find it under **Settings → Security → Keys → API Key**

## Getting started

```bash
git clone https://github.com/reallovedone/bitwarden-kdbx-backup.git
cd bitwarden-kdbx-backup

cp env.example .env
# edit .env with your credentials

mkdir -p backups
docker compose run --rm bw-backup
```

The backup will be saved as `./backups/bitwarden_YYYYMMDD_HHMMSS.kdbx`.

To run on a schedule (default: every day at 02:00):

```bash
docker compose up -d ofelia
```

## Configuration

Copy `env.example` to `.env` and fill in the required values.

| Variable | Required | Description |
|---|---|---|
| `BW_URL` | ✅ | Your Bitwarden / Vaultwarden URL (e.g. `https://vault.example.com`) |
| `BW_CLIENTID` | ✅ | API key `client_id` |
| `BW_CLIENTSECRET` | ✅ | API key `client_secret` |
| `BW_MASTER_PASSWORD` | ✅ | Master password (needed to unlock after API key login) |
| `KEEPASS_PASSWORD` | ✅ | Password for the output `.kdbx` file |
| `BACKUP_OUTPUT_DIR` | — | Output path inside the container (default: `/backups`) |
| `BACKUP_SCHEDULE` | — | Cron expression (default: `0 2 * * *`) |
| `TZ` | — | Timezone (default: `UTC`) |
| `NOTIFY_WEBHOOK_URL` | — | Webhook URL for notifications (Slack, ntfy, Gotify, generic) |
| `SMTP_HOST` | — | SMTP server |
| `SMTP_PORT` | — | SMTP port (default: `587`) |
| `SMTP_USER` | — | Sender address |
| `SMTP_PASSWORD` | — | SMTP password or app password |
| `NOTIFY_EMAIL_TO` | — | Notification recipient |

### Schedule examples

```
0 2 * * *     daily at 02:00 (default)
0 */6 * * *   every 6 hours
30 3 * * 1    every Monday at 03:30
```

## Notifications

**Webhook** — set `NOTIFY_WEBHOOK_URL`. The request body is:
```json
{ "text": "✅ *Bitwarden Backup SUCCESS*\nBackup completed in 12s.\n..." }
```

**Email** — set all `SMTP_*` variables plus `NOTIFY_EMAIL_TO`. Both are optional and independent; leave the variables empty to disable.

## Building locally

A separate compose file is provided for development and local builds:

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml run --rm bw-backup
```

To pin a specific Bitwarden CLI version, edit `BW_CLI_VERSION` in `docker-compose.dev.yml`.

## Dry run

To test connectivity and see how many items would be exported without writing any file:

```bash
docker compose run --rm bw-backup --dry-run
```

## Security

- Never commit `.env` — it's in `.gitignore`
- Use a strong, unique password for `KEEPASS_PASSWORD`
- Credentials are passed as environment variables, never as command-line arguments
- Session tokens are never logged
- Restrict access to `./backups` with appropriate filesystem permissions

## License

MIT — see [LICENSE](LICENSE).
