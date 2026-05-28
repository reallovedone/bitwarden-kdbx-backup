"""
Setup wizard HTTP server (stdlib only, no extra dependencies).

Usage as background thread (from daemon.py):
    import setup_server
    setup_server.start(config_path, port=8080)

Usage standalone:
    python setup_server.py [--config /path/config.toml] [--port 8080]
"""

import argparse
import html
import json
import os
import secrets
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from croniter import croniter

TOKEN    = secrets.token_urlsafe(32)
_MAX_POST = 1_000_000  # 1 MB guard against oversized POST bodies

_config_path: Path = Path("/config/config.toml")


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_STYLE = """\
:root{--bg:#0f0f11;--fg:#e2e2e2;--accent:#5b9cf6;--dim:#666;--card:#18181b;--border:#2a2a2f;--green:#4ade80;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--fg);font:14px/1.7 'JetBrains Mono','Fira Code',monospace;
     min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:2.5rem 1rem;}
h1{font-size:1.3rem;letter-spacing:.05em;margin-bottom:.2rem;}
h2{margin-bottom:.75rem;}
.sub{color:var(--dim);font-size:.82rem;margin-bottom:2rem;}
form{background:var(--card);border:1px solid var(--border);border-radius:10px;
     padding:2rem;width:100%;max-width:580px;display:flex;flex-direction:column;gap:1.1rem;}
.field{display:flex;flex-direction:column;gap:.3rem;}
label{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;}
label .req{color:var(--accent);}
input,textarea{background:#111113;border:1px solid var(--border);border-radius:6px;
               color:var(--fg);font:inherit;padding:.5rem .7rem;width:100%;
               transition:border-color .15s;resize:vertical;}
input:focus,textarea:focus{outline:none;border-color:var(--accent);}
.hint{font-size:.75rem;color:var(--dim);line-height:1.4;}
.hint code{background:#111;padding:.1rem .35rem;border-radius:3px;}
.info-box{background:#111;border:1px solid var(--border);border-radius:6px;
          padding:.6rem .8rem;font-size:.78rem;color:var(--dim);line-height:1.5;}
.info-box .ok{color:var(--green);}
.box{background:var(--card);border:1px solid var(--border);border-radius:10px;
     padding:2rem;max-width:480px;text-align:center;}
hr{border:none;border-top:1px solid var(--border);}
.sec{font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;}
button{background:var(--accent);border:none;border-radius:6px;color:#fff;cursor:pointer;
       font:inherit;font-weight:600;padding:.65rem;margin-top:.5rem;transition:opacity .15s;}
button:hover{opacity:.85;}
p{color:#888;margin-top:.5rem;}
a{color:var(--accent);}"""

_HTML_FORM = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bitwarden KeePass Backup — Setup</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>&#9881; Bitwarden KeePass Backup</h1>
<p class="sub">Setup — changes take effect on next scheduled backup</p>
<form method="POST" action="/">
  <input type="hidden" name="_token" value="{{TOKEN}}">

  <p class="sec">Bitwarden credentials</p>

  <div class="field">
    <label>Bitwarden / Vaultwarden URL <span class="req">*</span></label>
    <input name="BW_URL" type="url" placeholder="https://vault.example.com" value="{{BW_URL}}" required>
  </div>
  <div class="field">
    <label>Client ID <span class="req">*</span></label>
    <input name="BW_CLIENTID" type="text" placeholder="user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value="{{BW_CLIENTID}}" required>
    <span class="hint">Settings &rarr; Security &rarr; Keys &rarr; API Key</span>
  </div>
  <div class="field">
    <label>Client Secret <span class="req">*</span></label>
    <input name="BW_CLIENTSECRET" type="password" placeholder="leave blank to keep current">
  </div>
  <div class="field">
    <label>Master Password <span class="req">*</span></label>
    <input name="BW_MASTER_PASSWORD" type="password" placeholder="leave blank to keep current">
  </div>
  <div class="field">
    <label>KeePass Output Password <span class="req">*</span></label>
    <input name="KEEPASS_PASSWORD" type="password" placeholder="leave blank to keep current">
    <span class="hint">Password for the generated <code>.kdbx</code> file — store it safely</span>
  </div>

  <hr>
  <p class="sec">Local backup storage</p>
  <div class="info-box">
    <span class="ok">&#10003;</span> Backups always saved to <code>./backups/</code> on the host (Docker volume).<br>
    To change the path, edit <code>volumes:</code> in <code>docker-compose.yml</code>.
  </div>

  <hr>
  <p class="sec">Schedule &amp; timezone</p>

  <div class="field">
    <label>Backup Schedule (cron)</label>
    <input name="BACKUP_SCHEDULE" type="text" value="{{BACKUP_SCHEDULE}}" placeholder="0 2 * * *">
    <span class="hint">Default: every day at 02:00 &mdash; <a href="https://crontab.guru" target="_blank">crontab.guru</a></span>
  </div>
  <div class="field">
    <label>Timezone</label>
    <input name="TZ" type="text" value="{{TZ}}" placeholder="UTC">
    <span class="hint">e.g. <code>Europe/Rome</code>, <code>America/New_York</code></span>
  </div>

  <hr>
  <p class="sec">Notifications (optional)</p>

  <div class="field">
    <label>Notification URLs</label>
    <textarea name="NOTIFY_URLS" rows="3" placeholder="tgram://BOT_TOKEN/CHAT_ID">{{NOTIFY_URLS}}</textarea>
    <span class="hint">
      One URL per line or comma-separated &mdash;
      <a href="https://github.com/caronc/apprise/wiki" target="_blank">100+ services</a>:<br>
      Telegram: <code>tgram://BOT_TOKEN/CHAT_ID</code> &bull;
      Discord: <code>discord://WEBHOOK_ID/TOKEN</code><br>
      ntfy: <code>ntfy://hostname/topic</code> &bull;
      Email: <code>mailto://user:pass@gmail.com</code>
    </span>
  </div>

  <hr>
  <p class="sec">Backup retention</p>

  <div class="field">
    <label>Keep last N backups</label>
    <input name="BACKUP_KEEP" type="number" min="0" value="{{BACKUP_KEEP}}" placeholder="7">
    <span class="hint">Oldest <code>.kdbx</code> files deleted automatically. Set to <code>0</code> to keep all.</span>
  </div>

  <hr>
  <p class="sec">WebDAV / Nextcloud remote upload (optional)</p>

  <div class="field">
    <label>WebDAV URL</label>
    <input name="WEBDAV_URL" type="password"
           placeholder="https://user:apptoken@nextcloud.example.com/remote.php/dav/files/user/Backups/">
    <span class="hint">Include credentials in URL — never pre-filled. Leave blank to keep current or skip remote upload.</span>
  </div>

  <button type="submit">Save configuration</button>
</form>
</body>
</html>"""

_HTML_OK = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Saved</title>
<meta http-equiv="refresh" content="3;url=/?token={{TOKEN}}">
<style>{_STYLE}</style></head>
<body><div class="box">
<h2 style="color:var(--green)">&#10003; Saved</h2>
<p>Configuration written to <code>config.toml</code>.</p>
<p>Changes take effect on next scheduled backup.</p>
<p style="color:#555;font-size:.8rem;margin-top:1rem;">Redirecting back&hellip;</p>
</div></body></html>"""

_HTML_ERR = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title>
<style>{_STYLE}</style></head>
<body><div class="box">
<h2 style="color:#e55">&#10007; {{TITLE}}</h2>
<p>{{DETAIL}}</p>
<p><a href="javascript:history.back()">Go back</a></p>
</div></body></html>"""

_HTML_403 = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>403</title>
<style>{_STYLE}</style></head>
<body><div class="box">
<h2 style="color:#e55">403</h2>
<p>Invalid or missing token.</p>
</div></body></html>"""


# ---------------------------------------------------------------------------
# Config read / write
# ---------------------------------------------------------------------------

_FORM_DEFAULTS = {
    "BW_URL": "", "BW_CLIENTID": "", "BACKUP_SCHEDULE": "0 2 * * *",
    "TZ": "UTC", "NOTIFY_URLS": "", "BACKUP_KEEP": "7",
}


def _read_form_values() -> dict:
    """Read non-secret fields from config.toml for form pre-fill. Never returns passwords."""
    if not _config_path.exists():
        return {}
    try:
        with open(_config_path, "rb") as f:
            cfg = tomllib.load(f)
        bw, sc, no, rt = (cfg.get(s, {}) for s in ("bitwarden", "schedule", "notify", "retention"))
        return {
            "BW_URL":          html.escape(bw.get("url", "")),
            "BW_CLIENTID":     html.escape(bw.get("client_id", "")),
            "BACKUP_SCHEDULE": html.escape(sc.get("cron", "0 2 * * *")),
            "TZ":              html.escape(sc.get("timezone", "UTC")),
            "NOTIFY_URLS":     html.escape("\n".join(no.get("urls", []))),
            "BACKUP_KEEP":     html.escape(str(rt.get("keep", 7))),
            # WEBDAV_URL omitted — contains embedded credentials
        }
    except Exception:
        return {}


def _parse_notify_urls(raw: str) -> list[str]:
    return [p.strip() for p in raw.replace(",", "\n").splitlines() if p.strip()]


def _toml_str(value: str) -> str:
    """Convert a Python string to a valid TOML string literal."""
    return json.dumps(value)  # JSON strings are valid TOML basic strings


def _write_config(form: dict, existing: dict) -> None:
    """Write config.toml atomically with 0600 permissions."""

    def _field(toml_section: str, toml_key: str, form_field: str) -> str:
        """Use form value if provided, otherwise keep the existing toml value."""
        v = form.get(form_field, "").strip()
        return v if v else existing.get(toml_section, {}).get(toml_key, "")

    notify_urls = _parse_notify_urls(form.get("NOTIFY_URLS", ""))

    try:
        retention_keep = max(0, int(form.get("BACKUP_KEEP", "7").strip() or "7"))
    except ValueError:
        retention_keep = existing.get("retention", {}).get("keep", 7)

    lines = [
        "# config.toml — Bitwarden KeePass Backup",
        "# https://github.com/reallovedone/bitwarden-kdbx-backup",
        "",
        "[bitwarden]",
        f"url             = {_toml_str(form.get('BW_URL', '').strip())}",
        f"client_id       = {_toml_str(form.get('BW_CLIENTID', '').strip())}",
        f"client_secret   = {_toml_str(_field('bitwarden', 'client_secret',   'BW_CLIENTSECRET'))}",
        f"master_password = {_toml_str(_field('bitwarden', 'master_password', 'BW_MASTER_PASSWORD'))}",
        "",
        "[keepass]",
        f"password   = {_toml_str(_field('keepass', 'password', 'KEEPASS_PASSWORD'))}",
        'output_dir = "/backups"',
        "",
        "[schedule]",
        f"cron     = {_toml_str(form.get('BACKUP_SCHEDULE', '0 2 * * *').strip())}",
        f"timezone = {_toml_str(form.get('TZ', 'UTC').strip())}",
        "",
        "[retention]",
        f"keep = {retention_keep}",
        "",
        "[notify]",
        "urls = [",
        *[f"  {_toml_str(u)}," for u in notify_urls],
        "]",
        "",
        "[webdav]",
        f"url = {_toml_str(_field('webdav', 'url', 'WEBDAV_URL'))}",
    ]

    content = "\n".join(lines) + "\n"
    tmp     = _config_path.with_suffix(".toml.tmp")

    _config_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
    except Exception:
        os.unlink(str(tmp))
        raise

    os.replace(str(tmp), str(_config_path))
    os.chmod(str(_config_path), 0o600)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

def _check_token(given: str | None) -> bool:
    return bool(given) and secrets.compare_digest(given, TOKEN)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress access log (token appears in GET URL)

    def _send(self, code: int, body: str) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, code: int, title: str, detail: str) -> None:
        self._send(code, _HTML_ERR.format(
            TITLE=html.escape(title),
            DETAIL=html.escape(detail),
        ))

    def do_GET(self):
        token = parse_qs(urlparse(self.path).query).get("token", [None])[0]
        if not _check_token(token):
            self._send(403, _HTML_403)
            return
        vals = {**_FORM_DEFAULTS, **_read_form_values()}
        self._send(200, _HTML_FORM.format(TOKEN=html.escape(TOKEN), **vals))

    def do_POST(self):
        length = max(0, min(int(self.headers.get("Content-Length", 0)), _MAX_POST))
        form   = {k: v[0] for k, v in parse_qs(
            self.rfile.read(length).decode(errors="replace")
        ).items()}

        if not _check_token(form.get("_token")):
            self._send(403, _HTML_403)
            return

        cron_expr = form.get("BACKUP_SCHEDULE", "0 2 * * *").strip()
        if not croniter.is_valid(cron_expr):
            self._error(400, "Invalid cron expression",
                        f'"{cron_expr}" is not a valid cron expression.')
            return

        existing: dict = {}
        if _config_path.exists():
            try:
                with open(_config_path, "rb") as f:
                    existing = tomllib.load(f)
            except Exception:
                pass

        try:
            _write_config(form, existing)
        except Exception as e:
            self._error(500, "Write failed", str(e))
            return

        print(f"[setup] config.toml written → {_config_path}", flush=True)
        self._send(200, _HTML_OK.format(TOKEN=html.escape(TOKEN)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start(config_path: Path, port: int = 8080) -> None:
    """Start the setup wizard in a background daemon thread."""
    global _config_path
    _config_path = config_path
    server = HTTPServer(("0.0.0.0", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bitwarden KeePass Backup — setup wizard")
    parser.add_argument("--config", default="/config/config.toml")
    parser.add_argument("--port",   type=int, default=8080)
    args = parser.parse_args()

    _config_path = Path(args.config)
    server       = HTTPServer(("0.0.0.0", args.port), _Handler)

    print("=" * 58, flush=True)
    print("  Bitwarden KeePass Backup — Setup Wizard", flush=True)
    print(f"  Open: http://localhost:{args.port}/?token={TOKEN}", flush=True)
    print("  WARNING: HTTP only — use on trusted networks", flush=True)
    print("=" * 58, flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
