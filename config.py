"""
Config loader: reads /config/config.toml, then env vars override any value.

Priority (highest → lowest):
  environment variables  >  config.toml  >  built-in defaults
"""

import os
import tomllib
from pathlib import Path


def load(path: Path) -> dict:
    cfg: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            cfg = tomllib.load(f)

    bw = cfg.setdefault("bitwarden", {})
    _env(bw, "url",             "BW_URL")
    _env(bw, "client_id",       "BW_CLIENTID")
    _env(bw, "client_secret",   "BW_CLIENTSECRET")
    _env(bw, "master_password", "BW_MASTER_PASSWORD")

    kp = cfg.setdefault("keepass", {})
    _env(kp, "password",   "KEEPASS_PASSWORD")
    _env(kp, "output_dir", "BACKUP_OUTPUT_DIR", "/backups")

    sc = cfg.setdefault("schedule", {})
    _env(sc, "cron",     "BACKUP_SCHEDULE", "0 2 * * *")
    _env(sc, "timezone", "TZ",              "UTC")

    no = cfg.setdefault("notify", {})
    raw_urls = os.environ.get("NOTIFY_URLS", "").strip()
    if raw_urls:
        no["urls"] = [u.strip() for u in raw_urls.split(",") if u.strip()]
    no.setdefault("urls", [])

    rt = cfg.setdefault("retention", {})
    _env_int(rt, "keep", "BACKUP_KEEP", 7)

    wd = cfg.setdefault("webdav", {})
    _env(wd, "url", "WEBDAV_URL", "")

    return cfg


def missing_required(cfg: dict) -> list[str]:
    """Return list of required fields that are empty."""
    bw = cfg.get("bitwarden", {})
    missing = [
        f"bitwarden.{k}"
        for k in ("url", "client_id", "client_secret", "master_password")
        if not bw.get(k)
    ]
    if not cfg.get("keepass", {}).get("password"):
        missing.append("keepass.password")
    return missing


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(section: dict, key: str, var: str, default: str = "") -> None:
    """Set section[key] from env var if present, else keep toml value or default."""
    val = os.environ.get(var, "").strip()
    if val:
        section[key] = val
    else:
        section.setdefault(key, default)


def _env_int(section: dict, key: str, var: str, default: int) -> None:
    """Like _env but parses the value as int. Falls back to default on bad input."""
    raw = os.environ.get(var, "").strip()
    if raw:
        try:
            section[key] = int(raw)
        except ValueError:
            section.setdefault(key, default)
    else:
        section.setdefault(key, default)
