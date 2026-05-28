#!/usr/bin/env python3
"""
Bitwarden KeePass Backup — main entry point.

Default mode (no flags): daemon with built-in cron scheduler + setup UI on port 8080.
  --run-now  Run one backup immediately and exit.
  --dry-run  Count vault items without writing any file, then exit.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter

import bitwarden_backup as backup
import config as cfg_module
import setup_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/config.toml"))
SETUP_PORT  = int(os.environ.get("SETUP_PORT", "8080"))


# ---------------------------------------------------------------------------
# Daemon loop
# ---------------------------------------------------------------------------

def _resolve_tz(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        log.error(f"Unknown timezone '{name}', falling back to UTC.")
        return ZoneInfo("UTC")


def _next_run(cron_expr: str, tz: ZoneInfo) -> tuple[datetime, float]:
    now = datetime.now(tz)
    nxt = croniter(cron_expr, now).get_next(datetime)
    return nxt, (nxt - now).total_seconds()


def _run_once(cfg: dict, dry_run: bool = False) -> None:
    """Load config, validate, run backup. Exits process on failure."""
    missing = cfg_module.missing_required(cfg)
    if missing:
        log.error(f"Missing required config: {missing}")
        sys.exit(1)
    try:
        backup.run_backup(cfg, dry_run=dry_run)
    except Exception as e:
        log.error(f"Backup failed: {e}", exc_info=True)
        sys.exit(1)


def _daemon_loop() -> None:
    setup_server.start(CONFIG_PATH, port=SETUP_PORT)
    log.info(f"Setup wizard: http://localhost:{SETUP_PORT}/?token={setup_server.TOKEN}")

    while True:
        cfg     = cfg_module.load(CONFIG_PATH)
        missing = cfg_module.missing_required(cfg)

        if missing:
            log.warning(
                f"Config incomplete — missing: {missing}. "
                f"Configure at http://localhost:{SETUP_PORT}/?token={setup_server.TOKEN}"
            )
            time.sleep(30)
            continue

        tz        = _resolve_tz(cfg["schedule"]["timezone"])
        nxt, wait = _next_run(cfg["schedule"]["cron"], tz)
        log.info(f"Next backup: {nxt.strftime('%Y-%m-%d %H:%M %Z')} (in {int(wait)}s)")
        time.sleep(wait)

        cfg = cfg_module.load(CONFIG_PATH)  # pick up any UI changes made while sleeping
        try:
            backup.run_backup(cfg)
        except Exception as e:
            log.error(f"Backup failed: {e}", exc_info=True)
            backup.notify(cfg, False, f"Backup FAILED: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bitwarden KeePass Backup")
    parser.add_argument("--run-now", action="store_true",
                        help="Run one backup immediately and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="Count vault items without writing any file, then exit")
    args = parser.parse_args()

    if args.run_now or args.dry_run:
        _run_once(cfg_module.load(CONFIG_PATH), dry_run=args.dry_run)
    else:
        _daemon_loop()
