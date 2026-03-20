#!/usr/bin/env python3
"""
bitwarden_backup.py
-------------------
Exports the personal vault and all organizations from Bitwarden / Vaultwarden
and saves everything to a KeePass file (.kdbx).

Authentication: API Key (client_id + client_secret)
Notifications:  webhook (e.g. Slack, Gotify, ntfy) or SMTP email

Required environment variables (.env or systemd EnvironmentFile):
    BW_CLIENTID          → API key client_id
    BW_CLIENTSECRET      → API key client_secret
    BW_MASTER_PASSWORD   → master password (required to unlock after API key login)
    BW_URL               → URL of your Bitwarden / Vaultwarden instance (e.g. https://vault.example.com)
    KEEPASS_PASSWORD     → master password for the generated .kdbx file
    BACKUP_OUTPUT_DIR    → directory where the .kdbx file will be saved (default: /backups)

Optional variables for webhook notifications (Slack / ntfy / Gotify / generic):
    NOTIFY_WEBHOOK_URL   → webhook URL (leave empty to disable)

Optional variables for SMTP email notifications:
    SMTP_HOST            → e.g. smtp.gmail.com
    SMTP_PORT            → e.g. 587
    SMTP_USER            → sender address
    SMTP_PASSWORD        → SMTP password / app password
    NOTIFY_EMAIL_TO      → notification recipient
"""

import argparse
import os
import sys
import json
import subprocess
import logging
import smtplib
import tempfile
import requests
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from pykeepass import PyKeePass, create_database

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration from environment variables
# ---------------------------------------------------------------------------
def require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        log.error(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val


BW_CLIENTID        = require_env("BW_CLIENTID")
BW_CLIENTSECRET    = require_env("BW_CLIENTSECRET")
BW_MASTER_PASSWORD = require_env("BW_MASTER_PASSWORD")
BW_URL             = require_env("BW_URL").rstrip("/")
KEEPASS_PASSWORD   = require_env("KEEPASS_PASSWORD")
BACKUP_OUTPUT_DIR  = Path(os.environ.get("BACKUP_OUTPUT_DIR", "/backups"))

NOTIFY_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
SMTP_HOST          = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT          = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER          = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD      = os.environ.get("SMTP_PASSWORD", "").strip()
NOTIFY_EMAIL_TO    = os.environ.get("NOTIFY_EMAIL_TO", "").strip()


# ---------------------------------------------------------------------------
# Helper: run bw CLI command
# ---------------------------------------------------------------------------
def _sanitize_args(args: list[str]) -> list[str]:
    """Redact sensitive values (session tokens) from argument list for safe logging."""
    result = []
    redact_next = False
    for arg in args:
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
        elif arg == "--session":
            result.append(arg)
            redact_next = True
        else:
            result.append(arg)
    return result


def bw(args: list[str], input_text: str | None = None, capture: bool = True) -> str:
    """Run the Bitwarden CLI with the given arguments."""
    env = os.environ.copy()
    env["BW_CLIENTID"]     = BW_CLIENTID
    env["BW_CLIENTSECRET"] = BW_CLIENTSECRET

    cmd = ["bw", "--nointeraction"] + args
    result = subprocess.run(
        cmd,
        input=input_text,
        capture_output=capture,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        safe_args = " ".join(_sanitize_args(args))
        raise RuntimeError(
            f"bw {safe_args} failed (exit {result.returncode}):\n{result.stderr}"
        )
    return result.stdout.strip() if capture else ""


# ---------------------------------------------------------------------------
# Auth & session
# ---------------------------------------------------------------------------
def login_and_unlock() -> str:
    """Log in with API key and unlock the vault. Returns the BW_SESSION token."""
    log.info("Logging in with API key...")
    bw(["config", "server", BW_URL])
    bw(["login", "--apikey"])

    log.info("Unlocking vault...")
    session = bw(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"])
    log.info("Vault unlocked successfully.")
    return session


def logout():
    try:
        bw(["logout"])
        log.info("Logged out.")
    except Exception as e:
        log.warning(f"Logout failed (ignored): {e}")


# ---------------------------------------------------------------------------
# Vault and organization export
# ---------------------------------------------------------------------------
def export_vault(session: str) -> dict:
    """Export the personal vault as JSON."""
    log.info("Exporting personal vault...")
    raw = bw(["export", "--session", session, "--format", "json", "--raw"])
    return json.loads(raw)


def list_organizations(session: str) -> list[dict]:
    """Return the list of organizations."""
    log.info("Fetching organization list...")
    raw = bw(["list", "organizations", "--session", session])
    return json.loads(raw)


def export_organization(session: str, org_id: str, org_name: str) -> dict:
    """Export an organization as JSON."""
    log.info(f"Exporting organization: {org_name} ({org_id})")
    raw = bw(
        ["export", "--session", session, "--format", "json",
         "--organizationid", org_id, "--raw"]
    )
    return json.loads(raw)


def list_collections(session: str, org_id: str) -> list[dict]:
    """Return the collections for an organization."""
    raw = bw(["list", "collections", "--organizationid", org_id, "--session", session])
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Bitwarden item type mapping
# ---------------------------------------------------------------------------
ITEM_TYPE = {1: "login", 2: "secure_note", 3: "card", 4: "identity"}

# Bitwarden custom field types
FIELD_TYPE_HIDDEN = 1


def item_to_keepass_entry(kp: PyKeePass, group, item: dict):
    """Add a Bitwarden item as a KeePass entry in the specified group."""
    name     = item.get("name") or "Untitled"
    notes    = item.get("notes") or ""
    itype    = item.get("type", 1)
    username = ""
    password = ""
    url      = ""

    if itype == 1:  # Login
        login = item.get("login") or {}
        username = login.get("username") or ""
        password = login.get("password") or ""
        uris     = login.get("uris") or []
        if uris:
            url = uris[0].get("uri") or ""

    elif itype == 3:  # Card
        card = item.get("card") or {}
        username = card.get("cardholderName") or ""
        password = card.get("number") or ""
        notes = (
            f"Brand: {card.get('brand','')}\n"
            f"Exp: {card.get('expMonth','')}/{card.get('expYear','')}\n"
            f"CVV: {card.get('code','')}\n\n"
        ) + notes

    elif itype == 4:  # Identity
        identity = item.get("identity") or {}
        username = f"{identity.get('firstName','')} {identity.get('lastName','')}".strip()
        notes = json.dumps(identity, ensure_ascii=False, indent=2) + "\n\n" + notes

    entry = kp.add_entry(
        destination_group=group,
        title=name,
        username=username,
        password=password,
        url=url,
        notes=f"{notes}".strip(),
    )

    # Custom fields — hidden fields are marked as protected in KeePass
    for field in item.get("fields") or []:
        fname   = field.get("name") or "field"
        fval    = field.get("value") or ""
        ftype   = field.get("type", 0)
        protect = ftype == FIELD_TYPE_HIDDEN
        entry.set_custom_property(fname, fval, protect=protect)

    return entry


# ---------------------------------------------------------------------------
# KeePass group helpers
# ---------------------------------------------------------------------------
def _ensure_group_path(kp: PyKeePass, parent, path: str):
    """
    Navigate or create nested KeePass groups following a slash-delimited path.
    Example: "Work/Office/VMS" → Personal > Work > Office > VMS
    """
    parts = [p.strip() for p in path.split("/") if p.strip()]
    current = parent
    for part in parts:
        child = next((g for g in current.subgroups if g.name == part), None)
        if child is None:
            child = kp.add_group(current, part)
        current = child
    return current


# ---------------------------------------------------------------------------
# Build KeePass database
# ---------------------------------------------------------------------------
def _populate_groups(
    kp: PyKeePass,
    parent,
    items: list[dict] | None,
    get_id,
    id_to_name: dict[str, str],
    fallback_label: str,
) -> tuple[int, int]:
    """
    Add items to subgroups of *parent*, grouped by a category ID.
      - get_id(item)  → category id string, or None
      - id_to_name    → maps id → slash-delimited path (supports nesting)
      - fallback_label → name of the catch-all group for uncategorised items
    Returns (entry_count, named_group_count).
    """
    group_cache: dict[str, object] = {}
    fallback = None
    count = 0
    for item in items or []:
        gid = get_id(item)
        if gid and gid in id_to_name:
            if gid not in group_cache:
                group_cache[gid] = _ensure_group_path(kp, parent, id_to_name[gid])
            group = group_cache[gid]
        else:
            if fallback is None:
                fallback = kp.add_group(parent, fallback_label)
            group = fallback
        item_to_keepass_entry(kp, group, item)
        count += 1
    return count, len(group_cache)


def build_keepass(
    personal_vault: dict,
    organizations: list[tuple[str, dict, list[dict]]],
    output_path: Path,
) -> int:
    """
    Create the .kdbx file mirroring the Bitwarden structure:
    - Personal/
        - <Folder name>/   (one subgroup per Bitwarden folder)
        - No Folder/       (items without a folder)
    - Org: <OrgName>/
        - <Collection name>/  (one subgroup per collection)
        - No Collection/      (items without a collection)
    Returns the total number of entries inserted.
    """
    log.info(f"Creating KeePass database: {output_path}")
    kp = create_database(str(output_path), password=KEEPASS_PASSWORD)
    total = 0

    # --- Personal vault ---
    personal_group = kp.add_group(kp.root_group, "Personal")
    folders: dict[str, str] = {
        f["id"]: f["name"]
        for f in personal_vault.get("folders") or []
        if f.get("id")
    }
    count, nfolders = _populate_groups(
        kp, personal_group,
        personal_vault.get("items"),
        lambda item: item.get("folderId"),
        folders,
        "No Folder",
    )
    total += count
    log.info(f"  Personal: {count} entries across {nfolders} folder(s)")

    # --- Organizations ---
    for org_name, org_data, collections in organizations:
        safe_name = org_name or "Unknown Organization"
        org_group = kp.add_group(kp.root_group, f"Org: {safe_name}")
        col_map: dict[str, str] = {c["id"]: c["name"] for c in collections if c.get("id")}
        count, ncols = _populate_groups(
            kp, org_group,
            org_data.get("items"),
            lambda item: (item.get("collectionIds") or [None])[0],
            col_map,
            "No Collection",
        )
        total += count
        log.info(f"  {safe_name}: {count} entries across {ncols} collection(s)")

    kp.save()
    log.info(f"Database saved. Total entries: {total}")
    return total


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
def notify_webhook(success: bool, message: str):
    if not NOTIFY_WEBHOOK_URL:
        return
    icon   = "✅" if success else "❌"
    status = "SUCCESS" if success else "FAILED"
    payload = {"text": f"{icon} *Bitwarden Backup {status}*\n{message}"}
    try:
        r = requests.post(NOTIFY_WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
        log.info("Webhook notification sent.")
    except Exception as e:
        log.warning(f"Webhook notification failed: {e}")


def notify_email(success: bool, message: str):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, NOTIFY_EMAIL_TO]):
        return
    status  = "SUCCESS" if success else "FAILED"
    subject = f"[Bitwarden Backup] {status} — {datetime.now().strftime('%Y-%m-%d')}"
    msg = MIMEMultipart()
    msg["From"]    = SMTP_USER
    msg["To"]      = NOTIFY_EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "plain"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, NOTIFY_EMAIL_TO, msg.as_string())
        log.info("Email notification sent.")
    except Exception as e:
        log.warning(f"Email notification failed: {e}")


def notify(success: bool, message: str):
    notify_webhook(success, message)
    notify_email(success, message)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Bitwarden → KeePass backup")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and count vault items without writing the .kdbx file",
    )
    args = parser.parse_args()

    start = datetime.now()
    timestamp = start.strftime("%Y%m%d_%H%M%S")
    BACKUP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = BACKUP_OUTPUT_DIR / f"bitwarden_{timestamp}.kdbx"

    if args.dry_run:
        log.info("*** DRY RUN — no file will be written ***")

    session = None
    try:
        session = login_and_unlock()

        # Export personal vault
        personal_vault = export_vault(session)
        personal_count = len(personal_vault.get("items") or [])

        # Export organizations
        orgs_meta = list_organizations(session)
        organizations = []
        for org in orgs_meta:
            org_data = export_organization(session, org["id"], org["name"])
            collections = list_collections(session, org["id"])
            organizations.append((org["name"], org_data, collections))

        if args.dry_run:
            total_entries = personal_count + sum(
                len(data.get("items") or []) for _, data, _ in organizations
            )
            personal_folders = len(personal_vault.get("folders") or [])
            log.info(f"  Personal: {personal_count} entries, {personal_folders} folder(s)")
            for org_name, org_data, cols in organizations:
                count = len(org_data.get("items") or [])
                log.info(f"  {org_name}: {count} entries, {len(cols)} collection(s)")
            log.info(f"Dry run complete. Would export {total_entries} entries total.")
            return

        # Build KeePass database
        total_entries = build_keepass(personal_vault, organizations, output_path)

        elapsed = (datetime.now() - start).seconds
        msg = (
            f"Backup completed in {elapsed}s.\n"
            f"File: {output_path}\n"
            f"Organizations: {len(organizations)}\n"
            f"Total entries: {total_entries}"
        )
        log.info(msg)
        notify(True, msg)

    except Exception as e:
        msg = f"Backup FAILED: {e}"
        log.error(msg, exc_info=True)
        notify(False, msg)
        sys.exit(1)

    finally:
        if session:
            logout()
        # Remove any temporary bw files from the system temp directory
        for f in Path(tempfile.gettempdir()).glob("bw-*"):
            try:
                f.unlink()
            except Exception as e:
                log.warning(f"Failed to remove temp file {f}: {e}")


if __name__ == "__main__":
    main()
