#!/usr/bin/env python3
"""
Bitwarden → KeePass backup logic.
Public entry point: run_backup(cfg: dict, dry_run: bool = False) -> int
All functions accept the cfg dict produced by config.load().
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import apprise as apprise_lib
import requests
from pykeepass import PyKeePass, create_database

log = logging.getLogger(__name__)

_FIELD_HIDDEN = 1


# ---------------------------------------------------------------------------
# Bitwarden CLI helpers
# ---------------------------------------------------------------------------

def _bw_env(cfg: dict) -> dict:
    """Build subprocess environment with Bitwarden credentials injected."""
    env = os.environ.copy()
    bw  = cfg["bitwarden"]
    env["BW_CLIENTID"]      = bw["client_id"]
    env["BW_CLIENTSECRET"]  = bw["client_secret"]
    env["BW_MASTER_PASSWORD"] = bw["master_password"]
    return env


def _redact_session(args: list[str]) -> list[str]:
    """Replace the value after --session with [REDACTED] for safe logging."""
    out, hide_next = [], False
    for arg in args:
        if hide_next:
            out.append("[REDACTED]")
            hide_next = False
        elif arg == "--session":
            out.append(arg)
            hide_next = True
        else:
            out.append(arg)
    return out


def _bw(args: list[str], cfg: dict) -> str:
    """Run a bw CLI command and return stdout. Raises RuntimeError on failure."""
    result = subprocess.run(
        ["bw", "--nointeraction"] + args,
        capture_output=True,
        text=True,
        env=_bw_env(cfg),
    )
    if result.returncode != 0:
        safe = " ".join(_redact_session(args))
        raise RuntimeError(f"bw {safe} failed (exit {result.returncode}):\n{result.stderr}")
    return result.stdout.strip()


def _bw_json(args: list[str], cfg: dict) -> dict | list:
    """Run a bw CLI command and parse its JSON output."""
    return json.loads(_bw(args, cfg))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _login_and_unlock(cfg: dict) -> str:
    """Log in with API key and unlock the vault. Returns the session token."""
    log.info("Logging in with API key...")
    _bw(["config", "server", cfg["bitwarden"]["url"].rstrip("/")], cfg)
    _bw(["login", "--apikey"], cfg)
    log.info("Unlocking vault...")
    session = _bw(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"], cfg)
    log.info("Vault unlocked.")
    return session


def _logout(cfg: dict) -> None:
    try:
        _bw(["logout"], cfg)
        log.info("Logged out.")
    except Exception as e:
        log.warning(f"Logout failed (ignored): {e}")


# ---------------------------------------------------------------------------
# Vault export
# ---------------------------------------------------------------------------

def _export_vault(session: str, cfg: dict) -> dict:
    log.info("Exporting personal vault...")
    return _bw_json(["export", "--session", session, "--format", "json", "--raw"], cfg)


def _list_organizations(session: str, cfg: dict) -> list[dict]:
    log.info("Fetching organizations...")
    return _bw_json(["list", "organizations", "--session", session], cfg)


def _export_organization(session: str, org_id: str, org_name: str, cfg: dict) -> dict:
    log.info(f"Exporting organization: {org_name}")
    return _bw_json(
        ["export", "--session", session, "--format", "json", "--organizationid", org_id, "--raw"],
        cfg,
    )


def _list_collections(session: str, org_id: str, cfg: dict) -> list[dict]:
    return _bw_json(["list", "collections", "--organizationid", org_id, "--session", session], cfg)


# ---------------------------------------------------------------------------
# KeePass builder
# ---------------------------------------------------------------------------

def _item_to_entry(kp: PyKeePass, group, item: dict) -> None:
    name  = item.get("name") or "Untitled"
    notes = item.get("notes") or ""
    itype = item.get("type", 1)
    username = password = url = ""

    if itype == 1:  # Login
        login    = item.get("login") or {}
        username = login.get("username") or ""
        password = login.get("password") or ""
        uris     = login.get("uris") or []
        url      = uris[0].get("uri") or "" if uris else ""

    elif itype == 3:  # Card
        card     = item.get("card") or {}
        username = card.get("cardholderName") or ""
        password = card.get("number") or ""
        notes = (
            f"Brand: {card.get('brand', '')}\n"
            f"Exp: {card.get('expMonth', '')}/{card.get('expYear', '')}\n"
            f"CVV: {card.get('code', '')}\n\n"
        ) + notes

    elif itype == 4:  # Identity
        identity = item.get("identity") or {}
        username = f"{identity.get('firstName', '')} {identity.get('lastName', '')}".strip()
        notes    = json.dumps(identity, ensure_ascii=False, indent=2) + "\n\n" + notes

    entry = kp.add_entry(
        destination_group=group,
        title=name,
        username=username,
        password=password,
        url=url,
        notes=notes.strip(),
    )
    for field in item.get("fields") or []:
        entry.set_custom_property(
            field.get("name") or "field",
            field.get("value") or "",
            protect=field.get("type", 0) == _FIELD_HIDDEN,
        )


def _ensure_group(kp: PyKeePass, parent, path: str):
    """Navigate or create nested KeePass groups from a slash-delimited path."""
    current = parent
    for part in (p.strip() for p in path.split("/") if p.strip()):
        child   = next((g for g in current.subgroups if g.name == part), None)
        current = child if child else kp.add_group(current, part)
    return current


def _populate_group(kp, parent, items, get_id, id_to_name, fallback_label) -> tuple[int, int]:
    """
    Add items to sub-groups of parent, grouped by category ID.
    Returns (entry_count, named_group_count).
    """
    group_cache: dict = {}
    fallback = None
    count    = 0

    for item in items or []:
        gid = get_id(item)
        if gid and gid in id_to_name:
            if gid not in group_cache:
                group_cache[gid] = _ensure_group(kp, parent, id_to_name[gid])
            group = group_cache[gid]
        else:
            if fallback is None:
                fallback = kp.add_group(parent, fallback_label)
            group = fallback

        _item_to_entry(kp, group, item)
        count += 1

    return count, len(group_cache)


def _build_keepass(personal: dict, organizations: list, output: Path, cfg: dict) -> int:
    """Create the .kdbx file. Returns total number of entries written."""
    log.info(f"Creating KeePass database: {output}")
    old_umask = os.umask(0o177)  # ensure kdbx is created 0600 from the start
    try:
        kp = create_database(str(output), password=cfg["keepass"]["password"])
    finally:
        os.umask(old_umask)
    total = 0

    # Personal vault
    personal_group = kp.add_group(kp.root_group, "Personal")
    folders        = {f["id"]: f["name"] for f in personal.get("folders") or [] if f.get("id")}
    count, nf      = _populate_group(
        kp, personal_group, personal.get("items"),
        lambda i: i.get("folderId"), folders, "No Folder",
    )
    total += count
    log.info(f"  Personal: {count} entries, {nf} folder(s)")

    # Organizations
    for org_name, org_data, collections in organizations:
        label   = org_name or "Unknown Organization"
        og      = kp.add_group(kp.root_group, f"Org: {label}")
        col_map = {c["id"]: c["name"] for c in collections if c.get("id")}
        count, nc = _populate_group(
            kp, og, org_data.get("items"),
            lambda i: (i.get("collectionIds") or [None])[0],
            col_map, "No Collection",
        )
        total += count
        log.info(f"  {label}: {count} entries, {nc} collection(s)")

    kp.save()
    os.chmod(str(output), 0o600)
    log.info(f"Database saved. Total entries: {total}")
    return total


# ---------------------------------------------------------------------------
# Backup rotation
# ---------------------------------------------------------------------------

def _rotate_backups(out_dir: Path, cfg: dict) -> None:
    """Delete oldest .kdbx files, keeping only the last N."""
    keep = int(cfg.get("retention", {}).get("keep", 7))
    if keep <= 0:
        return
    files     = sorted(out_dir.glob("bitwarden_*.kdbx"), key=lambda p: p.name)
    to_delete = files[:-keep] if len(files) > keep else []
    for f in to_delete:
        try:
            f.unlink()
            log.info(f"Rotation: removed {f.name}")
        except Exception as e:
            log.warning(f"Rotation: could not remove {f.name}: {e}")


# ---------------------------------------------------------------------------
# WebDAV upload
# ---------------------------------------------------------------------------

def _parse_webdav_url(raw: str) -> tuple[str, tuple[str, str] | None]:
    """
    Split credentials from a WebDAV URL.
    Returns (clean_url, (user, password)) or (url, None) if no credentials.
    """
    if not raw:
        return "", None
    p = urlparse(raw)
    if p.username:
        netloc    = p.hostname + (f":{p.port}" if p.port else "")
        clean_url = urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
        return (clean_url.rstrip("/") + "/"), (p.username, p.password or "")
    return (raw.rstrip("/") + "/"), None


def _upload_webdav(path: Path, cfg: dict) -> bool:
    """Upload path to the configured WebDAV folder. Returns True on success."""
    url, auth = _parse_webdav_url(cfg["webdav"]["url"])
    if not url:
        return False
    dest = url + path.name
    log.info(f"Uploading to WebDAV: {dest}")
    try:
        with path.open("rb") as fh:
            r = requests.put(
                dest, data=fh, auth=auth,
                headers={"Content-Type": "application/octet-stream"},
                timeout=120,
            )
        r.raise_for_status()
        log.info(f"WebDAV upload complete (HTTP {r.status_code}).")
        return True
    except Exception as e:
        log.warning(f"WebDAV upload failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def notify(cfg: dict, success: bool, message: str) -> None:
    """Send success/failure notification via configured Apprise URLs."""
    urls = cfg.get("notify", {}).get("urls", [])
    if not urls:
        return
    a = apprise_lib.Apprise()
    for u in urls:
        a.add(u)
    title = f"Bitwarden Backup {'SUCCESS' if success else 'FAILED'}"
    ntype = apprise_lib.NotifyType.SUCCESS if success else apprise_lib.NotifyType.FAILURE
    a.notify(title=title, body=message, notify_type=ntype)
    log.info(f"Notification sent to {len(urls)} target(s).")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_backup(cfg: dict, dry_run: bool = False) -> int:
    """
    Run a full Bitwarden → KeePass backup.
    Returns total entry count. Raises on failure.
    """
    start     = datetime.now()
    out_dir   = Path(cfg["keepass"]["output_dir"])
    output    = out_dir / f"bitwarden_{start.strftime('%Y%m%d_%H%M%S')}.kdbx"

    if dry_run:
        log.info("*** DRY RUN — no file will be written ***")

    out_dir.mkdir(parents=True, exist_ok=True)

    session = None
    try:
        session   = _login_and_unlock(cfg)
        personal  = _export_vault(session, cfg)
        orgs_meta = _list_organizations(session, cfg)

        organizations = [
            (org["name"],
             _export_organization(session, org["id"], org["name"], cfg),
             _list_collections(session, org["id"], cfg))
            for org in orgs_meta
        ]

        if dry_run:
            total = len(personal.get("items") or []) + sum(
                len(d.get("items") or []) for _, d, _ in organizations
            )
            log.info(f"Dry run complete. Would export {total} entries.")
            return total

        total     = _build_keepass(personal, organizations, output, cfg)
        webdav_ok = _upload_webdav(output, cfg)
        _rotate_backups(out_dir, cfg)
        elapsed   = int((datetime.now() - start).total_seconds())

        msg = "\n".join([
            f"Backup completed in {elapsed}s.",
            f"File: {output}",
            f"Organizations: {len(organizations)}",
            f"Total entries: {total}",
        ])
        if webdav_ok:
            url, _ = _parse_webdav_url(cfg["webdav"]["url"])
            msg += f"\nWebDAV: uploaded to {url}{output.name}"

        log.info(msg)
        notify(cfg, True, msg)
        return total

    finally:
        if session:
            _logout(cfg)
