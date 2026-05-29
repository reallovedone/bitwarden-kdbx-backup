#!/bin/sh
set -e
chown -R appuser:appuser /backups /config 2>/dev/null || true
exec gosu appuser python /app/daemon.py "$@"
