#!/usr/bin/env bash
# Restore engine state from a backup tarball produced by backup.sh.
# Usage: restore.sh <archive.tar.gz> [state-dir]
set -euo pipefail
ARCHIVE="${1:?archive required}"
STATE="${2:-$HOME/.colima}"
[ -f "$ARCHIVE" ] || { echo "archive '$ARCHIVE' not found" >&2; exit 1; }
mkdir -p "$STATE"
tar -xzf "$ARCHIVE" -C "$STATE"
echo "restored engine state into $STATE"
