#!/usr/bin/env bash
# Restore engine state from a backup tarball produced by backup.sh
# (standalone; orca's `docker.restore` checks every entry in-process).
# Usage: restore.sh <archive.tar.gz> [state-dir]
set -euo pipefail
ARCHIVE="${1:?archive required}"
STATE="${2:-$HOME/.colima}"
[ -f "$ARCHIVE" ] || { echo "archive '$ARCHIVE' not found" >&2; exit 1; }
mkdir -p "$STATE"
# Never restore owners or setuid bits from the archive. bsdtar has no
# --no-overwrite-dir equivalent.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  SAFE=(--force-local --no-same-owner --no-same-permissions --no-overwrite-dir)
else
  SAFE=(--no-same-owner --no-same-permissions)
fi
tar "${SAFE[@]}" -xzf "$ARCHIVE" -C "$STATE"
echo "restored engine state into $STATE"
