#!/usr/bin/env bash
# Archive the engine's persistent state (standalone; orca's `docker.backup`
# does the same in-process).
# Usage: backup.sh <destination-dir> [state-dir]
set -euo pipefail
DEST="${1:?destination dir required}"
STATE="${2:-$HOME/.colima}"
[ -d "$STATE" ] || { echo "state dir '$STATE' not found" >&2; exit 1; }
# The archive can hold VM credentials: keep it private to the owner.
umask 077
mkdir -p "$DEST"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="$DEST/docker-engine-state-$STAMP.tar.gz"
LOCAL=()
tar --version 2>/dev/null | grep -q 'GNU tar' && LOCAL=(--force-local)
# Config only: lima's VM ssh keypair is regenerated on start, and VM and
# disk images (colima's data disk holds container images and volumes) are
# never backed up.
tar "${LOCAL[@]}" -czf "$ARCHIVE" \
  --exclude=_lima/_config/user --exclude=_lima/_config/user.pub \
  --exclude=_lima/_disks \
  --exclude='_lima/*/basedisk' --exclude='_lima/*/diffdisk' --exclude='_lima/*/disk' \
  --exclude='*.iso' --exclude='*.img' --exclude='*.qcow2' --exclude='*.raw' \
  -C "$STATE" .
echo "$ARCHIVE"
