#!/usr/bin/env bash
# Archive the engine's persistent state. Driven by `docker.backup`.
# Usage: backup.sh <destination-dir> [state-dir]
set -euo pipefail
DEST="${1:?destination dir required}"
STATE="${2:-$HOME/.colima}"
[ -d "$STATE" ] || { echo "state dir '$STATE' not found" >&2; exit 1; }
mkdir -p "$DEST"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="$DEST/docker-engine-state-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$STATE" .
echo "$ARCHIVE"
