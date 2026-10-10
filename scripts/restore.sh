#!/usr/bin/env bash
# Restore engine state from a backup tarball produced by backup.sh
# (standalone; orca's `docker.restore` checks every entry in-process).
# Extracts into a sibling staging dir, carries over anything the archive
# lacks, then swaps it in. A failure before the swap leaves the state dir as
# it was; a failed swap names where the previous state was put aside.
# Usage: restore.sh <archive.tar.gz> [state-dir]
set -euo pipefail
ARCHIVE="${1:?archive required}"
STATE="${2:-$HOME/.colima}"
# Same caps as orca's engine_state::LIMITS; overridable for tests.
MAX_BYTES="${RESTORE_MAX_BYTES:-$((4 << 30))}"
MAX_ENTRIES="${RESTORE_MAX_ENTRIES:-100000}"
die() { echo "$*" >&2; exit 1; }
[ -f "$ARCHIVE" ] || die "archive '$ARCHIVE' not found"
STATE="${STATE%/}"
PARENT="$(dirname "$STATE")"
NAME="$(basename "$STATE")"
mkdir -p "$PARENT"
PARENT="$(cd -P "$PARENT" && pwd)"
STATE="$PARENT/$NAME"

WORK="$(mktemp -d "$PARENT/.$NAME.restore-XXXXXX")"
STAGING="$WORK/state"
MOVED=()
rollback() {
  local i rel ok=1
  for ((i = ${#MOVED[@]} - 1; i >= 0; i--)); do
    rel="${MOVED[$i]}"
    mv "$STAGING/$rel" "$STATE/$rel" 2>/dev/null || { ok=0; echo "could not put back '$rel' (left in $STAGING)" >&2; }
  done
  if [ "$ok" -eq 1 ]; then rm -rf "$WORK"; fi
}
trap rollback EXIT

# Every check and the extraction read this one private copy, so the archive
# cannot change between being checked and being extracted.
COPY="$WORK/archive.tar.gz"
cp "$ARCHIVE" "$COPY"

# The tar stream size bounds the uncompressed payload; head stops a bomb early.
bytes="$(gzip -dc "$COPY" | head -c "$((MAX_BYTES + 1))" | wc -c | tr -d " " || true)"
[ "$bytes" -le "$MAX_BYTES" ] || die "archive expands past $MAX_BYTES bytes; refusing"
entries="$(tar -tzf "$COPY" | head -n "$((MAX_ENTRIES + 1))" | wc -l | tr -d " " || true)"
[ "$entries" -le "$MAX_ENTRIES" ] || die "archive has more than $MAX_ENTRIES entries; refusing"

# Refuse a symlink under $1 that leads outside the state dir: carry-over or a
# later colima run would write through it. An absolute target is allowed
# only inside the state dir; a relative one may not climb with `..`.
check_links() {
  local link target
  while IFS= read -r -d '' link; do
    target="$(readlink "$link")"
    case "$target" in
      .. | ../* | */../* | */..) die "'$link' -> '$target' leaves the state dir; refusing" ;;
      "$STATE" | "$STATE"/*) ;;
      /*) die "'$link' -> '$target' leaves the state dir; refusing" ;;
    esac
  done < <(find "$1" -type l -print0)
}
if [ -d "$STATE" ]; then check_links "$STATE"; fi

# Never restore owners or setuid bits from the archive. bsdtar has no
# --no-overwrite-dir equivalent.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  SAFE=(--force-local --no-same-owner --no-same-permissions --no-overwrite-dir)
else
  SAFE=(--no-same-owner --no-same-permissions)
fi
mkdir "$STAGING"
tar "${SAFE[@]}" -xzf "$COPY" -C "$STAGING"
rm -f "$COPY"
check_links "$STAGING"

# Move entries under $STATE/$1 with no counterpart in staging across. A path
# that is a directory on one side only is refused: the swap would drop it.
carry_over() {
  local rel="$1" old new name
  for old in "$STATE/$rel"* "$STATE/$rel".[!.]* "$STATE/$rel"..?*; do
    [ -e "$old" ] || [ -L "$old" ] || continue
    name="${old##*/}"
    new="$STAGING/$rel$name"
    if [ ! -e "$new" ] && [ ! -L "$new" ]; then
      mv "$old" "$new"
      MOVED+=("$rel$name")
    elif [ -d "$old" ] && [ ! -L "$old" ] && [ -d "$new" ] && [ ! -L "$new" ]; then
      carry_over "$rel$name/"
    elif { [ -d "$old" ] && [ ! -L "$old" ]; } || { [ -d "$new" ] && [ ! -L "$new" ]; }; then
      die "'$rel$name' is a directory on one side only; refusing"
    fi
  done
}

if [ -e "$STATE" ] || [ -L "$STATE" ]; then
  carry_over ""
  ASIDE="$(mktemp -d "$PARENT/.$NAME.old-XXXXXX")"
  mv "$STATE" "$ASIDE/state"
  if ! mv "$STAGING" "$STATE"; then
    trap - EXIT
    if mv "$ASIDE/state" "$STATE"; then
      rmdir "$ASIDE"
      rollback
      die "failed to move the restore into '$STATE'; previous state put back"
    fi
    die "failed to move the restore into '$STATE'; previous state is in '$ASIDE/state', the restore in '$STAGING'"
  fi
  trap - EXIT
  rm -rf "$ASIDE" "$WORK" || echo "previous state left in '$ASIDE/state'" >&2
else
  mv "$STAGING" "$STATE"
  trap - EXIT
  rm -rf "$WORK"
fi
echo "restored engine state into $STATE"
