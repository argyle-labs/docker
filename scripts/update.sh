#!/usr/bin/env bash
# Upgrade the docker engine on this host. Driven by `docker.engine_update`.
# Usage: update.sh [colima|engine]
set -euo pipefail
FLAVOR="${1:-colima}"

case "$FLAVOR" in
  colima)
    if command -v brew >/dev/null 2>&1; then
      brew upgrade colima docker || true
    fi
    colima stop || true
    colima start
    ;;
  engine)
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update
      sudo apt-get install -y --only-upgrade docker.io
      sudo systemctl restart docker
    else
      echo "engine flavor requires apt-get" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown flavor: $FLAVOR (want colima|engine)" >&2
    exit 1
    ;;
esac
echo "docker engine updated ($FLAVOR)"
