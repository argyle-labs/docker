#!/usr/bin/env bash
# Provision the docker engine on this host. Driven by `docker.install`.
# Usage: install.sh [colima|engine]
# Idempotent: a present, running engine is left untouched.
set -euo pipefail
FLAVOR="${1:-colima}"

if docker info >/dev/null 2>&1; then
  echo "docker engine already running; nothing to do"
  exit 0
fi

case "$FLAVOR" in
  colima)
    if ! command -v colima >/dev/null 2>&1; then
      if command -v brew >/dev/null 2>&1; then
        brew install colima docker
      else
        echo "colima not found and no brew available; install colima manually" >&2
        exit 1
      fi
    fi
    colima start
    ;;
  engine)
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update
      sudo apt-get install -y docker.io
      sudo systemctl enable --now docker
    else
      echo "engine flavor requires apt-get; use colima on this host" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown flavor: $FLAVOR (want colima|engine)" >&2
    exit 1
    ;;
esac
echo "docker engine provisioned ($FLAVOR)"
