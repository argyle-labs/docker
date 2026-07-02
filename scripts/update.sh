#!/usr/bin/env bash
# Upgrade a container runtime on this host, across every supported target.
# Driven by `docker.engine_update`.
#
# Usage: update.sh [runtime]   runtime ∈ docker | colima | podman
#   (default: colima on macOS, docker on Linux)
set -euo pipefail

RUNTIME="${1:-auto}"

OS="$(uname -s)"
DISTRO_ID=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-}"
fi
ATOMIC=0
if [ -f /run/ostree-booted ] || command -v rpm-ostree >/dev/null 2>&1; then ATOMIC=1; fi

have() { command -v "$1" >/dev/null 2>&1; }
SUDO=""
if [ "$(id -u)" -ne 0 ] && have sudo; then SUDO="sudo"; fi

if [ "$RUNTIME" = auto ]; then
  if [ "$OS" = Darwin ]; then RUNTIME=colima; else RUNTIME=docker; fi
fi

upgrade_brew_pkg() { have brew && brew upgrade "$@" || true; }

update_docker() {
  case "$OS" in
    Darwin) upgrade_brew_pkg docker colima; colima stop || true; colima start; return 0 ;;
  esac
  if [ "$ATOMIC" = 1 ]; then
    $SUDO rpm-ostree upgrade
    echo "rpm-ostree upgraded — reboot to apply"; return 0
  fi
  case "$DISTRO_ID" in
    alpine) $SUDO apk update && $SUDO apk upgrade docker docker-cli-compose && $SUDO service docker restart ;;
    arch|cachyos|endeavouros|manjaro) $SUDO pacman -Syu --noconfirm docker docker-compose && $SUDO systemctl restart docker ;;
    debian|ubuntu|raspbian|linuxmint|pop|fedora|centos|rhel|rocky|almalinux)
      # docker-ce installed from the vendor repo upgrades with the system package manager
      if have apt-get; then $SUDO apt-get update && $SUDO apt-get install -y --only-upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin
      elif have dnf; then $SUDO dnf upgrade -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      fi
      $SUDO systemctl restart docker 2>/dev/null || true ;;
    *) echo "unknown distro '$DISTRO_ID'; upgrade docker manually" >&2; exit 1 ;;
  esac
}

update_colima() { upgrade_brew_pkg colima docker; colima stop || true; colima start; }

update_podman() {
  case "$OS" in
    Darwin) upgrade_brew_pkg podman; podman machine stop || true; podman machine start || true; return 0 ;;
  esac
  if [ "$ATOMIC" = 1 ]; then $SUDO rpm-ostree upgrade; echo "rpm-ostree upgraded — reboot to apply"; return 0; fi
  case "$DISTRO_ID" in
    alpine) $SUDO apk update && $SUDO apk upgrade podman ;;
    arch|cachyos|endeavouros|manjaro) $SUDO pacman -Syu --noconfirm podman ;;
    debian|ubuntu|raspbian|linuxmint|pop) $SUDO apt-get update && $SUDO apt-get install -y --only-upgrade podman ;;
    fedora|centos|rhel|rocky|almalinux) $SUDO dnf upgrade -y podman ;;
    *) echo "unknown distro '$DISTRO_ID' for podman" >&2; exit 1 ;;
  esac
}

case "$RUNTIME" in
  docker) update_docker ;;
  colima) update_colima ;;
  podman) update_podman ;;
  *) echo "unknown runtime: $RUNTIME (want docker|colima|podman)" >&2; exit 1 ;;
esac

echo "container runtime updated ($RUNTIME on ${DISTRO_ID:-$OS})"
