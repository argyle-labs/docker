#!/usr/bin/env bash
# Provision a container runtime on this host, across every supported target.
# Driven by `docker.install`.
#
# Usage: install.sh [runtime]
#   runtime ∈ docker | colima | podman   (default: colima on macOS, docker on Linux)
#
# Targets: macOS (brew), Alpine (apk/OpenRC), Debian/Ubuntu (official docker-ce),
#          CachyOS/Arch (pacman), Fedora/RHEL (dnf), and atomic/immutable
#          rpm-ostree distros (Bazzite, Silverblue, Kinoite, Bluefin).
# Idempotent: a present, running runtime is left untouched.
set -euo pipefail

RUNTIME="${1:-auto}"

# ---- target detection -------------------------------------------------------
OS="$(uname -s)"                       # Darwin | Linux
DISTRO_ID=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-}"
fi
ATOMIC=0
if [ -f /run/ostree-booted ] || command -v rpm-ostree >/dev/null 2>&1; then
  ATOMIC=1
fi

have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" -ne 0 ] && have sudo; then SUDO="sudo"; fi

# default runtime per platform
if [ "$RUNTIME" = auto ]; then
  if [ "$OS" = Darwin ]; then RUNTIME=colima; else RUNTIME=docker; fi
fi

if docker info >/dev/null 2>&1 && [ "$RUNTIME" != podman ]; then
  echo "docker runtime already running; nothing to do"; exit 0
fi
if [ "$RUNTIME" = podman ] && podman info >/dev/null 2>&1; then
  echo "podman already available; nothing to do"; exit 0
fi

# ---- homebrew bootstrap (macOS, or Linuxbrew) -------------------------------
install_brew() {
  have brew && return 0
  echo "installing Homebrew..."
  NONINTERACTIVE=1 /bin/bash -c \
    "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  local p
  for p in /opt/homebrew/bin /usr/local/bin /home/linuxbrew/.linuxbrew/bin; do
    if [ -x "$p/brew" ]; then eval "$("$p/brew" shellenv)"; break; fi
  done
}

atomic_note() {
  cat >&2 <<'EOF'
NOTE: atomic/immutable host (rpm-ostree). Packages are layered onto the base
image and only take effect AFTER A REBOOT. Podman is preinstalled here and is
the recommended runtime; on Bazzite you can also run `ujust install-docker`.
EOF
}

# ---- docker engine ----------------------------------------------------------
install_docker() {
  case "$OS" in
    Darwin)
      # no native daemon on macOS: colima provides dockerd, plus the docker CLI
      install_brew
      brew install docker
      install_colima
      return 0 ;;
  esac
  # Linux
  if [ "$ATOMIC" = 1 ]; then
    atomic_note
    $SUDO rpm-ostree install --idempotent docker docker-compose
    echo "layered docker via rpm-ostree — reboot, then: sudo systemctl enable --now docker"
    return 0
  fi
  case "$DISTRO_ID" in
    alpine)
      $SUDO apk add --no-cache docker docker-cli-compose
      $SUDO rc-update add docker default
      $SUDO service docker start ;;
    arch|cachyos|endeavouros|manjaro)
      $SUDO pacman -Sy --noconfirm --needed docker docker-compose
      $SUDO systemctl enable --now docker ;;
    debian|ubuntu|raspbian|linuxmint|pop|fedora|centos|rhel|rocky|almalinux)
      # Docker's official convenience script installs docker-ce from the vendor repo
      curl -fsSL https://get.docker.com | $SUDO sh
      $SUDO systemctl enable --now docker 2>/dev/null || true ;;
    *)
      echo "unknown distro '$DISTRO_ID'; trying Docker convenience script" >&2
      curl -fsSL https://get.docker.com | $SUDO sh
      $SUDO systemctl enable --now docker 2>/dev/null || true ;;
  esac
}

# ---- colima -----------------------------------------------------------------
install_colima() {
  install_brew                 # colima ships via Homebrew on macOS and Linux
  brew install colima docker
  colima start
}

# ---- podman -----------------------------------------------------------------
install_podman() {
  case "$OS" in
    Darwin)
      install_brew
      brew install podman
      podman machine inspect >/dev/null 2>&1 || podman machine init
      podman machine start 2>/dev/null || true
      return 0 ;;
  esac
  if [ "$ATOMIC" = 1 ]; then
    if have podman; then echo "podman already present (atomic base)"; return 0; fi
    atomic_note
    $SUDO rpm-ostree install --idempotent podman
    echo "layered podman via rpm-ostree — reboot to use it"
    return 0
  fi
  case "$DISTRO_ID" in
    alpine)                       $SUDO apk add --no-cache podman ;;
    arch|cachyos|endeavouros|manjaro) $SUDO pacman -Sy --noconfirm --needed podman ;;
    debian|ubuntu|raspbian|linuxmint|pop) $SUDO apt-get update && $SUDO apt-get install -y podman ;;
    fedora|centos|rhel|rocky|almalinux)   $SUDO dnf install -y podman ;;
    *) echo "unknown distro '$DISTRO_ID' for podman" >&2; exit 1 ;;
  esac
}

case "$RUNTIME" in
  docker) install_docker ;;
  colima) install_colima ;;
  podman) install_podman ;;
  *) echo "unknown runtime: $RUNTIME (want docker|colima|podman)" >&2; exit 1 ;;
esac

echo "container runtime provisioned ($RUNTIME on ${DISTRO_ID:-$OS})"
