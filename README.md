<p align="center">
  <img src="assets/icon-256.png" width="120" alt="docker" />
</p>

# docker

Adapts the Docker Engine + Compose (and Colima / Podman) into [orca](https://github.com/argyle-labs/orca)'s containers domain — it provisions, upgrades, backs up, and drives a container runtime on any host.

A first-party orca plugin (containers backend). This is a **backend/adapter**: it has no service of its own, it manages the container runtime and the stacks you run on it.

## What it manages

- **Provision / upgrade** a container runtime — **Docker Engine**, **Colima**, or **Podman** — on any target (macOS, Alpine, Debian/Ubuntu, CachyOS/Arch, Fedora, and atomic/immutable hosts like Bazzite).
- **Manage Compose stacks as config** — register a stack, then **view / edit / deploy** its compose file over cli / api / mcp (orca is the config manager), plus the full `up` / `down` / `restart` / `start` / `stop` / `build` / `pull` / `logs` lifecycle.
- **Inventory** — list / inspect containers through orca's five-verb surface.
- **Back up / restore** the engine's persistent state.

Everything here works **two ways, and both are supported and documented**:

- **With orca** — orca fully manages it: call the `docker.*` tools and orca runs the right thing on the host.
- **Without orca (standalone)** — run the shipped `scripts/*.sh` directly. These are the *same* scripts orca invokes, so the two paths never diverge.

---

## With orca (orca manages everything)

Once orca is on the host you never touch the scripts — drive the tools. Payloads are typed; examples live in [`examples/`](examples/).

| tool | what it does | key args |
| --- | --- | --- |
| `docker.install` | provision + start a runtime (`scripts/install.sh`) | `runtime`: `docker`\|`colima`\|`podman` |
| `docker.engine_update` | upgrade the runtime (`scripts/update.sh`) | `runtime` |
| `docker.update` | run a Compose lifecycle action against a stack | `path`, `action`, optional `service` |
| `docker.list` | host docker resources: engine status + registered runtimes; plus compose services (`path`) or a project scan (`root`) | optional `path` \| `root` |
| `docker.detail` | inspect one Compose project: services, logs, stats | `path`, optional `service`, `tail` |
| `docker.create` | register a docker runtime | `runtime_name`, one of `socket_path`\|`host`\|`url` |
| `docker.delete` | remove a registered docker runtime | `runtime` |
| `docker.backup` | archive engine state to a `.tar.gz` | `destination`, optional `state_path` |
| `docker.restore` | restore engine state from an archive | `archive`, optional `state_path` |

> Individual **containers** and managed **Compose stacks** are not `docker.*` tools — they are surfaced on orca's generic five-verb **unit** surface (`docker.__unit.*`). The `docker.*` tools above manage the runtime, its registered engines, and one-off Compose projects by path. See **[Managing Compose stacks](#managing-compose-stacks-orca-as-config-manager)** below.

```jsonc
// docker.install — provision colima (default), Docker Engine, or podman
{ "runtime": "docker" }

// docker.update — bring a Compose stack up
{ "path": "/srv/stacks/myapp", "action": "up" }

// docker.detail — inspect a Compose project (services + logs + stats)
{ "path": "/srv/stacks/myapp", "tail": 200 }

// docker.create — register a docker runtime (needs socketPath | host | url)
{ "runtimeName": "remote-host", "host": "tcp://10.0.0.5:2375" }

// docker.backup / docker.restore
{ "destination": "/srv/backups" }
{ "archive": "/srv/backups/docker-engine-state-20260702-120000.tar.gz" }
```

The lifecycle tools are `local_only` — they act on the host orca is running on.

### Managing Compose stacks (orca as config manager)

orca is your **config manager** for `docker compose`: register a stack once and
then **view / edit / deploy** its compose file entirely over the cli / api / mcp —
no need to SSH in and hand-edit YAML. A *stack* is a name bound to a project
directory on the host; orca owns the registry of managed stacks (persisted in its
per-plugin store) while the compose file stays canonical on disk.

Stacks ride orca's generic **unit** surface as the `stack` kind (the same surface
the [dockge](https://github.com/argyle-labs/dockge) plugin uses, so one stack
vocabulary spans both). Every operation is available through `unit` list / detail
/ update / create / upsert / delete with `kind = "stack"`:

| operation | verb | payload |
| --- | --- | --- |
| **list** stacks + service status | `list` | `query.kind = "stack"` |
| **view** compose YAML + `.env` + status | `detail` | `id.kind = "stack"`, `id.id = <name>` |
| **tail** stack logs | `detail` | `id.kind = "stack"`, `query.kind = "logs"` |
| **edit** (rewrite YAML/env, no deploy) | `update` | `action = "edit"`, `{ compose_yaml?, compose_env? }` |
| **deploy / lifecycle** | `update` | `action = up`\|`down`\|`start`\|`stop`\|`restart`\|`build`\|`pull` |
| **register + deploy** (add-only) | `create` | `action = "deploy"`, deploy payload |
| **register-or-replace + deploy** | `upsert` | `action = "set"`, deploy payload |
| **deregister** (leaves containers running) | `delete` | `id.kind = "stack"`, `id.id = <name>` |

```jsonc
// create (action=deploy) — write a brand-new stack's compose file and bring it up.
// Omit compose_yaml to register an existing on-disk compose file as-is.
{
  "action": "deploy",
  "payload": {
    "name": "myapp",
    "dir": "/srv/stacks/myapp",
    "compose_yaml": "services:\n  web:\n    image: nginx\n    ports: [\"8080:80\"]\n",
    "compose_env": "TZ=UTC\n",
    "deploy": true
  }
}

// detail (view) — returns { name, dir, file, compose_yaml, compose_env, services[] }
{ "id": { "manager": "docker@host", "kind": "stack", "id": "myapp", "name": "myapp" } }

// update (edit) — change the YAML without redeploying
{ "id": { "kind": "stack", "id": "myapp", ... }, "action": "edit",
  "payload": { "compose_yaml": "services:\n  web:\n    image: nginx:1.27\n" } }

// update (deploy the edit) — bring the changed stack up
{ "id": { "kind": "stack", "id": "myapp", ... }, "action": "up" }
```

To **tear down** a stack, run `update action=down` first, then `delete` to
deregister — `delete` alone only stops orca managing it; it never stops your
running containers out from under you.

---

## Without orca (standalone)

The plugin ships the scripts orca runs. Use them directly on any target.

### 1. Install a container runtime

```sh
./scripts/install.sh [docker|colima|podman]
# default: colima on macOS, docker on Linux
```

The script detects the OS + package manager and installs the runtime the right way. It is **idempotent** — a running runtime is left untouched. Per-target behavior:

| target | `docker` | `colima` | `podman` |
| --- | --- | --- | --- |
| **macOS** | colima + `brew install docker` | `brew install colima docker` | `brew install podman` + `podman machine` |
| **Alpine** (apk/OpenRC) | `apk add docker docker-cli-compose` + `rc-update` | via Homebrew | `apk add podman` |
| **Debian / Ubuntu** | official `get.docker.com` (docker-ce) + systemd | via Homebrew | `apt-get install podman` |
| **CachyOS / Arch** (pacman) | `pacman -S docker docker-compose` + systemd | via Homebrew | `pacman -S podman` |
| **Fedora / RHEL** (dnf) | official `get.docker.com` (docker-ce) | via Homebrew | `dnf install podman` |
| **Atomic / immutable** (Bazzite, Silverblue, Kinoite — `rpm-ostree`) | `rpm-ostree install docker` **(reboot required)**; podman is preferred here | n/a | preinstalled; else `rpm-ostree install podman` |

> **Homebrew bootstrap:** the script installs Homebrew itself when a path needs it (macOS, or Linuxbrew for colima).
>
> **Atomic hosts:** `/usr` is read-only, so packages are *layered* with `rpm-ostree` and only take effect **after a reboot**. Podman ships preinstalled and is the recommended runtime; on Bazzite you can also run `ujust install-docker`.

Manual equivalents, if you prefer not to run the script:

```sh
# Debian/Ubuntu/Fedora — official Docker Engine
curl -fsSL https://get.docker.com | sh && sudo systemctl enable --now docker

# Alpine
sudo apk add docker docker-cli-compose && sudo rc-update add docker default && sudo service docker start

# Arch / CachyOS
sudo pacman -S --needed docker docker-compose && sudo systemctl enable --now docker

# macOS (no native daemon — colima provides dockerd)
brew install colima docker && colima start

# Podman anywhere
sudo apk add podman   # or apt-get/pacman/dnf install podman ; macOS: brew install podman && podman machine init && podman machine start
```

### 2. Deploy a stack (Compose)

Point Compose at a project directory and bring it up:

```sh
cd /srv/stacks/myapp     # contains docker-compose.yml
docker compose up -d
docker compose ps
```

Minimal `docker-compose.yml`:

```yaml
services:
  whoami:
    image: traefik/whoami
    ports:
      - "8080:80"
    restart: unless-stopped
```

Lifecycle actions mirror the `docker.update` tool: `up`, `down`, `restart`, `start`, `stop`, `build`, `pull`, `logs`.

### 3. Update the runtime

```sh
./scripts/update.sh [docker|colima|podman]
```

Upgrades the runtime via the host package manager (or `rpm-ostree upgrade` on atomic hosts, `brew upgrade` on macOS) and restarts the daemon.

### 4. Back up / restore engine state

```sh
# archive the colima/lima profile (or a supplied state dir) to a timestamped tarball
./scripts/backup.sh /srv/backups            # prints the archive path
# restore it (pair with install.sh to rebuild a host)
./scripts/restore.sh /srv/backups/docker-engine-state-YYYYmmdd-HHMMSS.tar.gz
```

> **What's backed up:** the *engine's* state (the colima/lima VM profile + config), so a reprovisioned host can be rebuilt. **Container data** lives in named volumes / bind mounts and is backed up per-stack (e.g. `docker run --rm -v <vol>:/data -v $PWD:/out alpine tar czf /out/<vol>.tgz -C /data .`).

### Verify

```sh
docker info      # daemon reachable
docker ps        # running containers
podman info      # if using podman
```

---

## Layout

- `src/` — the plugin (pure Rust): the containers/compose/engine adapters, the five-verb `docker.*` surface, and the `docker.{install,engine_update,backup,restore}` lifecycle tools.
- `scripts/` — the install / update / backup / restore helpers orca drives (and you can run standalone).
- `examples/` — sample tool payloads.
- `assets/` — plugin icon.
