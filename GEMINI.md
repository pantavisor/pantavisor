# Pantavisor

Pantavisor is a container-based runtime for embedded Linux systems. It handles container orchestration, atomic OTA updates, remote management, and inter-container communication.

## Key Components

| Component | Description |
|-----------|-------------|
| `xconnect/` | Service mesh daemon with plugins (unix, rest, dbus, drm, wayland) |
| `ctrl/` | REST API: /xconnect-graph, /daemons, /signal, /containers, /groups endpoints |
| `tools/pvcurl` | Lightweight curl wrapper using nc for HTTP-over-Unix-socket |
| `tools/pvcontrol` | CLI wrapper around pvcurl for pv-ctrl operations |
| `utils/tsh.c` | Daemon stdout/stderr capture via logserver |

## Documentation

### Reference (`docs/reference/`)

API and format specifications, versioned with each Pantavisor release. Always update when modifying the corresponding feature.

| Document | Location | Description |
|----------|----------|-------------|
| **Control Socket** | [docs/reference/pantavisor-commands.md](docs/reference/pantavisor-commands.md) | pv-ctrl HTTP endpoints (containers → PV) |
| **xconnect** | [docs/reference/pantavisor-xconnect.md](docs/reference/pantavisor-xconnect.md) | Service mesh manifests and mediation patterns |
| **xconnect Spec** | [xconnect/XCONNECT.md](xconnect/XCONNECT.md) | Technical specification and plugin architecture |
| **Configuration** | [docs/reference/pantavisor-configuration.md](docs/reference/pantavisor-configuration.md) | All configuration keys, defaults, and levels |
| **Log Sockets** | [docs/reference/logserver-sockets.md](docs/reference/logserver-sockets.md) | Logserver unix sockets reference |
| **Metadata** | [docs/reference/pantavisor-metadata.md](docs/reference/pantavisor-metadata.md) | User and device metadata reference |
| **State Format** | [docs/reference/pantavisor-state-format-v2.md](docs/reference/pantavisor-state-format-v2.md) | state.json format (v2) |
| **Tools** | [docs/reference/pantavisor-tools.md](docs/reference/pantavisor-tools.md) | pventer, pvcurl, pvcontrol, pvtx — on-device CLI tools |

### Technical Overview (`docs/overview/`)

Feature overview intended to be read top-to-bottom as a book. Not versioned — always reflects current master. Synced to the docs site under the "Technical Overview" section.

| Document | Location | Description |
|----------|----------|-------------|
| **Architecture** | [docs/overview/pantavisor-architecture.md](docs/overview/pantavisor-architecture.md) | High-level architecture and state machine |
| **Revisions** | [docs/overview/revisions.md](docs/overview/revisions.md) | Revision concept and state JSON structure |
| **BSP** | [docs/overview/bsp.md](docs/overview/bsp.md) | Kernel, modules, firmware, bootloader |
| **Containers** | [docs/overview/containers.md](docs/overview/containers.md) | Container runtime, groups, roles, status |
| **Updates** | [docs/overview/updates.md](docs/overview/updates.md) | Update flow, states, transitions |
| **Storage** | [docs/overview/storage.md](docs/overview/storage.md) | On-disk layout, logs, metadata, integrity |
| **Disks** | [docs/overview/disks.md](docs/overview/disks.md) | Disk types, dual mode, dm-crypt, boot sequence |
| **Remote Control** | [docs/overview/remote-control.md](docs/overview/remote-control.md) | Pantacor Hub client and remote controllers |
| **Local Control** | [docs/overview/local-control.md](docs/overview/local-control.md) | pv-ctrl socket, Pantabox, pvcontrol |
| **Configuration** | [docs/overview/pantavisor-configuration-levels.md](docs/overview/pantavisor-configuration-levels.md) | Configuration levels and precedence |
| **Init Mode** | [docs/overview/init-mode.md](docs/overview/init-mode.md) | Embedded, standalone, appengine modes |
| **Watchdog** | [docs/overview/watchdog.md](docs/overview/watchdog.md) | Watchdog configuration and modes |
| **Hooks** | [docs/overview/hooks.md](docs/overview/hooks.md) | System lifecycle hooks |
| **Inter-Container Communication** | [docs/overview/xconnect.md](docs/overview/xconnect.md) | xconnect service mesh overview |

## Docs Pipeline

Changes to `docs/**` on master automatically trigger a GitLab CI pipeline in the docs repo (via GitHub Action → GitLab CI trigger). The docs pipeline:
1. Updates the `content/pantavisor-src` submodule to latest master
2. Copies `docs/reference/` files into versioned directories (`content/reference/<version>/`)
3. Copies `docs/overview/` files into `content/` (the docs site root, overwriting existing)
4. Regenerates the `mkdocs.yml` navigation for the Reference Pages section
5. Auto-commits and pushes if anything changed

## Architecture

- **pv-xconnect**: Standalone mediation service for cross-container communication
  - Detailed design in [xconnect/XCONNECT.md](xconnect/XCONNECT.md)
  - Plugin-driven: unix, rest, dbus, drm, wayland
  - Runs as a managed daemon (DM_ALL mode, all init modes)
- **Pantavisor as Security Broker**: Containers use logical service names, access granted via explicit `run.json` requirements
- **Build flag**: `PANTAVISOR_XCONNECT` (CMake), controlled by `xconnect` in `PANTAVISOR_FEATURES` (Yocto)

## Development Guidelines

- **Documentation**: Always check if [reference documentation](docs/reference/) should be updated after making changes to the code.
  - **Reference links from overview docs**: Link to `../../../reference/legacy/` for content that already exists there, or `../../../reference/027/` (current development tag) for new content appearing for the first time.
  - **Overview docs**: Use relative links within `docs/overview/` (e.g., `containers.md#restart-policy`).
- **Commits**: Always use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (v1.0.0) for all commit messages.
- **Formatting**: Run `clang-format -i` on modified `.c`/`.h` files before committing
- **API testing**: Use `pvcurl` (not `curl`) inside appengine containers
- **Build**: Use `kas/with-workspace.yaml` overlay for local source development
