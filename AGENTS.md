# Pantavisor

Pantavisor is a container-based runtime for embedded Linux systems. It handles container orchestration, atomic OTA updates, remote management, and inter-container communication.

## Key Components

| Component | Description |
|-----------|-------------|
| `xconnect/` | Service mesh daemon with plugins (unix, rest, dbus, drm, wayland) |
| `ctrl/` | REST API: /xconnect-graph, /daemons, /signal, /containers, /groups endpoints |
| `appengine/` | `pv-appengine` entrypoint, baseline config and rev0 state for running Pantavisor as PID 1 in a container |
| `tools/pvcurl` | Lightweight curl wrapper using nc for HTTP-over-Unix-socket |
| `tools/pvcontrol` | CLI wrapper around pvcurl for pv-ctrl operations |
| `utils/tsh.c` | Daemon stdout/stderr capture via logserver |

## Documentation

**Read [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) before writing or editing anything under `docs/`.** It is the
single source of truth for placement, table conventions, frontmatter, and link conventions. The
essentials:

| Folder | Answers | Contains | Never contains |
|--------|---------|----------|----------------|
| `docs/overview/` | *How does this work, and why?* | Prose, rationale, diagrams, worked examples | Exhaustive key/field/endpoint tables — link to reference |
| `docs/reference/` | *What exactly are the valid values?* | Complete tables: keys, values, defaults, fields, status codes | Multi-paragraph explanation — link to overview |
| `docs/tools/` | *How do I invoke it?* | CLI synopsis, flags, exit codes, worked invocations | Subsystem theory |

Reference is authoritative and complete; overview is readable top-to-bottom and never complete.
If a value is enumerable from the code, it belongs in a reference table — never write `string`
where the parser accepts a fixed set of tokens.

### Every change gets a documentation pass

After any change — a new feature, a change to an existing one, a fix that alters behaviour — stop
and ask whether the **overview** and the **reference** still describe reality. Usually one of them
needs an edit and often both do: the reference because a value, field or endpoint moved, and the
overview because the explanation around it no longer matches.

Answering "no change needed" is a fine outcome, but it should be an answer, not an omission.

Run `scripts/check-docs.sh` before committing. It mechanically verifies configuration keys, control
socket routes and device metadata keys against the code, and validates frontmatter, index membership
and links — but it only catches what is enumerable. Whether the prose still makes sense is on you.

### Reference (`docs/reference/`)

API and format specifications, versioned with each Pantavisor release. Always update when modifying the corresponding feature.

| Document | Location | Description |
|----------|----------|-------------|
| **State Format** | [docs/reference/pantavisor-state-format-v2.md](docs/reference/pantavisor-state-format-v2.md) | state.json format (v2) |
| **Configuration** | [docs/reference/pantavisor-configuration.md](docs/reference/pantavisor-configuration.md) | All configuration keys, values, defaults, and levels |
| **Control Socket** | [docs/reference/pantavisor-commands.md](docs/reference/pantavisor-commands.md) | pv-ctrl HTTP endpoints (containers → PV) |
| **xconnect** | [docs/reference/pantavisor-xconnect.md](docs/reference/pantavisor-xconnect.md) | Service mesh manifests and mediation patterns |
| **xconnect Spec** | [xconnect/XCONNECT.md](xconnect/XCONNECT.md) | Technical specification and plugin architecture |
| **Metadata** | [docs/reference/pantavisor-metadata.md](docs/reference/pantavisor-metadata.md) | User and device metadata reference |
| **Log Sockets** | [docs/reference/logserver-sockets.md](docs/reference/logserver-sockets.md) | Logserver sockets, protocols, outputs, timestamp formats |
| **IPAM** | [docs/reference/pantavisor-ipam.md](docs/reference/pantavisor-ipam.md) | Address pool schema, per-container assignment, backend-plugin hook |
| **Hooks** | [docs/reference/pantavisor-hooks.md](docs/reference/pantavisor-hooks.md) | Hook points, hook environment variables, failure semantics |
| **Power** | [docs/reference/pantavisor-power.md](docs/reference/pantavisor-power.md) | Power modes, wakelock scopes, `PV_POWER_*` keys, `/wakelocks` |

### Tools (`docs/tools/`)

On-device CLI tool docs, versioned with each Pantavisor release alongside `docs/reference/`.

| Document | Location | Description |
|----------|----------|-------------|
| **Tools** | [docs/tools/pantavisor-tools.md](docs/tools/pantavisor-tools.md) | pventer, pvcurl, pvcontrol, pvtx — on-device CLI tools |
| **pvcontrol** | [docs/tools/pvcontrol.md](docs/tools/pvcontrol.md) | Full `pvcontrol` CLI reference with worked examples |

### Technical Overview (`docs/overview/`)

Feature overview intended to be read top-to-bottom as a book, versioned with each Pantavisor release alongside `docs/reference/`. Synced to the docs site under the "Technical Overview" section.

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
| **IPAM** | [docs/overview/ipam.md](docs/overview/ipam.md) | Container IP address management: pools, allocation, network namespaces |
| **Inter-Container Communication** | [docs/overview/xconnect.md](docs/overview/xconnect.md) | xconnect service mesh overview |
| **Hooks** | [docs/overview/hooks.md](docs/overview/hooks.md) | System lifecycle hooks |
| **Watchdog** | [docs/overview/watchdog.md](docs/overview/watchdog.md) | Watchdog configuration and modes |
| **Power and Wakelocks** | [docs/overview/wakelocks.md](docs/overview/wakelocks.md) | Suspend, wakelocks, managed power mode |
| **Configuration Levels** | [docs/overview/pantavisor-configuration-levels.md](docs/overview/pantavisor-configuration-levels.md) | Configuration levels and precedence |
| **Init Mode** | [docs/overview/init-mode.md](docs/overview/init-mode.md) | Embedded, standalone, appengine modes |

## Docs Pipeline

The `docs/` folder is published on [docs.pantavisor.io/reference](https://docs.pantavisor.io/reference) by the [docs.pantavisor](https://github.com/pantavisor/docs.pantavisor) Docusaurus site, versioned per release rather than by folder:
1. Each meta-pantavisor release publishes a docs tarball, tracked in [`releases.json`](https://pantavisor-ci.s3.amazonaws.com/meta-pantavisor/releases.json) on S3. The tarball bundles this repo's `docs/` as `pantavisor/` and meta-pantavisor's `docs/` as a sibling `meta-pantavisor/` directory.
2. `scripts/sync-reference.mjs` + `migrate-docs.js` in docs.pantavisor download the tarball for each published version listed in `releases.json` and generate a versioned instance at `/reference/<version>/pantavisor/...`. This covers everything under `docs/` — `docs/reference/`, `docs/overview/`, and `docs/tools/` alike — snapshotted together per release.
3. Hand-authored, versionless guides live in the site's `curated/` instance (served at the site root, e.g. `/build`, `/install`, `/operate`); they are never generated from this repo.
4. Pages marked `draft: true` — [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) and [docs/issues.md](docs/issues.md) — are excluded from the published build.
5. `docs.pantahub.com`, the retired MkDocs site, still 301-redirects into some of those published URLs. A page's path under `docs/` is its URL, so renaming, moving, deleting or drafting one of the pages frozen in [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md#page-urls-are-permanent) turns a live redirect into a 404. `scripts/check-docs.sh` enforces the list.

## Architecture

- **pv-xconnect**: Standalone mediation service for cross-container communication
  - Detailed design in [xconnect/XCONNECT.md](xconnect/XCONNECT.md)
  - Plugin-driven: unix, rest, dbus, drm, wayland
  - Runs as a managed daemon (DM_ALL mode, all init modes)
- **Pantavisor as Security Broker**: Containers use logical service names, access granted via explicit `run.json` requirements
- **Build flag**: `PANTAVISOR_XCONNECT` (CMake), controlled by `xconnect` in `PANTAVISOR_FEATURES` (Yocto)

## Development Guidelines

- **Configuration keys**: the `PV_*`/`PH_*` env-var name in `entries[]` (config.c) is the only identity of a key. The dotted `aliases[]` table is frozen legacy: never add an alias for a new entry, and write docs, commits, and examples in the env-var form only (see the note in [docs/reference/pantavisor-configuration.md](docs/reference/pantavisor-configuration.md)).
- **Documentation**: Every change gets a [documentation pass](#every-change-gets-a-documentation-pass) in the same commit — consider both the overview and the reference. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for what belongs where, and run `scripts/check-docs.sh` before committing.
- **Commits**: Always use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (v1.0.0) for all commit messages.
- **Formatting**: Run `clang-format -i` on modified `.c`/`.h` files before committing
- **API testing**: Use `pvcurl` (not `curl`) inside appengine containers
- **Build**: Use `kas/with-workspace.yaml` overlay for local source development
