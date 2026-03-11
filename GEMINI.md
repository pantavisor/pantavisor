# feature/xconnect-landing

This branch adds the pv-xconnect service mesh, daemon management, control API enhancements, and shell tooling (pvcurl/pvcontrol).

## Key Components

| Component | Description |
|-----------|-------------|
| `xconnect/` | Service mesh daemon with plugins (unix, rest, dbus, drm, wayland) |
| `ctrl/` | REST API: /xconnect-graph, /daemons, /signal endpoints |
| `tools/pvcurl` | Lightweight curl wrapper using nc for HTTP-over-Unix-socket |
| `tools/pvcontrol` | CLI wrapper around pvcurl for pv-ctrl operations |
| `utils/tsh.c` | Daemon stdout/stderr capture via logserver |

## Documentation

| Document | Location | Description |
|----------|----------|-------------|
| **Control Socket** | [docs/reference/pantavisor-commands.md](docs/reference/pantavisor-commands.md) | Reference for pv-ctrl HTTP endpoints (containers -> PV) |
| **xconnect** | [docs/reference/pantavisor-xconnect.md](docs/reference/pantavisor-xconnect.md) | Service mesh logic and manifests (container <-> container) |
| **xconnect Spec** | [xconnect/XCONNECT.md](xconnect/XCONNECT.md) | Technical specification and plugin architecture |
| **Configuration** | [docs/reference/pantavisor-configuration.md](docs/reference/pantavisor-configuration.md) | Pantavisor configuration reference |
| **Log Sockets** | [docs/reference/logserver-sockets.md](docs/reference/logserver-sockets.md) | Logserver unix sockets reference |
| **Metadata** | [docs/reference/pantavisor-metadata.md](docs/reference/pantavisor-metadata.md) | User and device metadata reference |
| **State Format** | [docs/reference/pantavisor-state-format-v2.md](docs/reference/pantavisor-state-format-v2.md) | Pantavisor state.json format (v2) |
| **Config (Legacy)**| [docs/reference/pantavisor-configuration-legacy.md](docs/reference/pantavisor-configuration-legacy.md) | Legacy configuration reference |

## Architecture

- **pv-xconnect**: Standalone mediation service for cross-container communication
  - Detailed design in [xconnect/XCONNECT.md](xconnect/XCONNECT.md)
  - Plugin-driven: unix, rest, dbus, drm, wayland
  - Runs as a managed daemon (DM_ALL mode, all init modes)
- **Pantavisor as Security Broker**: Containers use logical service names, access granted via explicit `run.json` requirements
- **Build flag**: `PANTAVISOR_XCONNECT` (CMake), controlled by `xconnect` in `PANTAVISOR_FEATURES` (Yocto)

## Development Guidelines

- **Documentation**: Always check if [reference documentation](docs/reference/) should be updated after making changes to the code.
- **Commits**: Always use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (v1.0.0) for all commit messages.
- **Formatting**: Run `clang-format -i` on modified `.c`/`.h` files before committing
- **API testing**: Use `pvcurl` (not `curl`) inside appengine containers
- **Build**: Use `kas/with-workspace.yaml` overlay for local source development
