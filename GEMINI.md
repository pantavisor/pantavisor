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

## Architecture

- **pv-xconnect**: Standalone mediation service for cross-container communication
  - Detailed design in [xconnect/XCONNECT.md](xconnect/XCONNECT.md)
  - Plugin-driven: unix, rest, dbus, drm, wayland
  - Runs as a managed daemon (DM_ALL mode, all init modes)
- **Pantavisor as Security Broker**: Containers use logical service names, access granted via explicit `run.json` requirements
- **Build flag**: `PANTAVISOR_XCONNECT` (CMake), controlled by `xconnect` in `PANTAVISOR_FEATURES` (Yocto)

## Development Guidelines

- **Formatting**: Run `clang-format -i` on modified `.c`/`.h` files before committing
- **API testing**: Use `pvcurl` (not `curl`) inside appengine containers
- **Build**: Use `kas/with-workspace.yaml` overlay for local source development
