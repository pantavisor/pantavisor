# Pantavisor Development Guide

This document provides guidance for AI assistants and developers working with the Pantavisor codebase.

## Current Branch: feature/ipam

This branch implements IP Address Management (IPAM) for container networking with automatic rollback on configuration errors.

## Quick Reference

### Key Documentation

| Document | Purpose |
|----------|---------|
| [CLAUDE.md](CLAUDE.md) | Comprehensive codebase architecture and API reference |
| [CONFIGURATION.md](CONFIGURATION.md) | Complete configuration system with layered precedence |
| [PLATFORM.md](PLATFORM.md) | Container runtime features, try-boot, and rollback |
| [SYSTEM_STATE.md](SYSTEM_STATE.md) | System state architecture (BSP, containers, storage) |
| [xconnect/XCONNECT.md](xconnect/XCONNECT.md) | Service mesh specification (D-Bus, Unix, REST) |

### Build Commands

```bash
# Standard build
mkdir build && cd build
cmake ..
make

# With debug
cmake -DPANTAVISOR_DEBUG=ON ..

# For appengine (Docker testing)
cmake -DPANTAVISOR_APPENGINE=ON ..
```

### Key Source Files

| File | Purpose |
|------|---------|
| `init.c` | Entry point, early initialization |
| `pantavisor.c` | Core state machine |
| `platforms.c` | Container lifecycle management |
| `ipam.c` / `ipam.h` | IP address management (this branch) |
| `config.c` / `config.h` | Configuration system |
| `ctrl/ctrl.c` | REST API server |
| `parser/parser_system1.c` | State JSON parsing |

---

## Architecture Overview

Pantavisor is the init system (PID 1) for containerized embedded Linux devices.

### Core Concepts

1. **Atomic Updates**: Updates are all-or-nothing with automatic rollback
2. **Try-Boot**: New revisions are tested before committing
3. **Containers**: LXC-based isolation for applications
4. **Service Mesh**: pv-xconnect mediates container-to-container communication

### State Machine

```
INIT → RUN → WAIT ↔ COMMAND
               ↓
           ROLLBACK ← ERROR
               ↓
       REBOOT / POWEROFF
```

### Try-Boot Mechanism

When an update is installed:

1. `pv_try` is set to new revision
2. Device reboots into new revision
3. Pantavisor validates (containers start, network works, etc.)
4. **Success**: Commit (`pv_done = pv_rev`, clear `pv_try`)
5. **Failure**: Any reboot before commit → bootloader returns to `pv_done`

**Rollback triggers:**
- Container crash or start failure
- Essential mount failure
- Network config error (IPAM validation)
- Goals timeout (`PV_UPDATER_GOALS_TIMEOUT`)
- Network timeout (`PH_UPDATER_NETWORK_TIMEOUT`)

---

## Configuration System

Pantavisor uses layered configuration with precedence (low to high):

```
default → pantavisor.config → policy → oem config → kernel cmdline → env → metadata
```

### Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `PV_UPDATER_COMMIT_DELAY` | 25s | Stability wait before commit |
| `PV_UPDATER_GOALS_TIMEOUT` | 120s | Container readiness timeout |
| `PV_LOG_LEVEL` | 0 | Log verbosity (0=FATAL to 5=ALL) |
| `PV_BOOTLOADER_TYPE` | uboot | Bootloader: `uboot`, `rpiab`, `grub` |

See [CONFIGURATION.md](CONFIGURATION.md) for complete reference.

---

## IPAM (This Branch)

### Overview

IPAM manages container networking through IP pools defined in `device.json`:

```json
{
    "network": {
        "pools": {
            "internal": {
                "type": "bridge",
                "bridge": "br0",
                "subnet": "10.0.3.0/24",
                "gateway": "10.0.3.1",
                "nat": true
            }
        }
    }
}
```

Containers request interfaces in `run.json`:

```json
{
    "name": "my-app",
    "network": {
        "pool": "internal",
        "hostname": "myhost"
    }
}
```

### Key Files

- `ipam.c` - Pool management, IP allocation, bridge setup
- `ipam.h` - Data structures (`pv_ip_pool`, `pv_ip_lease`)
- `platforms.c` - Integration with container startup
- `parser/parser_system1.c` - Parsing network config from JSON

### Validation & Rollback

Invalid network configuration should fail container start:

| Error | Result |
|-------|--------|
| Static IP outside subnet | Container start refused → rollback |
| IP already in use | Container start refused → rollback |
| Pool doesn't exist | Container start refused → rollback |

**Fixed in `state.c`**:
- **Auto-Recovery Collision**: Ensured that network leases (IPAM) are released before a platform is set to `INSTALLED` during a restart. This prevents "IP already in use" errors when a container restarts after a crash.
- **Legacy Fallback**: Added fallback for `restart_policy: container` so it triggers automatic restart even if `auto_recovery` JSON is not defined.

---

## Testing with Appengine

Appengine is a Docker-based testing environment.

### Quick Start

```bash
# Build appengine image (from meta-pantavisor)
./kas-container build .github/configs/release/docker-x86_64-scarthgap.yaml:kas/with-workspace.yaml

# Load and run
docker load < build/tmp-scarthgap/deploy/images/docker-x86_64/pantavisor-appengine-docker.tar

docker run --name pva-test -d --privileged \
    -v $(pwd)/pvtx.d:/usr/lib/pantavisor/pvtx.d \
    -v storage-test:/var/pantavisor/storage \
    --entrypoint /bin/sh pantavisor-appengine:1.0 -c "sleep infinity"

# Start pantavisor manually
docker exec pva-test sh -c 'pv-appengine &'

# Check status
docker exec pva-test lxc-ls -f
```

### Useful Commands

```bash
# Pantavisor logs
docker exec pva-test cat /run/pantavisor/pv/logs/0/pantavisor/pantavisor.log

# Container logs
docker exec pva-test cat /run/pantavisor/pv/logs/0/<container>/lxc/console.log

# API queries
# NOTE: Use pvcurl instead of curl inside appengine
docker exec pva-test pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/containers
docker exec pva-test pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/config
```

---

## Development Guidelines (Gemini Memory)

### Code Formatting
- **Clang Format**: Always run `clang-format -i` on modified `.c` and `.h` files before committing. Use the `.clang-format` file in the root of the repository.
- **Whitespace**: Avoid unnecessary newlines that don't serve to structure functional blocks of code. Ensure code modifications are clean and maintain consistent style.

### Commit Style

```
feat(component): short description
fix(component): short description
docs: documentation update
refactor(component): code improvement
```

Examples:
```
feat(ipam): support static IP and MAC overrides from run.json
docs: comprehensive IPAM design with in-memory leases
fix(ctrl): handle NULL host header in HTTP requests
```

---

## Related Repositories

- **meta-pantavisor**: Yocto layer for building Pantavisor images
- **pvr**: CLI tool for managing Pantavisor devices
- **pantahub**: Cloud platform for device management
