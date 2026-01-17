# pv_lxccli - CLI-based LXC Plugin

A Pantavisor container runtime plugin that uses LXC command-line tools instead of the liblxc API.

## Overview

This plugin provides an alternative to `pv_lxc.so` that works with stock/unpatched LXC installations. Instead of linking against liblxc and using the C API, it generates config files and invokes `lxc-start`, `lxc-stop`, and `lxc-info` commands.

## Benefits

- **No LXC patches required** - Works with upstream LXC packages from any distribution
- **Broad version compatibility** - LXC 2.1+ for cgroup v1, LXC 3.0+ for cgroup v2
- **Easier debugging** - Can manually run the same commands to troubleshoot
- **Stable interface** - CLI tools have stable options across LXC versions

## How It Works

### Container Start

1. Reads the original `lxc.conf` from the platform
2. Appends Pantavisor-specific configuration:
   - `lxc.rootfs.mount` - rootfs mount point
   - `lxc.uts.name` - container hostname
   - `lxc.console.path` - PTY for console capture
   - `lxc.cgroup2.devices.allow` - cgroup v2 device access
   - `lxc.mount.entry` - bind mounts for /pv, logs, metadata
   - `lxc.hook.mount` - mount hooks
   - `lxc.environment` - container type
3. Writes merged config to `/run/pantavisor/lxccli/<name>/config`
4. Runs: `lxc-start -n <name> -P <lxcpath> -f <config> -d`

### Container Stop

1. Checks if container is running via `lxc-info`
2. Runs: `lxc-stop -n <name> -P <lxcpath> -t 30`
3. Falls back to `lxc-stop -k` (SIGKILL) if graceful stop fails
4. Cleans up console PTY

### Console Capture

Creates a PTY pair for each container:
- Slave side is configured via `lxc.console.path`
- Master side is returned from `pv_console_log_getfd()`
- Pantavisor reads container console output from the master fd

## LXC Version Compatibility

| LXC Version | Cgroup v1 | Cgroup v2 | Notes |
|-------------|-----------|-----------|-------|
| 1.x         | No        | No        | Old config syntax |
| 2.1+        | Yes       | No        | Dotted config syntax |
| 3.0+        | Yes       | Yes       | `lxc.cgroup2.*` support |
| 4.x+        | Yes       | Yes       | Fully supported |
| 5.x+        | Yes       | Yes       | Fully supported |

## Configuration Options Used

```ini
# Set by plugin
lxc.rootfs.mount = /lxc/rootfs
lxc.uts.name = <container-name>
lxc.log.level = <0-5>
lxc.console.path = /dev/pts/X

# For cgroup v2 systems
lxc.cgroup2.devices.allow = a

# Bind mounts (examples)
lxc.mount.entry = /storage/.pv pv none bind,ro,create=dir 0 0
lxc.mount.entry = /storage/logs pv/logs none bind,ro,create=dir 0 0

# Hooks
lxc.hook.mount = /lib/pantavisor/pv/hooks_lxc-mount.d/script.sh

# Environment
lxc.environment = container=pv-<group>

# Custom init (if platform specifies exec)
lxc.init.cmd = /custom/init
```

## Build Requirements

- CMake 3.0+
- libutil (glibc) or libc with openpty (musl)
- No liblxc dependency

## Runtime Requirements

- LXC CLI tools: `lxc-start`, `lxc-stop`, `lxc-info`
- LXC 2.1+ (3.0+ for cgroup v2)

## Differences from pv_lxc

| Feature | pv_lxc | pv_lxccli |
|---------|--------|-----------|
| LXC dependency | liblxc + patches | CLI tools only |
| Config modification | In-memory API | File-based merge |
| Console capture | `console_getfd()` API | PTY via `lxc.console.path` |
| LXC log streaming | Via patched API | Not yet implemented |
| Version compatibility | Requires lxc-pv fork | Stock LXC 2.1+ |

## Files

- `pv_lxccli.c` - Plugin implementation
- `pv_lxccli.h` - Plugin interface
- `README.pv_lxccli.md` - This documentation

## Future Work

- LXC log (`lxc.log.file`) streaming to fd - requires lxc-pv patches for real-time access
