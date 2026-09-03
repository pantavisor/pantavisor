---
title: "Init Mode"
sidebar_position: 16
description: "Embedded, standalone, and appengine operational modes, and when to use each."
---
# Init Mode

Pantavisor offers several [configurable](../reference/pantavisor-configuration.md#summary) init modes for convenience: embedded, standalone and appengine.

## Embedded Mode

This is the way Pantavisor was meant to be run. In this case, the bootloader will directly start up Pantavisor, which will run alongside a minimal rootfs with all its dependencies.

## Standalone Mode

This mode was created for debugging Pantavisor. It works the same way as _embedded_, with the bootloader starting Pantavisor up. The difference is Pantavisor will not launch any container or perform any of its regular [operations](pantavisor-architecture.md). To do so, Pantavisor has to be manually run from console inside of the device.

## AppEngine mode

AppEngine mode is meant for prototyping on already setup devices running any Linux distro. In this case, Pantavisor will run as a daemon that can be started from your init system or directly from console.

### Containerised appengine

The same mode also runs with Pantavisor as PID 1 inside a container, which is how the runtime is developed and tested off-hardware. It is the same `pantavisor` binary with the same revisions, containers, updates and pv-ctrl API, while the board-specific parts (bootloader, watchdog, secure boot, hardware reboots) are stubbed or simulated.

In this regard, the entrypoint for this container is `pv-appengine`, a looped script in charge of simulating the bootloader, reboot and poweoff behaviors. Furthermore, on first boot, the entrypoint seeds storage from the skeleton, deploys an initial revision with `pvtx` from `/usr/lib/pantavisor/pvtx.d/` plus anything present in `/usr/lib/pantavisor/pvtx.extra.d/`, and writes the initial boot state to `storage/boot/uboot.txt`.

Pantavisor reads `PV_*` config keys straight from the environment, so any of them can be overridden per appengine container without editing a config file, which offers the ability to test different setups without having to rebuild the binaries.

Some container-specific behaviours worth knowing:

- **Loop devices:** There is no udev, so `/dev/loop0..1023` are pre-created. Loop devices are host-global, so concurrent appengines each need their own `PV_LOOP_INDEX_BASE` 64 device range reserved. To avoid conflicts with leftover loop devices, the entrypoint reaps stale devices in its own 64-device band, detaching only those whose backing file reads `(deleted)`.
- **Log location:** Logs live under the storage mount at `<storage>/logs/0/`, not `/run/pantavisor/pv/logs/0/` as on a device so they can be inspected from host. `PV_LOG_SERVER_OUTPUTS=filetree,stdout_direct` additionally streams the internal log to stdout, unbuffered, as each event happens. See [logserver-sockets.md](../reference/logserver-sockets.md).
- **Named initial revisions:** Pantavisor only auto-commits the revision it boots into when that revision is named `0`. When `PV_APPENGINE_INITIAL_REV` names a different revision, `pv-appengine` writes the `.pv/done` and `.pv/progress` markers the factory path would have written. This is what lets a caller boot straight into a prepared revision with no install and no commit reboot.

## Reference

- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_SYSTEM_INIT_MODE`, `PV_LOOP_INDEX_BASE` and the appengine-specific keys
- [Log Sockets](../reference/logserver-sockets.md#log-server-outputs) — the sinks appengine uses to stream to stdout
