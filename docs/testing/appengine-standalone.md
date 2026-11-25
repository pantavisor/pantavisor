---
title: "The Standalone Appengine"
sidebar_position: 2
description: "What appengine is, how a container stands in for a device, why to prototype on it, and how a standalone instance is built and kept."
---
# The Standalone Appengine

Appengine is Pantavisor running inside a Docker container on any Linux host, with the
container playing the device. To run one, see [standalone.md](standalone.md).

## Why use it

A board needs a bootloader set up, a kernel built and a flashable image before Pantavisor
runs on it. On the other hand, an appengine instance boots in seconds on the workstation
you already have, and is thrown away just as fast:

- Quickly set up a prototype board not yet supported by Pantavisor.
- Keep a target around for `pvr` clone, edit and post cycles.
- Try a container or a configuration before writing a test for it.
- Reproduce a test setup without its script, to poke at a failure.
- Run Pantavisor under valgrind, which is less convenient in a board.

## What runs in it

The `pantavisor-appengine` image holds the `pantavisor` binary, `pvtx`, LXC and valgrind,
plus `pv-appengine`, the container entrypoint, acting as the bootloader.

The factory revision is deployed on first boot from the image: a `bsp` and the `pvr-sdk`
container, which serves the `pvr` endpoint.

Pantavisor runs in [appengine init mode](../overview/init-mode.md#appengine-mode), with
the base config in `/etc/pantavisor-appengine.config` and every `PV_*` key overridable
from the container env.

## How a container stands in for a device

What you prototype carries over to a device is the same `pantavisor` binary, with the
same revisions, containers, updates, pv-ctrl API and `pvr` endpoint. What does not carry
over is anything board-specific, listed below:

| Device part | On a board | In appengine |
|---|---|---|
| Bootloader | Picks `pv_rev` or `pv_try` envs | `pv-appengine` directly reads `storage/boot/uboot.txt` |
| Kernel, modules, firmware | from the revision `bsp` | from the host |
| Drivers | modules declared by the `bsp` | from the the host |
| PID 1 | Pantavisor | `pv-appengine`, which runs Pantavisor as its child |
| Storage | a partition Pantavisor mounts | a host directory bind-mounted at `/var/pantavisor/storage` |
| Reboot | `reboot()` | Pantavisor exits and `pv-appengine` relaunches it after 5 s |
| Power off | `reboot()` with power off | Pantavisor exits and the container stops |
| Crash | kernel panic, then reset | `pv-appengine` relaunches Pantavisor or stops the container depending on exit code |
| Boot config | config file, kernel env and cmdline | config file plus container env |
| Watchdog | per board | disabled |
| secureboot | per board | disabled by default |
| Network | the board interfaces | the Docker bridge |
| Console | serial port | container stdout |

Container-specific behaviours of loop devices, logs and named initial revisions are
described in [init mode](../overview/init-mode.md#containerised-appengine).

## How a standalone instance is built

`run.docker.sh` runs one `pantavisor-appengine` container per instance, the same image
the [pvtest pool](pvtest-harness.md#topology) uses, booted from a setup json with the
same format the `test.json` so they are inter-exchangable:

- The setup json `config.env` becomes the container env.
- The `containers.tarballs` are staged into `seed/` and installed on top of the factory
  revision as `locals/<name>`, which boots already DONE.
- The setup json `config.usrmeta` is saved once the instance is ready.

You reach Pantavisor in two ways: `run.docker.sh` commands through `docker exec`, and the
`pvr` endpoint over HTTP on port 12368.

## Topology

```
 HOST (x86_64 or arm64)
 ┌────────────────────────────────────────────────────────────────────────┐
 │  run.docker.sh (one container per instance, no tester, no slot pool)   │
 │                                                                        │
 │  ┌────────────────────┐         ┌──────────────────────────┐           │
 │  │  you, on the host  │──HTTP──►│  pantavisor-appengine    │           │
 │  │  pvr               │ :12368  │  pv-appengine (PID1)     │           │
 │  │                    │ (IP/-P) │  └─ pantavisor           │           │
 │  │  run.docker.sh     │─docker─►│     ├─ pvr-sdk (LXC)     │           │
 │  │  exec / attach     │  exec   │     └─ sshd              │           │
 │  └────────────────────┘         └─────┬──────────────┬─────┘           │
 │                       docker logs -f  │              │ bind mounts     │
 │                                       ▼              ▼                 │
 │          ~/.local/share/pvtest/instances/<name>/                       │
 │            console.log    storage/    seed/    setup.json              │
 │                                                                        │
 │  host kernel: modules, /dev/kmsg, /dev/hwrng, loop devices, cgroups    │
 └────────────────────────────────────────────────────────────────────────┘
```

## Lifecycle

| Command | Does | Undone by |
|---|---|---|
| `up <json>` | creates the container and the workdir, stages the tarballs and boots `locals/<name>` | `down` |
| `start <name>` | boots the existing container again, on the storage it left behind | `stop` |

## The instance workdir

The default follows `$XDG_DATA_HOME`. Overridable by `PVTEST_INSTANCES_DIR` and
ignored with `-w`.

```
~/.local/share/pvtest/instances/<name>/
  setup.json    <- the setup json given to up
  seed/         <- the staged tarballs, mounted read-only
  storage/      <- Pantavisor storage, filetree logs under storage/logs/
  console.log   <- console of every boot, appended
  valgrind/     <- valgrind output, with up -V
```

## Where the Code Lives

| Path | Role |
|---|---|
| `pvtest/host/run.docker.sh` | boots, drives and removes the instances |
| `pvtest/host/templates/run.docker.json` | setup json template |
| `pvtest/host/host-docker` | host-only docker helpers shared with `test.docker.sh` |
| `appengine/` | the `pv-appengine` entrypoint and the appengine base config |
