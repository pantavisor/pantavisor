---
title: "Cgroup Version"
sidebar_position: 17
description: "How Pantavisor picks cgroup v1 or v2, and which lxc.cgroup lines of a container it keeps."
---
# Cgroup Version

:::note
This page describes planned behaviour. It is not implemented yet.
:::

Pantavisor runs on either cgroup layout:

- **v1**: the hybrid layout Pantavisor mounts today on a device: v1 controllers under
  `/sys/fs/cgroup/<controller>` plus `cgroup2` at `/sys/fs/cgroup/unified`. v1 is
  deprecated.
- **v2**: a single `cgroup2` hierarchy at `/sys/fs/cgroup`.

A container says which layouts it supports by carrying explicit lines for each one in
its `lxc.container.conf`. Before LXC reads that file, Pantavisor removes the lines for
the layout it is not running on. Pantavisor never rewrites one kind of line into the
other.

## Choosing the version

`PV_SYSTEM_CGROUP_VERSION` takes `1`, `2` or `auto`:

| Value | Embedded and standalone | Appengine |
|-------|-------------------------|-----------|
| `1` | Mount the hybrid layout. Fail if that is impossible, e.g. with an LXC that has no v1 support (LXC 7). | Fail unless the host runs a hybrid or legacy layout. |
| `2` | Mount `cgroup2` at `/sys/fs/cgroup`. Fail if the kernel has no `cgroup2` or no cgroup BPF device support (`CONFIG_CGROUP_BPF`). | Fail unless the host runs a pure `cgroup2` layout. |
| `auto` | v2 if the kernel and LXC support it, otherwise v1. | Use the layout the host runs. |

When the key is not set, the default is `1` in embedded and standalone mode and `auto`
in appengine mode, which is the behaviour of Pantavisor before this key existed.

Whenever Pantavisor ends up on v1, it logs a deprecation warning.

The key has no dotted (`system.cgroup.version`) form.

To choose v2 on a device, set it in `pantavisor.config`:

```
PV_SYSTEM_CGROUP_VERSION=2
```

To see which layout a running system uses:

```bash
stat -fc %T /sys/fs/cgroup   # cgroup2fs = v2, tmpfs = v1 (hybrid or legacy)
```

## Container lines

Two kinds of line are affected:

| Kind | Keys |
|------|------|
| v1 | `lxc.cgroup.<controller>.*`, e.g. `lxc.cgroup.devices.allow`, `lxc.cgroup.memory.limit_in_bytes` |
| v2 | `lxc.cgroup2.*`, e.g. `lxc.cgroup2.devices.allow`, `lxc.cgroup2.memory.max` |

`lxc.cgroup.dir*` and `lxc.cgroup.relative` do not depend on the layout. Pantavisor
keeps them in every case and they are not counted below.

A container that works on both layouts carries both kinds:

```
lxc.cgroup.devices.deny = a
lxc.cgroup.devices.allow = c 1:3 rwm
lxc.cgroup2.devices.deny = a
lxc.cgroup2.devices.allow = c 1:3 rwm
```

## Start rule

Pantavisor removes the lines of the other kind, gives LXC the result, and decides:

| Lines removed | Lines left for the running layout | Result |
|---------------|-----------------------------------|--------|
| none | any or none | start |
| some | some | start |
| some | none | refuse to start, and log which lines were removed |

The refusal stops a container that was written with a sandbox for one layout from
running without any sandbox on the other.

The original `lxc.container.conf` in the revision is not changed; LXC reads a copy
written to the Pantavisor run directory.

### `devices.allow = a`

A removed `lxc.cgroup.devices.allow = a` or `lxc.cgroup2.devices.allow = a` does not
count as a removed line: with no device line at all, a container already gets every
device its parent cgroup allows, on both layouts and with every LXC version, so
removing it takes no sandbox away. Pantavisor logs a warning
for each such line, because the line is not needed.

This keeps revisions built with older pvr templates starting on v2: those templates
write `lxc.cgroup.devices.allow = a` into every container that sets no device list.

Pantavisor no longer adds `lxc.cgroup2.devices.allow = a` on v2.

## pvr template

The pvr `lxc-docker` template writes the lines from the container's `src.json` args.
The v1 args exist today; the v2 args are new:

| Kind | Device list | Other cgroup lines |
|------|-------------|--------------------|
| v1 | `PVR_LXC_CGROUP_DEVICES_WHITE` | `PVR_LXC_CGROUP_V1` |
| v2 | `PVR_LXC_CGROUP2_DEVICES_WHITE` | `PVR_LXC_CGROUP_V2` |

A container that sets both kinds gets both kinds of line. The template stops writing
the default `lxc.cgroup.devices.allow = a`.

## meta-pantavisor defaults

| Build | `PV_SYSTEM_CGROUP_VERSION` |
|-------|----------------------------|
| Device images (`lxc-stable`, `lxc-next`) | `2` |
| Device images with `lxc-deprecated` (LXC 3) | `1` |
| Appengine | `auto` |

`pantavisor.config` ships with the BSP, so a device moves to v2 in the same revision that
brings the new Pantavisor. If a container in that revision cannot start on v2, the
update fails and the device rolls back to the previous revision.

## Open points

- Lines that come in through `lxc.include` are not filtered.
- Containers on v2 see a pure `cgroup2` tree under `/sys/fs/cgroup`. Anything inside a
  container that reads v1 paths there needs v2 support.
