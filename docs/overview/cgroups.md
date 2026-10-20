---
title: "Cgroup Version"
sidebar_position: 17
description: "How Pantavisor picks cgroup v1 or v2, and which lxc.cgroup lines of a container it keeps."
---
# Cgroup Version

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

`PV_SYSTEM_CGROUP_VERSION` takes `1`, `2`, `auto` or `default`:

| Value | Embedded and standalone | Appengine |
|-------|-------------------------|-----------|
| `1` | Mount the hybrid layout. Fail if that is impossible, e.g. with an LXC that has no v1 support (LXC 7). | Fail unless the host runs a hybrid or legacy layout. Also fail with LXC 7. |
| `2` | Mount `cgroup2` at `/sys/fs/cgroup`. Fail if the kernel has no `cgroup2` or no cgroup BPF device support (`CONFIG_CGROUP_BPF`). | Fail unless the host runs a pure `cgroup2` layout. |
| `auto` | v2 if the kernel supports it, otherwise v1. Fail if neither works, e.g. LXC 7 on a kernel without v2. | Use the layout the host runs. |
| `default` | The default of the init mode: same as `1`. | The default of the init mode: same as `auto`. |

Pantavisor checks the kernel for v2 by looking for `cgroup2` in `/proc/filesystems`
and by loading a trivial cgroup device BPF program. An invalid value is logged and the default is used.

When the key is not set, or set to `default`, the default is `1` in embedded and standalone mode and `auto`
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

## Checking which version is in use

Pantavisor publishes what `auto` or `default` resolved to in two
[device metadata](../reference/pantavisor-metadata.md) keys:

| Key | Value |
|-----|-------|
| `pantavisor.cgroup.layout` | `hybrid`, `legacy` or `unified` (`unknown` if not detected) |
| `pantavisor.cgroup.version` | `2` for `unified`, `1` for `hybrid` and `legacy` |

On the device:

```bash
pvcontrol devmeta ls
```

The same keys show in the device metadata on Pantacor Hub. Pantavisor also logs
them at startup in `pantavisor.log`:

```
cgroup layout hybrid, using cgroup version 1 (PV_SYSTEM_CGROUP_VERSION=auto)
```

## Cgroup v2 layout

On v2 the layout is the same on devices and in appengine. In
the paths below, `<base>` is the base cgroup: the cgroup Pantavisor starts in (the
root `/` on a device, the container's own cgroup in appengine).

| Cgroup | Holds |
|--------|-------|
| `<base>/init.scope` | Pantavisor and every other process that was in the base cgroup, including PID 1 in appengine |
| `<base>/lxc/<name>` | the container `<name>` |
| `<base>/lxc.monitor.<name>` | the LXC monitor of the container |

At startup Pantavisor creates `<base>/init.scope`, moves all processes of the base cgroup into it and
only then enables every controller of the base cgroup in `<base>/cgroup.subtree_control`, so LXC can
pass them on to the containers (limits such as `pids.max` need this). The name
`init.scope` is what makes LXC place containers next to it, in `<base>/lxc`.

`docker exec` processes of an appengine container join the cgroup of PID 1, so they
run in `<base>/init.scope` too. To see where everything runs:

```bash
for p in /proc/[0-9]*; do echo "${p#/proc/} $(cat $p/cgroup 2>/dev/null) $(cat $p/comm 2>/dev/null)"; done
```

This is managed automatically; no action needed. v1 and hybrid layouts are unchanged.

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
written to `<PV_SYSTEM_LXCDIR>/<container>.conf` (`/run/pantavisor/lxc/<container>.conf`
by default). The directory is root only and is not mounted into any container. Compare
it with the original on a device:

```bash
diff /storage/trails/current/<container>/lxc.container.conf /run/pantavisor/lxc/<container>.conf
```

Each removed line is logged by the `pv_lxc` module
of the Pantavisor log, and so is a refusal:

```bash
grep pv_lxc /storage/logs/<revision>/pantavisor/pantavisor.log
```

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

This part is done by pvr, not by Pantavisor.

The pvr `lxc-docker` template writes the lines from the container's `src.json` args.
The v1 args exist today; the v2 args are new:

| Kind | Device list | Other cgroup lines |
|------|-------------|--------------------|
| v1 | `PVR_LXC_CGROUP_DEVICES_WHITE` | `PVR_LXC_CGROUP_V1` |
| v2 | `PVR_LXC_CGROUP2_DEVICES_WHITE` | `PVR_LXC_CGROUP_V2` |

A container that sets both kinds gets both kinds of line. The template stops writing
the default `lxc.cgroup.devices.allow = a`.

## meta-pantavisor defaults

These values are set by the meta-pantavisor layer, not by Pantavisor itself. Without
them the embedded default is `1`.

| Build | `PV_SYSTEM_CGROUP_VERSION` |
|-------|----------------------------|
| Device images with `lxc-stable` (LXC 6) | `auto` |
| Device images with `lxc-next` (LXC 7) | `2` |
| Device images with `lxc-deprecated` (LXC 3) | `1` |
| Appengine | `auto`, set in the Pantavisor appengine config |

meta-pantavisor adds no kernel options for this. The BSP decides: with `auto`, a board
whose kernel has cgroup BPF (`CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`) runs v2, and one
without it runs v1 and logs the deprecation warning. When the value is `2`, the kernel
build fails with an error if those two options are missing.

`pantavisor.config` ships with the BSP, so a device can change layout in the same
revision that brings the new Pantavisor. If a container in that revision cannot start on
the new layout, the update fails and the device rolls back to the previous revision.

## Open points

- Lines that come in through `lxc.include` are not filtered.
- Standalone mode does not mount the cgroup tree in Pantavisor today, so the key has
  no effect there.
- Containers on v2 see a pure `cgroup2` tree under `/sys/fs/cgroup`. Anything inside a
  container that reads v1 paths there needs v2 support.
