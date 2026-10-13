---
title: "Devmode"
sidebar_position: 17
description: "A fast edit loop on a device: write files into a running container without building a new revision."
---
# Devmode

Devmode lets a developer change the files of a container on a running device and see the result after a container restart, without building and installing a new revision for every edit. The container still runs as deployed: same root filesystem, same configuration, same group and restart policy.

## Enable devmode

Devmode is off by default. Turn it on with [`PV_DEVMODE_ALLOWED`](../reference/pantavisor-configuration.md#summary), for example through [user metadata](../reference/pantavisor-metadata.md#user-metadata) (the key is the variable name, as for any [configuration level](pantavisor-configuration-levels.md#user-metadata)):

```bash
pvcontrol usrmeta save PV_DEVMODE_ALLOWED true
```

With `PV_DEVMODE_ALLOWED=false`, a devmode revision is refused: `PUT /steps/devmode/...` and the `run` command for a devmode revision both return an error.

## Devmode revisions

A devmode revision is a copy of another revision that you run on the device. Its name says which one it is based on:

| Name | Based on |
|------|----------|
| `devmode/l/<name>` | the local revision `locals/<name>` |
| `devmode/r/<number>` | the Hub revision `<number>` |

Install it like a [local revision](local-control.md) and run it:

```bash
pvcontrol steps put /tmp/state.json devmode/r/12
pvcontrol cmd run devmode/r/12
```

Unlike a local revision, running a devmode revision does not switch the device to local mode. The device keeps talking to [Pantacor Hub](remote-control.md#pantacor-hub): metadata and logs keep flowing, and a new Hub update replaces the devmode revision. The Hub is never told about a devmode revision: its progress is not reported there, and a lost Hub connection does not roll it back.

## The inlay

While a devmode revision runs, every container has a writable layer called the inlay. It sits in the root filesystem of the container directly below the container's own writable layer (the `lxc-overlay` upper):

| Order | Layer |
|-------|-------|
| 1, top | container writable layer (upper) |
| 2 | inlay (`_devmode`) |
| 3 | `/configs/<container>` overlay, if the container has one |
| 4 | `root.ovl.squashfs`, if any |
| 5, bottom | `root.squashfs` |

Files you put in the inlay shadow the same files of the image. The inlay only applies to containers whose root filesystem is an overlay; others log a warning and run without it.

Inlay files are stored per revision, so the inlay is kept when you post the same devmode name again and removed together with the devmode revision. Files the container itself changed at runtime live in the upper layer and shadow inlay files, unless the container's lxc-overlay is cleared on every boot.

### Write files into the inlay

A container with the `mgmt` [role](containers.md) sees the inlay of every container read-write at `/pantavisor/devmode/<container>`. Copy the changed files there with `cp`, `rsync` or `scp`:

```bash
rsync -a ./build/rootfs/ /pantavisor/devmode/my-container/
```

From the [debug ssh](../reference/pantavisor-configuration.md#summary) shell, the same directory is under `/storage/disks/rev/<devmode revision>/<container>/_devmode`.

The container sees new files after its next start, because the root filesystem is mounted again on start:

```bash
pvcontrol containers restart my-container
```

## Fallback to the last commit

A devmode revision is never committed. It is installed as a try, and stays one:

- `pv_rev` and the `done` marker keep pointing at the last revision that was committed before devmode started, not necessarily the revision the devmode revision is based on.
- Any reset, power loss or failed start boots that committed revision again. The devmode revision is then marked as rolled back, and `pvcontrol steps ls` shows it as `ERROR`.
- A running devmode revision shows `UPDATED` (`Update finished, revision not set as rollback point`).
- To go back to the committed revision on purpose, run it: `pvcontrol cmd run <revision>`.
- A rolled back devmode revision can be run again with `pvcontrol cmd run devmode/r/12`.

:::note
A reboot that devmode requests itself arms the try again, so the device comes back up in the devmode revision. Some U-Boot setups keep the "already tried" marker in `pv.env`, which Pantavisor cannot write; there the device boots the last commit after any reboot, and you run the devmode revision again.
:::

## Garbage collection

Devmode revisions are listed by `pvcontrol steps ls` and cleaned up by the [garbage collector](storage.md#garbage-collector) like local revisions: the running, updating and last committed revisions are kept, the rest can be removed. Removing a devmode revision also removes its files.

While `devmode/l/<name>` or `devmode/r/<number>` exists, the revision it is based on (`locals/<name>` or `<number>`) is never collected. Run the collector by hand with `pvcontrol cmd run-gc`.

## Reference

- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_DEVMODE_ALLOWED`
- [Control socket](../reference/pantavisor-commands.md#steps) — `/steps/devmode/...` and the `LOCAL_RUN` command
