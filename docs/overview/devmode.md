---
title: "Devmode"
sidebar_position: 19
description: "A fast edit loop on a device: write files into a running container without building a new revision."
---
# Devmode

Devmode lets a developer change the files of a container on a running device and see the result after a container restart, without building and installing a new revision for every edit. The container still runs as deployed: same root filesystem, same configuration, same group and restart policy.

## Enable devmode

Devmode is off by default. Turn it on with [`PV_DEVMODE_ALLOWED`](../reference/pantavisor-configuration.md#summary) in one of the two places that are part of the device's trusted configuration:

- [pantavisor.config](pantavisor-configuration-levels.md#pantavisorconfig), set when the image is built or on the device:

  ```
  PV_DEVMODE_ALLOWED=1
  ```

- the [OEM configuration](pantavisor-configuration-levels.md#oem) file inside the revision, at `<PV_OEM_NAME>/<PV_POLICY>.config` (`<PV_OEM_NAME>/default.config` when `PV_POLICY` is empty). With `PV_OEM_NAME=myoem`, from a [pvr](https://docs.pantahub.com/pvr/) checkout of the device:

  ```bash
  mkdir -p myoem
  echo "PV_DEVMODE_ALLOWED=1" >> myoem/default.config
  pvr add . && pvr commit && pvr post
  ```

Check the result with `pvcontrol conf ls`; the key reports `pv conf file` or `oem config` as its level. Any other level (user metadata, commands, the kernel command line, environment variables, policies) is refused with a warning in the log, because anyone who can write user metadata or edit the boot partition could otherwise open the device to unsigned code.

With `PV_DEVMODE_ALLOWED=0`, a devmode revision is refused: `PUT /steps/devmode/...` and the `run` command for a devmode revision both return an error.

## Devmode revisions

`pvcontrol devmode create` copies the committed revision into a devmode revision and runs it. Name another revision to base it on that one. A left-over devmode revision of that base is removed first, so the session starts clean; `--resume` keeps its files:

```bash
pvcontrol devmode create
pvcontrol devmode create 12 --resume
```

To go back to the committed revision, run it:

```bash
pvcontrol cmd run 12
```

Starting a devmode revision, switching to another one and running a normal revision again all reboot the device, so that every container starts with or without its inlay. Wait for the new revision to show `UPDATED` (devmode) or `DONE` (normal):

```bash
pvcontrol steps show-progress current
```

`pvcontrol devmode create` while the devmode revision of that base runs changes nothing: the answer has `"running":true`. To start clean, run the committed revision first and create it again.

Unlike a local revision, running a devmode revision does not switch the device to local mode. The device keeps talking to [Pantacor Hub](remote-control.md#pantacor-hub): metadata and logs keep flowing, and a new Hub update replaces the devmode revision. The Hub is never told about a devmode revision: its progress is not reported there, and a lost Hub connection does not roll it back.

### Know when the device reboots

Your SSH session drops when the device reboots, so Pantavisor says so before it happens. `pvcontrol` prints a line to stderr, then the answer:

```
$ pvcontrol devmode create
starting the devmode revision; the device reboots now and this connection will drop
{"revision":"devmode/r/187","base":"187","resumed":false,"reboot":true}
```

Scripts that call the [API](../reference/pantavisor-commands.md#commands) directly find `{"reboot":true}` in the answer; the lines of each `pvcontrol` command are in [pvcontrol](../tools/pvcontrol.md#devmode). Right before the reboot Pantavisor logs a `rebooting into <revision>` line at the `WALL` level, which reaches `/dev/console` when [`PV_LOG_CONSOLE_ALERTS`](../reference/pantavisor-configuration.md#summary) is set. Read it later with:

```bash
grep -r "rebooting into" /storage/logs/
```

### Install a devmode revision by hand

A devmode revision is a copy of another revision. Its name says which one it is based on:

| Name | Based on |
|------|----------|
| `devmode/l/<name>` | the local revision `locals/<name>` |
| `devmode/r/<number>` | the Hub revision `<number>` |

Install it like a [local revision](local-control.md) and run it:

```bash
pvcontrol steps put /tmp/state.json devmode/r/12
pvcontrol cmd run devmode/r/12
```

## The inlay

While a devmode revision runs, every container has a writable layer called the inlay. It sits in the root filesystem of the container directly below the container's own writable layer (the `lxc-overlay` upper):

| Order | Layer |
|-------|-------|
| 1, top | container writable layer (upper) |
| 2 | inlay (`_devmode`) |
| 3 | `/configs/<container>` overlay, if the container has one |
| 4 | `root.ovl.squashfs`, if any |
| 5, bottom | `root.squashfs` |

Files you put in the inlay shadow the same files of the image, and whiteouts hide them. A container whose root filesystem is not an overlay has no inlay and no folder in `/pantavisor/devmode`. Such a container logs a warning and runs without it.

Inlay files are stored per revision, so the inlay is kept when you post the same devmode name again and removed together with the devmode revision. Files the container itself changed at runtime live in the upper layer and shadow inlay files, unless the container's lxc-overlay is cleared on every boot.

### Look at files and change them

A container with the `mgmt` [role](containers.md) sees the whole filesystem of every container at `/pantavisor/devmode/<container>`, for looking only. It is an overlay of the image layers (the container's configuration files, `root.ovl.squashfs` if it has one and `root.squashfs`) with the inlay on top, so you see the files of the image and what devmode changed:

```bash
ls /pantavisor/devmode/my-container/etc
```

The folder is read-only; writing there fails with a read-only filesystem error. All changes go through the API, which `pvcontrol devmode files` uses. It works from a mgmt container and from the host of the device, and the path is relative to the root of the container:

```bash
pvcontrol devmode files put my-container etc/my-app.conf ./my-app.conf --mode 0644
cat my-app.conf | pvcontrol devmode files put my-container etc/my-app.conf -
pvcontrol devmode files ls my-container
pvcontrol devmode files get my-container etc/my-app.conf
pvcontrol devmode files rm my-container etc/motd
pvcontrol devmode files mv my-container etc/my-app.conf etc/my-app.conf.old
pvcontrol devmode files chmod my-container opt/my-app/run.sh --mode 0755 --uid 1000 --gid 1000
```

To keep a whole build output in step with a container, from your workstation, use `pvr devmode sync`; it changes the files through the same API.

Everything you change lands in the inlay, the image is never touched:

- a new or changed file is stored in the inlay;
- removing a file of the image hides it in the container;
- removing a directory of the image and putting it again, with `files rm --recursive` and `files put --type dir`, makes the new directory start empty and hide everything the image had in it.

The container sees the changes after its next start, because the root filesystem is mounted again on start:

```bash
pvcontrol devmode apply my-container
```

This restarts the container, the same as `pvcontrol containers restart my-container`.

The inlay itself, with only your changes, is on the device at `/volumes/<container>/_devmode` for the container's own start, and at `/storage/disks/rev/<devmode revision>/<container>/_devmode` on the storage, for example `/storage/disks/rev/devmode/r/12/my-container/_devmode`. Looking at it there shows only what you changed, and deleted files appear as whiteouts:

```bash
ls -l /storage/disks/rev/devmode/r/12/my-container/_devmode/etc
```

If the filesystem of the device cannot hold overlay whiteouts, Pantavisor logs a warning and shows only the inlay in `/pantavisor/devmode/<container>`; files can still be added and changed, but the image files are not listed.

To take a whole folder, or the container, off the device in one step, `get --tar` writes a tar of it to standard output. The names are relative to the container root, and modes, owners and symlinks are kept:

```bash
pvcontrol devmode files get my-container --tar > my-container.tar
pvcontrol devmode files get my-container etc/nginx --tar | tar -tv
```

`mv` renames a file, directory or symlink in one step and creates the directories of the new path. A directory that comes from the image cannot be renamed on the overlay; copy it and remove the old one instead. `chmod` changes the mode and the owner of a file without sending it again; give any of `--mode`, `--uid` and `--gid`. A symlink only takes an owner. When a call fails, the answer carries the reason as an `errno` next to the message:

```console
$ pvcontrol devmode files rm my-container opt/my-app
{"Error":"A directory is in the way, or the path is not a directory","errno":"ENOTEMPTY"}
```

`ls` shows what devmode changed, the content of the inlay, with the `sha256` of every file. A file of the image that you removed is listed as `"type":"deleted"`. The endpoints are in the [control socket reference](../reference/pantavisor-commands.md#devmodefiles), the commands in [pvcontrol](../tools/pvcontrol.md#devmode).

The folder only exists while a devmode revision runs. A device where devmode is not allowed, or that runs a committed revision, has no `/pantavisor/devmode` in its mgmt containers; this is managed automatically, no action is needed.

### See what the container wrote itself

The files a running container wrote itself live in its own writable layer, the top layer of the table above, and shadow the same path in the inlay. `/pantavisor/devmode/<container>` does not include that layer. Mgmt containers see it, read-only, at `/pantavisor/devmode/.container-layer/<container>`:

```bash
ls /pantavisor/devmode/.container-layer/my-container/etc
```

The `GET /devmode` call lists the path as `container_layer`; see [/devmode](../reference/pantavisor-commands.md#devmode).

### Containers with the system restart policy

A container with restart policy `system` cannot be restarted through the API. In a devmode revision, restarting it answers `409` (reboot needed). Reboot the device into the devmode revision:

```bash
pvcontrol devmode apply my-system-container --reboot
```

A `system` container needs `--reboot`, which adds `?reboot=1` to the call and reboots the device into the devmode revision. The raw call is:

```bash
curl -X PUT --data '{"action":"restart"}' --unix-socket /pantavisor/pv-ctrl "http://localhost/containers/my-system-container?reboot=1"
```

### Check and reset the inlay

```bash
pvcontrol devmode status
pvcontrol devmode reset my-container
```

The raw calls are:

```bash
curl -X GET --unix-socket /pantavisor/pv-ctrl http://localhost/devmode
curl -X DELETE --unix-socket /pantavisor/pv-ctrl http://localhost/devmode/files/my-container
```

The first call shows whether devmode is on, the running devmode revision, the revision it is based on and the inlay directory of each container. The second call replaces the inlay of one container with an empty one. The image files show again in `/pantavisor/devmode/<container>` right away, and in the container after its next restart.

## Run commands in a container

While a devmode revision runs, a container with the `mgmt` role can run a command in any other running container, with no ssh or shell in between:

```bash
pvcontrol containers exec my-container -- cat /etc/os-release
pvcontrol containers exec --timeout 5 my-container -- ls -l /usr/bin
```

The command runs in the namespaces, cgroups and capabilities of the container. The arguments reach it as you type them, so quotes and `$` need no extra escaping. The raw call, its limits and all answers are in the [control socket reference](../reference/pantavisor-commands.md#run-a-command-in-a-container).

## Fallback to the last commit

A devmode revision is never committed. It is installed as a try, and stays one:

- The device falls back to the last revision that was committed before devmode started, which is not necessarily the revision the devmode revision is based on.
- A reboot that you ask Pantavisor for (`pvcontrol cmd reboot`, `pvcontrol devmode apply` on a system container) boots back into the devmode revision. Any reset, power loss or failed start boots that committed revision again. The devmode revision is then marked as rolled back: `pvcontrol steps show-progress devmode/r/12` shows `ERROR`.
- A running devmode revision shows `UPDATED` (`Update finished, revision not set as rollback point`).
- To go back to the committed revision on purpose, run it: `pvcontrol cmd run <revision>`. A plain reboot does not leave devmode.
- While a devmode revision runs, the `pantavisor.revision` device metadata key reports that committed revision, so Pantacor Hub commands that look up the current revision keep working. The key `pantavisor.devmode` holds the devmode revision name. It is removed on the next start into a committed revision, also after a rollback. Logs of the devmode revision stay tagged with its own name, and its progress is never sent to Pantacor Hub.
- A rolled back devmode revision can be run again with `pvcontrol cmd run devmode/r/12`; it keeps its inlays.

Read both keys on the device, or from your workstation with `pvr`:

```
pvcontrol devmeta ls | jq '{rev: .["pantavisor.revision"], devmode: .["pantavisor.devmode"]}'
pvr device get <device> | jq '."device-meta"["pantavisor.devmode"]'
```

### Bootloaders

A reboot that devmode requests itself must boot back into the devmode revision, and any other reboot must boot the committed one. How that works depends on the [bootloader](bsp.md#bootloader):

| Bootloader | Devmode | How a requested reboot comes back in devmode |
|------------|---------|----------------------------------------------|
| `uboot`, `uboot-pvk` | yes, when the boot script keeps `pv_trying` in a `pv.env` file | Pantavisor clears `pv_trying` before the reboot (see [where `pv_trying` is stored](bsp.md#where-pv_trying-is-stored)) |
| `rpiab` | yes | Pantavisor arms the Raspberry Pi tryboot flag again before the reboot; the try partition still holds the devmode revision's boot image (see [rpiab](bsp.md#rpiab)) |
| appengine | yes | Pantavisor clears `pv_trying` in `uboot.txt` |
| `grub`, `uboot-ab`, `uboot` without `pv.env` | no | a devmode revision cannot be installed and a reboot request in devmode answers an error |

Check what happened on the device:

```bash
# uboot, uboot-pvk
grep -r uboot-env-file /storage/logs/devmode/
# rpiab
grep -r "next reboot is a tryboot" /storage/logs/devmode/
```

## Garbage collection

Devmode revisions are listed by `pvcontrol steps ls` and cleaned up by the [garbage collector](storage.md#garbage-collector) like local revisions: the running, updating and last committed revisions are kept, the rest can be removed. Removing a devmode revision also removes its files.

While `devmode/l/<name>` or `devmode/r/<number>` exists, the revision it is based on (`locals/<name>` or `<number>`) is never collected. Run the collector by hand with `pvcontrol cmd run-gc`.

## Reference

- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_DEVMODE_ALLOWED`
- [Control socket](../reference/pantavisor-commands.md#devmode) — `/devmode`, [`/devmode/files`](../reference/pantavisor-commands.md#devmodefiles), `/steps/devmode/...`, container restart with `?reboot=1`, [`/containers/{name}/exec`](../reference/pantavisor-commands.md#run-a-command-in-a-container)
