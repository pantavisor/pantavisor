---
title: "Devmode"
sidebar_position: 18
description: "A fast edit loop on a device: write files into a running container without building a new revision."
---
# Devmode

Devmode lets a developer change the files of a container on a running device and see the result after a container restart, without building and installing a new revision for every edit. The container still runs as deployed: same root filesystem, same configuration, same group and restart policy.

## Enable devmode

Devmode is off by default. Turn it on with [`PV_DEVMODE_ALLOWED`](../reference/pantavisor-configuration.md#summary) in one of the two places that are part of the device's trusted configuration:

- [pantavisor.config](pantavisor-configuration-levels.md#pantavisorconfig), set when the image is built or on the device:

  ```
  PV_DEVMODE_ALLOWED=true
  ```

- the [OEM configuration](pantavisor-configuration-levels.md#oem) file inside the revision, at `<PV_OEM_NAME>/<PV_POLICY>.config` (`<PV_OEM_NAME>/default.config` when `PV_POLICY` is empty). With `PV_OEM_NAME=myoem`, from a [pvr](https://docs.pantahub.com/pvr/) checkout of the device:

  ```bash
  mkdir -p myoem
  echo "PV_DEVMODE_ALLOWED=true" >> myoem/default.config
  pvr add . && pvr commit && pvr post
  ```

Check the result with `pvcontrol conf ls`; the key reports `pv conf file` or `oem config` as its level. Any other level (user metadata, commands, the kernel command line, environment variables, policies) is refused with a warning in the log, because anyone who can write user metadata or edit the boot partition could otherwise open the device to unsigned code.

With `PV_DEVMODE_ALLOWED=false`, a devmode revision is refused: `PUT /steps/devmode/...` and the `run` command for a devmode revision both return an error.

## Devmode revisions

`pvcontrol devmode create` asks Pantavisor to do the following steps with one call, `POST /devmode`. The base is the committed revision unless you name one, and a left-over devmode revision of that base is removed first, so the session starts clean. Add `--resume` to keep its files:

```bash
pvcontrol devmode create
pvcontrol devmode create 12 --resume
```

By hand:

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

Starting a devmode revision, switching to another one and running a normal revision again all reboot the device, so that every container starts with or without its inlay. Wait for the new revision to show `UPDATED` (devmode) or `DONE` (normal):

```bash
pvcontrol steps show-progress current
```

### Know when the device reboots

Your SSH session drops when the device reboots, so Pantavisor says so before it happens:

- `pvcontrol` prints a line to stderr:

  ```
  $ pvcontrol devmode create
  starting the devmode revision; the device reboots now and this connection will drop
  {"revision":"devmode/r/187","base":"187","resumed":false,"reboot":true}
  $ pvcontrol cmd run 187
  leaving devmode for 187; the device reboots now and this connection will drop
  {"reboot":true}
  ```

  `pvcontrol cmd reboot` prints `rebooting back into devmode/r/187; the device reboots now ...` and `pvcontrol cmd run devmode/r/188` prints `running devmode/r/188; the device reboots now ...` and `pvcontrol devmode apply <system container> --reboot` prints `rebooting into the devmode revision to restart <system container>; the device reboots now ...`.
- the answer of the control socket has the body `{"reboot":true}`, for scripts and tools that call the [API](../reference/pantavisor-commands.md#commands) directly. Calls that do not reboot keep the empty body.
- Pantavisor logs one line at the `WALL` level right before it reboots, so it reaches `/dev/console` when [`PV_LOG_CONSOLE_ALERTS`](../reference/pantavisor-configuration.md#summary) is set:

  ```
  rebooting into devmode/r/187
  ```

  Read it later with `grep -r "rebooting into" /storage/logs/`.

`pvcontrol devmode create` while the devmode revision of that base runs changes nothing: the answer has `"running":true`. To start clean, run the committed revision first (`pvcontrol cmd run <revision>`) and create it again.

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

### Change files with plain commands

A container with the `mgmt` [role](containers.md) sees the whole filesystem of every container at `/pantavisor/devmode/<container>`, read-write. It is an overlay of the image layers (the container's configuration files, `root.ovl.squashfs` if it has one and `root.squashfs`) with the inlay on top, so you see the files of the image and can change them with `cp`, `rm`, `mkdir`, `rmdir`, `rsync` or `scp`:

```bash
ls /pantavisor/devmode/my-container/etc
cp ./my-app.conf /pantavisor/devmode/my-container/etc/my-app.conf
rm /pantavisor/devmode/my-container/etc/motd
```

Everything you change lands in the inlay, the image is never touched:

- a new or changed file is stored in the inlay;
- `rm` of a file of the image creates a whiteout in the inlay, a character device with number 0:0 that hides the file;
- `rmdir` followed by `mkdir` of a directory of the image makes the new directory opaque: it starts empty and hides everything the image had in it.

To make the folder match a build output exactly, including the files it no longer has, use `rsync`:

```bash
rsync -a -c --delete ./rootfs/ /pantavisor/devmode/my-container/
```

The `-c` compares file contents instead of size and modification time. Without it `rsync` rewrites every file whose time changed, and each of those is copied into the inlay even though the content is the same. A change of only the owner or permissions of an image file also copies it into the inlay.

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

### Copy files with pvcontrol

Without a shell in a mgmt container, for example over ssh to the host of the device, `pvcontrol devmode files` does the same through the control socket. The path is relative to the root of the container:

```bash
pvcontrol devmode files put my-container etc/my-app.conf ./my-app.conf --mode 0644
cat my-app.conf | pvcontrol devmode files put my-container etc/my-app.conf -
pvcontrol devmode files ls my-container
pvcontrol devmode files get my-container etc/my-app.conf
pvcontrol devmode files rm my-container etc/motd
pvcontrol devmode apply my-container
```

`ls` shows what devmode changed, the content of the inlay, with the `sha256` of every file. A file of the image that you removed is listed as `"type":"deleted"`. A change made this way is the same as one made in `/pantavisor/devmode/<container>`: it lands in the inlay, and the container sees it after `pvcontrol devmode apply`. The endpoints are in the [control socket reference](../reference/pantavisor-commands.md#devmodefiles), the commands in [pvcontrol](../tools/pvcontrol.md#devmode).

### See what the container wrote itself

The files a running container wrote itself live in its own writable layer, the top layer of the table above, and shadow the same path in the inlay. `/pantavisor/devmode/<container>` does not include that layer. Mgmt containers see it, read-only, at `/pantavisor/devmode/.container/<container>`:

```bash
ls /pantavisor/devmode/.container/my-container/etc
```

Writing there fails with a read-only filesystem error. Pantavisor binds it again whenever the container starts, since a layer with `boot` persistence starts empty on every boot. The `GET /devmode` call lists the path as `container_layer`, and the `persistence` of the layer as `container_layer_persistence`; see [/devmode](../reference/pantavisor-commands.md#devmode). This is managed automatically; no action is needed.

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
curl -X DELETE --unix-socket /pantavisor/pv-ctrl http://localhost/devmode/containers/my-container
```

The first call shows whether devmode is on, the running devmode revision, the revision it is based on and the inlay directory of each container. The second call empties the inlay of one container, including its whiteouts and opaque directories, and the overlay work directory next to it. The image files show again in `/pantavisor/devmode/<container>` right away, and in the container after its next restart.

## Run commands in a container

While a devmode revision runs, a container with the `mgmt` role can run a command in any other running container, with no ssh or shell in between:

```bash
pvcontrol containers exec my-container -- cat /etc/os-release
pvcontrol containers exec --timeout 5 my-container -- ls -l /usr/bin
```

The command runs in the namespaces, cgroups and capabilities of the container. The arguments reach it as you type them, so quotes and `$` need no extra escaping. A command can run for 600 seconds at most, and 4 commands can run at the same time.

The call is refused outside devmode (`403` when `PV_DEVMODE_ALLOWED` is off, `409` when no devmode revision runs), for callers without the `mgmt` role (`403`) and for Pantavisor itself (`404`). The raw call, its limits and all answers are in the [control socket reference](../reference/pantavisor-commands.md#run-a-command-in-a-container). Whether devmode is allowed on a device is also in its device metadata: `pantavisor.devmode.allowed` is `1` or `0`.

## Fallback to the last commit

A devmode revision is never committed. It is installed as a try, and stays one:

- `pv_rev` and the `done` marker keep pointing at the last revision that was committed before devmode started, not necessarily the revision the devmode revision is based on.
- A reboot that you ask Pantavisor for (`pvcontrol cmd reboot`, `pvcontrol devmode apply` on a system container) boots back into the devmode revision. Any reset, power loss or failed start boots that committed revision again. The devmode revision is then marked as rolled back: `pvcontrol steps show-progress devmode/r/12` shows `ERROR`.
- A running devmode revision shows `UPDATED` (`Update finished, revision not set as rollback point`).
- To go back to the committed revision on purpose, run it: `pvcontrol cmd run <revision>`. A plain reboot does not leave devmode.
- While a devmode revision runs, the `pantavisor.revision` device metadata key reports that committed revision, so Pantacor Hub commands that look up the current revision keep working. The key `pantavisor.devmode` holds the devmode revision name. It is removed on the next start into a committed revision, also after a rollback. Logs of the devmode revision stay tagged with its own name, and its progress is never sent to Pantacor Hub.
- A rolled back devmode revision can be run again with `pvcontrol cmd run devmode/r/12`.

Read both keys on the device, or from your workstation with `pvr`:

```
pvcontrol devmeta ls | jq '{rev: .["pantavisor.revision"], devmode: .["pantavisor.devmode"]}'
pvr device get <device> | jq '."device-meta"["pantavisor.devmode"]'
```

:::note
A reboot that devmode requests itself arms the try again, so the device comes back up in the devmode revision. On U-Boot the "already tried" marker lives in the `pv.env` file of the boot script, and Pantavisor clears it there: the generic boot script passes `PV_BOOTLOADER_TRYING_ENV=part:<n>:/pv.env`, see [bootloader](bsp.md#where-pv_trying-is-stored) and [configuration](../reference/pantavisor-configuration.md). Pantavisor only rewrites a `pv.env` that already exists. If it cannot, it logs a warning and the device boots the last commit after the reboot; run the devmode revision again. Appengine comes back up in the devmode revision on its own.

Check what happened on the device:

```
grep -r uboot-env-file /storage/logs/devmode/
```
:::

## Garbage collection

Devmode revisions are listed by `pvcontrol steps ls` and cleaned up by the [garbage collector](storage.md#garbage-collector) like local revisions: the running, updating and last committed revisions are kept, the rest can be removed. Removing a devmode revision also removes its files.

While `devmode/l/<name>` or `devmode/r/<number>` exists, the revision it is based on (`locals/<name>` or `<number>`) is never collected. Run the collector by hand with `pvcontrol cmd run-gc`.

## Reference

- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_DEVMODE_ALLOWED`
- [Control socket](../reference/pantavisor-commands.md#devmode) — `/devmode`, [`/devmode/files`](../reference/pantavisor-commands.md#devmodefiles), `/steps/devmode/...`, container restart with `?reboot=1`, [`/containers/{name}/exec`](../reference/pantavisor-commands.md#run-a-command-in-a-container)
