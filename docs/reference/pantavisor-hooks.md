---
title: "Hooks"
sidebar_position: 8
description: "Hook points, hook environment variables, and failure semantics."
---

# Pantavisor Hooks

**Overview:** [Hooks](../overview/hooks.md) explains what hooks are for, why they are part of the
revision, and how to write one.

## Hook directory

```
/usr/lib/pantavisor/pv/hooks/system.d/
```

The base path (`/usr/lib/pantavisor/pv`) is set at build time via `CMAKE_INSTALL_FULL_LIBDIR` and
may differ per target.

| Rule | Behaviour |
|------|-----------|
| Discovery | The directory is re-scanned on every hook invocation |
| Order | Alphabetical by filename. Use a numeric prefix (`10-my-hook`, `50-notify`) to control it |
| Eligibility | Regular files with the owner-execute bit (`S_IXUSR`) set |
| Skipped | Directories, symlinks and non-executable files, silently |
| Missing directory | Not an error — no hooks run |
| Output | stdout and stderr are captured by the [log server](logserver-sockets.md) under the hook's filename |

## Hook points

The active hook point is passed to the script as [`PV_OP`](#hook-environment-variables).

| `PV_OP` value | When it fires | Bootloader backends |
|---------------|---------------|---------------------|
| `system-start` | Early in Pantavisor initialization, before containers are started | all |
| `system-before-install-update` | Before the incoming revision is written into the [bootloader](../overview/bsp.md#bootloader) environment | [`uboot-ab`](../overview/bsp.md#uboot-ab), [`rpiab`](../overview/bsp.md#rpiab) |
| `system-after-install-update` | After the incoming revision has been written into the bootloader environment | [`uboot-ab`](../overview/bsp.md#uboot-ab), [`rpiab`](../overview/bsp.md#rpiab) |
| `system-install-update` | Both of the above combined, for backends with no dedicated install step | [`uboot`](../overview/bsp.md#uboot), [`grub`](../overview/bsp.md#grub) |
| `system-boot-done` | After a new revision has been committed following a successful try-boot | all |
| `system-done` | When all containers have reached their [status goal](../overview/containers.md#status-goal) | all |

## Hook environment variables

Set before executing every hook, unset afterwards.

| Variable | Value |
|----------|-------|
| `PV_OP` | The [hook point](#hook-points) currently running |
| `PV_REV` | ID of the currently running [revision](../overview/revisions.md) |
| `PV_TRY` | ID of the revision being attempted for the next boot; the incoming revision for update hooks. Empty outside a try-boot, or once committed |
| `PV_TRYBOOT` | `"true"` if booted into an uncommitted trial revision, `"false"` otherwise. Always `"true"` during `system-boot-done` |
| `PV_OBJ_STORAGE` | Absolute path to the object [storage](../overview/storage.md) directory |
| `PV_TRAILS_STORAGE` | Absolute path to the [trails](../overview/storage.md#trails-and-objects) directory for the current revision |
| `PV_STATUS` | Current revision [status](../overview/updates.md) from the progress JSON (e.g. `DONE`, `TESTING`). Empty if no progress file exists |

## Failure semantics

A non-zero exit aborts the remaining hooks in the directory. What happens next depends on the hook
point:

| `PV_OP` | Effect of a non-zero exit |
|---------|---------------------------|
| `system-start` | Fatal. Pantavisor exits, the device reboots, and the bootloader's tryboot counter decrements toward [rollback](../overview/updates.md#error) |
| `system-before-install-update` | The update install is aborted |
| `system-after-install-update` | The update install is aborted |
| `system-install-update` | The update install is aborted |
| `system-boot-done` | The commit fails |
| `system-done` | Logged only. The platform still transitions to its running state |
