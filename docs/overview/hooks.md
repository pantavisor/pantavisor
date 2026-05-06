---
nav_order: 13
---
# Hooks

## Overview

Hooks are executable scripts that Pantavisor runs at well-defined lifecycle points. They allow operators to execute custom logic — such as notifying an external service, validating system state, or triggering a reboot — at specific moments during startup, update installation, and platform status goal complete.

## Hooks Are Part of the Revision

Hooks live under `/usr/lib/pantavisor/pv/hooks/system.d/` on the root filesystem, which is part of the BSP layer shipped with each revision. When Pantavisor boots a new revision, it runs that revision's hooks — not the previous one's. This makes hooks a first-class part of the revision contract: if you change a hook, you update the revision.

The implications are significant for `system-start`:

- On a **try-boot** (booting a new, unconfirmed revision), `system-start` runs from the new revision's hook directory.
- If `system-start` exits non-zero, Pantavisor treats the boot as failed, triggers a reboot, and the bootloader's tryboot counter decrements toward rollback.
- Once the counter is exhausted, the bootloader selects the last-good revision and the device returns to a known-good state.

`system-start` is therefore a **gate on the revision, not a side-effect**. Use it to validate preconditions that must hold for the new revision to be viable — hardware presence, key material, valid configuration. A failure leaves no persistent state; the system simply reboots or rolls back.

`system-done` is intentionally asymmetric: it fires when all containers have reached their [status goal](containers.md#status-goal), but a non-zero exit is only logged and does not block the transition. Use `system-done` for notifications, telemetry, or late-stage side-effects where partial failure is acceptable. See [Failure Behaviour](#failure-behaviour) for details.

## Hook Directory

All hooks are placed under:

```
/usr/lib/pantavisor/pv/hooks/system.d/
```

The base path (`/usr/lib/pantavisor/pv`) is set at build time via `CMAKE_INSTALL_FULL_LIBDIR` and may differ depending on the target configuration.

Pantavisor discovers scripts in this directory on every hook invocation. Execution follows these rules:

- Scripts run in **alphabetical order** by filename.
- Only **regular files** with the **executable bit** (`S_IXUSR`) set are run; directories, symlinks, and non-executable files are silently skipped.
- Naming convention: use a numeric prefix (e.g. `10-my-hook`, `50-notify`) to control execution order.

## Hook Points

Each hook point corresponds to a specific moment in [Pantavisor's lifecycle](pantavisor-architecture.md#state-machine). The active hook point is communicated to hook scripts via the [`PV_OP`](#environment-variables) environment variable.

| `PV_OP` value | When it fires |
|---|---|
| `system-start` | Early during Pantavisor initialization, before containers are started. |
| [`system-before-install-update`](updates.md) | Before Pantavisor writes the incoming revision into the [bootloader](bsp.md#bootloader) environment (so the bootloader loads the right kernel on next boot). Fired only on backends with a dedicated install step: [`uboot-ab`](bsp.md#uboot-ab) and [`rpiab`](bsp.md#rpiab). |
| [`system-after-install-update`](updates.md) | After Pantavisor has written the incoming revision into the [bootloader](bsp.md#bootloader) environment. Same backends as `system-before-install-update`: [`uboot-ab`](bsp.md#uboot-ab) and [`rpiab`](bsp.md#rpiab). |
| [`system-install-update`](updates.md) | Combines before and after into a single hook point. Fired on backends without a dedicated install step: [`uboot`](bsp.md#uboot) and [`grub`](bsp.md#grub). |
| `system-boot-done` | After the new revision has been committed following a successful try-boot. `PV_TRYBOOT` is always `"true"` at this point. See [environment variables](#environment-variables) |
| `system-done` | When the platform reaches fully-running state (all containers have met their [status goal](containers.md#status-goal)). |

## Environment Variables

Pantavisor sets the following environment variables before executing every hook:

| Variable | Description |
|---|---|
| `PV_OP` | Name of the [hook point](#hook-points) currently running (see table above). |
| `PV_REV` | ID of the currently running [revision](revisions.md). |
| `PV_TRY` | ID of the revision being attempted for the next boot. Empty string if not in a try-boot or once the try-boot has been committed. For update hooks (`system-*-install-update`), this is the incoming revision being installed. |
| `PV_TRYBOOT` | `"true"` if the device booted into a trial revision that has not yet been committed, `"false"` otherwise. |
| `PV_OBJ_STORAGE` | Absolute path to the object [storage](storage.md) directory. |
| `PV_TRAILS_STORAGE` | Absolute path to the [trails](storage.md#trails-and-objects) directory for the current revision. |
| `PV_STATUS` | Current revision [status](updates.md) string from the progress JSON (e.g. `DONE`, `TESTING`). Empty if no progress file is available. |

## Writing a Hook

A hook is any executable file. The example below is a minimal shell script that reacts to different hook points:

```sh
#!/bin/sh

case "$PV_OP" in
    system-start)
        logger "Pantavisor is starting, current revision: $PV_REV"
        ;;
    system-before-install-update)
        logger "About to install revision: $PV_TRY"
        ;;
    system-boot-done)
        logger "New revision $PV_REV committed successfully"
        ;;
    system-done)
        logger "Platform fully running, revision: $PV_REV"
        ;;
esac

exit 0
```

Hooks are installed as part of the BSP build. Operators ship them via a dedicated BSP package or Yocto recipe — not by editing Pantavisor's own source tree. Any packaging mechanism that places an executable file at the hook directory path on the target filesystem is sufficient.

For a CMake-based BSP package, the install directive looks like:

```cmake
install(FILES path/to/50-my-script
	PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION ${PV_INSTALL_FULL_PVLIBDIR}/hooks/system.d)
```

For a Yocto recipe, use `do_install` to copy the file and `chmod +x` it, or place it under `files/` and use `install -m 0755`.

## Failure Behaviour

- A hook that exits with a **non-zero status** causes Pantavisor to abort any remaining hooks in the directory and fail the triggering operation.
- For `system-start`, failure is **fatal**: Pantavisor exits, the device reboots, and the bootloader's tryboot counter decrements. Once the counter reaches zero, the bootloader selects the last-good revision and the device rolls back. Treat `system-start` as a hard gate on the revision.
- For update hooks (`system-before-install-update`, `system-after-install-update`, `system-install-update`, `system-boot-done`), failure aborts the update process.
- For `system-done`, failure is **logged only** and does not prevent the platform from transitioning to its running state. This asymmetry with `system-start` is intentional: `system-done` fires after all containers have reached their status goal and the revision is already running; at that point there is no safe rollback path, so the hook result is informational.
- Hook output (stdout and stderr) is captured by the [logserver](storage.md#logs) and available in the device logs.
