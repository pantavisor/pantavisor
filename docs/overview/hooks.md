---
nav_order: 13
---
# Hooks

## Overview

Hooks are executable scripts that Pantavisor runs at well-defined lifecycle points. They allow operators to execute custom logic — such as notifying an external service, validating system state, or triggering a reboot — at specific moments during startup, update installation, and platform status goal complete.

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
| [`system-before-install-update`](updates.md) | Before Pantavisor writes the incoming revision into the [bootloader](bsp.md#bootloader) environment (so the bootloader loads the right kernel on next boot). Only fired on bootloaders that support separate before/after install hooks. |
| [`system-after-install-update`](updates.md) | After Pantavisor has written the incoming revision into the [bootloader](bsp.md#bootloader) environment. Only fired on bootloaders that support separate before/after install hooks. |
| [`system-install-update`](updates.md) | Combines before and after into a single hook point, fired on [bootloaders](bsp.md#bootloader) that do not support separate before/after hooks. |
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

Install the script into the hook directory, this is done in build time in the CMakeLists.txt file. As example, on cmake this should be the command to install an script:

```sh
install(FILES path/to/50-my-script
	PERMISSIONS WORLD_READ WORLD_EXECUTE GROUP_READ GROUP_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION ${PV_INSTALL_FULL_PVLIBDIR}/hooks/system.d)
```

## Failure Behaviour

- A hook that exits with a **non-zero status** causes Pantavisor to abort any remaining hooks in the directory and fail the triggering operation.
- For update hooks (`system-before-install-update`, `system-after-install-update`, `system-install-update`, `system-boot-done`), failure aborts the update process.
- For `system-done`, failure is logged but does not prevent the platform from transitioning to its running state.
- Hook output (stdout and stderr) is captured by the [logserver](storage.md#logs) and available in the device logs.
