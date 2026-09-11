---
title: "Hooks"
sidebar_position: 12
description: "System lifecycle hooks: what they gate, when they run, and how to write one."
---
# Hooks

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

Pantavisor re-scans this directory on every hook invocation and runs the executable regular files it
finds, in alphabetical order, so a numeric prefix (`10-my-hook`, `50-notify`) controls the order.
Anything non-executable is skipped, and a missing directory simply means no hooks. See
[hook directory rules](../reference/pantavisor-hooks.md#hook-directory) for the exact conditions.

## Hook Points

Each hook point corresponds to a specific moment in
[Pantavisor's lifecycle](pantavisor-architecture.md#state-machine), and is communicated to the
script through the `PV_OP` environment variable:

- `system-start` fires early in initialization, before containers start.
- `system-before-install-update` fires before writing the incoming revision into the 
  [bootloader](bsp.md#bootloader) environment during an [update](updates.md).
- `system-after-install-update` fires after writing the already installed revision into
  the [bootloader](bsp.md#bootloader) environment during an [update](updates.md).
- `system-install-update` combines the previous two.
- `system-boot-done` fires after a new revision has been committed following a successful try-boot.
- `system-done` fires when all containers have reached their [status goal](containers.md#status-goal).

Alongside `PV_OP`, Pantavisor passes the current and incoming revision IDs, the try-boot flag, the
object and trails storage paths, and the revision status to the script as variables. See the
[hook points](../reference/pantavisor-hooks.md#hook-points) and
[hook environment variables](../reference/pantavisor-hooks.md#hook-environment-variables) tables for
the complete lists.

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

A hook that exits non-zero aborts the remaining hooks in the directory and fails the triggering
operation, with one deliberate exception.

For `system-start`, failure is **fatal**: Pantavisor exits, the device reboots, and the bootloader's
tryboot counter decrements. Once the counter reaches zero the bootloader selects the last-good
revision and the device rolls back. Treat `system-start` as a hard gate on the revision. Update
hooks behave the same way, aborting the update.

For `system-done`, failure is **logged only** and does not prevent the platform from transitioning
to its running state. The asymmetry is intentional: `system-done` fires after all containers have
reached their status goal and the revision is already running, so there is no safe rollback path
left and the hook result is informational.

Hook output (stdout and stderr) is captured by the [logserver](storage.md#logs) and available in the
device logs.

## Reference

- [Hooks](../reference/pantavisor-hooks.md) — hook points, environment variables, directory rules, failure semantics
