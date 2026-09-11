---
title: "Power"
sidebar_position: 9
description: "Power modes, wakelock scopes, PV_POWER_* keys, and the /wakelocks response."
---

# Pantavisor Power

**Overview:** [Power and Wakelocks](../overview/wakelocks.md) explains why suspend is blocked the way
it is, how managed mode schedules wakes, and what happens without kernel wakelock support.

## Power modes

Set with [`PV_POWER_MODE`](pantavisor-configuration.md#summary).

| Value | Suspend | Behaviour |
|-------|---------|-----------|
| `disabled` | never | No power management; wakelock calls are no-ops |
| `locks` | opportunistic | Kernel autosleep on; Pantavisor holds a wakelock whenever busy, so the device suspends only when idle and resumes on an external wake source. Default |
| `managed` | opportunistic + timed wake | As `locks`, plus Pantavisor arms an RTC alarm and wakes itself to poll Pantacor Hub, so no external wake source is required |

### Kernel requirement

`locks` and `managed` need `CONFIG_PM_WAKELOCKS` and a writable
`<PV_POWER_SYSFS_DIR>/wake_lock`.

| Mode | Kernel support missing |
|------|------------------------|
| `disabled` | Tolerated |
| `locks` | Degrades: one WARN, wakelocks become no-ops, boot proceeds. Reported as `degraded` in [`GET /wakelocks`](#get-wakelocks) |
| `managed` | Fatal: init fails and Pantavisor does not start, so a try-boot into such a revision never confirms and rolls back |

## Wakelock scopes

All suspend blocking goes through one kernel wakelock named `pantavisor`, reference-counted in
userspace. Each scope owns a guard and contributes at most one to the count.

| Scope | Held while |
|-------|------------|
| `boot` | From start until the state machine first reaches steady state (`RUN` → `WAIT`) |
| `update` | An [update](../overview/updates.md) downloads, installs and passes the post-boot test/commit |
| `update_check` | A poll-for-updates roundtrip is in flight |
| `devmeta` | A local [device-metadata](pantavisor-metadata.md#device-metadata) change is not yet synced to Pantacor Hub, bounded by `PV_POWER_DEVMETA_MAX_HELD` |
| `usrmeta` | A [user-metadata](pantavisor-metadata.md#user-metadata) GET is in flight |
| `shutdown` | Teardown (sync, unmount) during shutdown |
| `debug_shell` | A debug/serial shell session is open |
| `poll` | A managed-mode wake window is open |

## Configuration keys

Full rows, levels included, are in the [configuration reference](pantavisor-configuration.md#summary).
Every key below except `PV_POWER_MODE` and `PV_POWER_SYSFS_DIR` is a duration: it takes a bare
number of seconds or a single-unit value — `30s`, `10min`, `1h`, `1d`.

| Key | Default | Applies to | Meaning |
|-----|---------|------------|---------|
| `PV_POWER_MODE` | `locks` | all | [Power mode](#power-modes) |
| `PV_POWER_SYSFS_DIR` | `/sys/power` | `locks`, `managed` | Base dir of the wakelock sysfs nodes |
| `PV_POWER_DEVMETA_EAGER_PUSH` | `0` | all | Push a dirty `devmeta` change out-of-band immediately instead of waiting up to a full devmeta interval |
| `PV_POWER_DEVMETA_MAX_HELD` | `300` | all | Max seconds the `devmeta` scope is held awaiting a Hub ack |
| `PV_POWER_AUTOSLEEP_SETTLE` | `90` | `managed` | Delay after ready before autosleep is enabled |
| `PV_POWER_WAKE_INTERVAL` | `3600` | `managed` | Seconds between timed wakes |
| `PV_POWER_WAKE_MIN_AWAKE` | `10` | `managed` | Minimum awake seconds per wake window |
| `PV_POWER_WAKE_MAX_AWAKE` | `60` | `managed` | Maximum awake seconds per wake window |
| `PV_POWER_WAKE_RUN_WINDOW` | `0` | `managed` | Extra awake seconds after the wake's payloads complete, as the containers' guaranteed run window |

## `GET /wakelocks`

Served by the [control socket](pantavisor-commands.md#wakelocks), and wrapped by
[`pvcontrol wakelocks ls`](../tools/pvcontrol.md).

```bash
pvcontrol wakelocks ls
```

| Field | Type | Meaning |
|-------|------|---------|
| `mode` | string | The **active** power mode (`disabled` / `locks` / `managed`), which may lag the configured one until the next config apply |
| `count` | number | Current reference count on the `pantavisor` wakelock; `0` means the device is free to suspend |
| `degraded` | bool | `true` when `locks` mode fell back to no-op wakelocks because the kernel lacks wakelock support (`managed` fails init instead) |
| `autosleep` | bool | `true` once managed mode has enabled kernel autosleep, after the settle delay |
| `settling` | bool | `true` while managed mode is waiting out `PV_POWER_AUTOSLEEP_SETTLE` before enabling autosleep |
| `polling` | bool | `true` while a managed wake window is open — the device woke to poll Hub and/or run containers |
| `run_window` | bool | `true` only while `polling` is true and the guaranteed container run window has not yet elapsed |
| `held.boot` | bool | Held from start until the state machine first reaches steady state |
| `held.update` | bool | An update is downloading, installing, or in its post-boot test/commit |
| `held.update_check` | bool | A poll-for-updates roundtrip is in flight |
| `held.devmeta` | bool | A local device-metadata change is not yet synced to Hub |
| `held.usrmeta` | bool | A user-metadata GET is in flight |
| `held.shutdown` | bool | Teardown (sync, unmount) is running during shutdown |
| `held.debug_shell` | bool | A debug/serial shell session is open |
| `held.poll` | bool | A managed-mode wake window is open (mirrors `polling`) |
