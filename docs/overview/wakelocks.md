---
title: "Power and Wakelocks"
sidebar_position: 14
description: "How Pantavisor blocks and schedules system suspend so a device sleeps without missing updates."
---

# Power and Wakelocks

Pantavisor can block and schedule system suspend so a device sleeps between activity without missing
updates. Which of the three [power modes](../reference/pantavisor-power.md#power-modes) is in effect
is selected by [`PV_POWER_MODE`](../reference/pantavisor-configuration.md#summary): `disabled` does
nothing, `locks` (the default) suspends whenever Pantavisor is idle and relies on an external wake
source, and `managed` additionally wakes the device on a timer so it works with no external source
at all.

`locks` and `managed` both need kernel wakelock support. If it is missing, `managed` fails init and
Pantavisor does not start — a try-boot into such a revision never confirms and rolls back — because
silently never suspending would defeat the point of the mode. `locks` degrades instead: one warning,
wakelocks become no-ops, boot proceeds. Only `disabled` tolerates its absence outright. See
[kernel requirement](../reference/pantavisor-power.md#kernel-requirement).

## Wakelocks

All suspend blocking goes through one kernel wakelock named `pantavisor`, reference-counted in
userspace: the first acquire writes the name to `<PV_POWER_SYSFS_DIR>/wake_lock`, the last release
writes `wake_unlock`. Each [scope](../reference/pantavisor-power.md#wakelock-scopes) owns a guard,
so it contributes at most one to the count — boot, an in-flight update, a metadata sync, an open
debug shell, and so on.

`devmeta` is dirty-gated: it is held from a local `pv-ctrl` metadata change (only on an
authenticated Hub device) until Hub acks the change, bounded by
[`PV_POWER_DEVMETA_MAX_HELD`](../reference/pantavisor-configuration.md#summary).

## Managed mode

At init, managed mode arms an RTC wake alarm. Once the boot lock is released and platforms are up
(first `RUN` → `WAIT`), it enables kernel autosleep. From then:

1. The device suspends whenever the wakelock refcount reaches zero.
2. A worker thread is parked in a blocking `read()` on `/dev/rtc0`. When the RTC alarm fires it
   wakes the device; the thread grabs the `pantavisor` wakelock inline — same thread, right after
   the read returns — before the autosleep loop can re-suspend, then signals the event loop over an
   eventfd.
3. The event loop opens a **wake window**: it re-arms the alarm for the next cycle and holds `poll`
   while it polls Hub. The window stays open at least `PV_POWER_WAKE_MIN_AWAKE` (so the network can
   re-associate after deep suspend), until one poll round reaches Hub (or trivially, if unauthed or
   no Hub is configured), plus `PV_POWER_WAKE_RUN_WINDOW` more as the containers' guaranteed run
   time — all bounded by `PV_POWER_WAKE_MAX_AWAKE`.
4. When the window closes, `poll` is released and the device suspends again.

A found update holds `update` independently of the poll window, so the device stays awake through
download, install and reboot regardless of the wake schedule.

Every wake carries up to two payloads: the Hub roundtrip (if authed) and the container run window
(off by default). A wake is only re-armed if at least one payload applies — a device with neither
Hub nor a declared run window has nothing to wake for and stays asleep until an external event.

Waking through the RTC char device with a blocking read is deliberate. A `CLOCK_BOOTTIME_ALARM`
timerfd serviced from the event loop loses the race: autosleep re-suspends before the callback can
grab a wakelock. A blocking `read()` returns in-kernel while the RTC wakeup event is still held, so
grabbing the wakelock inline on the same thread closes that gap.

## Inspecting state

```bash
pvcurl /wakelocks
```

Reports the active mode, the refcount, whether autosleep/settle/poll are active, and which scopes
are held. See [`GET /wakelocks`](../reference/pantavisor-power.md#get-wakelocks) for the response
fields.

## Reference

- [Power](../reference/pantavisor-power.md) — modes, scopes, `PV_POWER_*` keys, `/wakelocks` response
- [Configuration](../reference/pantavisor-configuration.md#summary) — the `PV_POWER_*` rows with their levels
