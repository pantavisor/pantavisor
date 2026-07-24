# Wakelocks and power modes

Pantavisor can block and schedule system suspend so a device sleeps between
activity without missing updates. The behaviour is selected by `power.mode`:

| mode | suspend | description |
|------|---------|-------------|
| `disabled` | never | no power management; wakelock calls are no-ops |
| `locks` (default) | opportunistic | kernel autosleep is on; Pantavisor holds a wakelock whenever it is busy, so the device suspends only when idle and comes back on an external wake source |
| `managed` | opportunistic + timed wake | as `locks`, plus Pantavisor wakes itself on a timer to poll Hub, so it works with no external wake source |

`locks` and `managed` both need kernel wakelock support (`CONFIG_PM_WAKELOCKS`,
a writable `/sys/power/wake_lock`). If it is missing: `managed` fails init and
Pantavisor does not start (a tryboot to such a revision never confirms and
rolls back), since silently never suspending would defeat the point of the
mode; `locks` degrades instead — one WARN, wakelocks become no-ops, boot
proceeds (reported via `degraded` in `GET /wakelocks`). Only `disabled`
tolerates its absence outright.

## Wakelocks

All suspend blocking goes through one kernel wakelock named `pantavisor`,
reference-counted in userspace: the first acquire writes the name to
`/sys/power/wake_lock`, the last release writes `/sys/power/wake_unlock`. Each
scope owns a guard, so it contributes at most one to the count.

| scope | held while |
|-------|-----------|
| `boot` | from start until the FSM first reaches steady state (`RUN -> WAIT`) |
| `update` | an update downloads, installs and passes the post-boot test/commit |
| `update_check` | a poll-for-updates roundtrip is in flight |
| `devmeta` | a local device-metadata change is not yet synced to Hub |
| `usrmeta` | a user-metadata GET is in flight |
| `shutdown` | teardown (sync, unmount) during shutdown |
| `debug_shell` | a debug/serial shell session is open |
| `poll` | a managed-mode wake window is open |

`devmeta` is dirty-gated: held from a local `pv-ctrl` metadata change (only on an
authenticated Hub device) until Hub acks the change, bounded by
`power.devmeta.max_held`.

## Managed mode

At init, managed mode arms an RTC wake alarm. Once the boot lock is released and
platforms are up (first `RUN -> WAIT`), it enables kernel autosleep. From then:

1. The device suspends whenever the wakelock refcount reaches zero.
2. A worker thread is parked in a blocking `read()` on `/dev/rtc0`. When the RTC
   alarm fires it wakes the device; the thread grabs the `pantavisor` wakelock
   inline — same thread, right after the read returns — before the autosleep
   loop can re-suspend, then signals the event loop over an eventfd.
3. The event loop opens a **wake window**: it re-arms the alarm for the next
   cycle and holds `poll` while it polls Hub. The window stays open at least
   `power.wake.min_awake` (so the network can re-associate after deep
   suspend), until one poll round reaches Hub (or trivially, if unauthed/no
   Hub configured) plus `power.wake.run_window` more as the containers'
   guaranteed run time, bounded by `power.wake.max_awake`.
4. When the window closes, `poll` is released and the device suspends again.

A found update holds `update` (independent of the poll window), so the device
stays awake through download, install and reboot regardless of the wake
schedule.

Every wake carries up to two payloads: the Hub roundtrip (if authed) and the
container run window (`power.wake.run_window`, off by default). A wake is
only re-armed if at least one payload applies — a device with neither Hub nor
a declared run window has nothing to wake for and stays asleep until an
external event.

Waking through the RTC char device with a blocking read is deliberate. A
`CLOCK_BOOTTIME_ALARM` timerfd serviced from the event loop loses the race:
autosleep re-suspends before the callback can grab a wakelock. A blocking
`read()` returns in-kernel while the RTC wakeup event is still held, so grabbing
the wakelock inline on the same thread closes that gap.

## Configuration

| key | default | meaning |
|-----|---------|---------|
| `power.mode` | `locks` | `disabled` / `locks` / `managed` |
| `power.wake.interval` | `3600` | managed: seconds between timed wakes (device heartbeat) |
| `power.wake.run_window` | `0` (off) | managed: after the wake's payload(s) complete, stay awake this many further seconds as the containers' guaranteed run window |
| `power.autosleep.settle` | `90` | managed: delay after ready before autosleep is enabled |
| `power.wake.min_awake` | `10` | managed: minimum awake seconds per wake window |
| `power.wake.max_awake` | `60` | managed: maximum awake seconds per wake window |
| `power.devmeta.max_held` | `300` | max seconds the `devmeta` lock is held awaiting a Hub ack |
| `power.sysfs_dir` | `/sys/power` | base dir of the wakelock sysfs nodes |

## Inspecting state

`GET /wakelocks` on the pv-ctrl socket returns the current mode, refcount,
whether autosleep/settle/poll are active, and which scopes are held.
