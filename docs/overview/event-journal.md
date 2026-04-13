# Event Journal

Pantavisor includes a structured event journaling system that records timestamped lifecycle events from all subsystems into the revision's [progress payload](storage.md#update-progress). This provides a machine-readable "black box" that admin tools and dashboards can use to understand what happened on a device — which containers crashed, when recovery was attempted, whether the cloud connection dropped, and how the update progressed.

## Overview

Events accumulate in a fixed-size ring buffer (128 entries, ~29 KB) scoped to the current revision. When the buffer is full, oldest events are overwritten and a synthetic `wrapped` marker is emitted. Events are serialized into the `events` array of the progress JSON, which flows to both the local `.pv/progress` file and [Pantacor Hub](remote-control.md#pantacor-hub).

Event journaling can be disabled via the [`PV_LOG_EVENTS`](../reference/pantavisor-configuration.md) configuration key to avoid unnecessary storage writes on flash-constrained devices.

## Event Structure

Each event contains:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | integer | Wall-clock Unix timestamp |
| `type` | string | Event category: `system`, `platform`, `update`, `pantahub` |
| `src` | string | Source identifier (container name, revision number, subsystem name, or `"pantahub"`) |
| `event` | string | Event name (e.g. `started`, `crashed`, `testing`, `online`) |
| `detail` | string | Optional space-separated `key=value` pairs with additional context |

Example progress JSON with events:

```json
{
  "status": "DONE",
  "status-msg": "Factory revision",
  "progress": 100,
  "retries": 0,
  "events": [
    {"ts": 1718000001, "type": "system",   "src": "pantavisor", "event": "state_change", "detail": "STATE_INIT -> STATE_RUN"},
    {"ts": 1718000002, "type": "update",   "src": "0",          "event": "boot",         "detail": "resumed after reboot"},
    {"ts": 1718000005, "type": "platform", "src": "my-app",     "event": "started"},
    {"ts": 1718000006, "type": "platform", "src": "my-app",     "event": "ready"},
    {"ts": 1718000030, "type": "platform", "src": "my-app",     "event": "stable"},
    {"ts": 1718000035, "type": "platform", "src": "crash-app",  "event": "crashed",      "detail": "pid=1234"},
    {"ts": 1718000040, "type": "platform", "src": "crash-app",  "event": "recovering",   "detail": "attempt=1/5 delay=5s"}
  ]
}
```

## Event Types

### `system` — Pantavisor internals

Source is the subsystem name. Tracks state machine transitions and managed daemon lifecycle.

| src | event | detail | description |
|-----|-------|--------|-------------|
| `pantavisor` | `state_change` | `STATE_INIT -> STATE_RUN` | Pantavisor state machine transition |

### `platform` — Container lifecycle

Source is the container name. Tracks the full container lifecycle including [auto-recovery](containers.md#auto-recovery).

| event | detail | description |
|-------|--------|-------------|
| `started` | | Container process started |
| `ready` | | Container reached its [status goal](containers.md#status-goal) |
| `stable` | | Container survived the [stable_timeout](containers.md#auto-recovery) period without crashing |
| `crashed` | `pid=N` | Container process exited unexpectedly |
| `recovering` | `attempt=N/M delay=Ns` | Auto-recovery restarting container after backoff delay |
| `max_retries` | `backoff=reboot\|never\|Ns` | Auto-recovery exhausted max retries, applying [backoff policy](containers.md#auto-recovery) |
| `stopped` | | Container stopped |
| `user_stopped` | | Container stopped via [ctrl API](local-control.md) |
| `user_started` | | Container started via [ctrl API](local-control.md) |
| `user_restarted` | | Container restarted via [ctrl API](local-control.md) |

### `update` — Revision lifecycle

Source is the revision number. Tracks the [update flow](updates.md#progress) from queuing through commit or rollback.

| event | detail | description |
|-------|--------|-------------|
| `queued` | `retry=N/M` | Update queued for processing |
| `downloading` | | Object download phase started |
| `reboot` | | Rebooting into new revision |
| `transition` | | Non-reboot transition to new revision |
| `boot` | `resumed after reboot` | Booted into new revision after reboot |
| `testing` | `mode=reboot\|nonreboot` | Entered [TESTING](updates.md#testing) phase |
| `committed` | | Revision [committed](updates.md#done) as rollback point |
| `rollback` | | [Rollback](updates.md#error) triggered |

### `pantahub` — Cloud communication

Source is `"pantahub"`. Tracks connectivity and authentication with [Pantacor Hub](remote-control.md#pantacor-hub).

| event | detail | description |
|-------|--------|-------------|
| `online` | | Hub communication restored |
| `offline` | `failed_reqs=N` | Hub communication lost after N failed requests |
| `auth` | | Successfully authenticated with Hub |
| `auth_failed` | | Authentication failed |

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `PV_LOG_EVENTS` | `1` | Enable (`1`) or disable (`0`) event journaling. Can be changed at runtime via config override. |

When disabled, no events are recorded and the `events` array is omitted from the progress JSON.

## Querying Events

Events can be queried locally via the ctrl API:

```bash
# Get progress with events for the current revision
pvcontrol steps get 0 progress
# or
pvcurl GET /steps/0/progress
```

When connected to [Pantacor Hub](remote-control.md#pantacor-hub), events are automatically included in progress reports sent to the cloud.
