---
title: "Metadata"
sidebar_position: 5
description: "User-defined and system-managed device metadata reference."
---

# Pantavisor Metadata

This page contains reference information about [Pantavisor metadata](../overview/storage.md#metadata).

## Device metadata

This is the device metadata created by Pantavisor that will give you useful information about your device:

| Key | Value | Description |
| --- | ----- | ----------- |
| `interfaces` | json | network interfaces of the device, keyed by `<iface>.<family>` where family is `ipv4`, `ipv6` or `mac` (see below) |
| `pantahub.address` | IP:port | Pantacor Hub address the client is communicating with |
| `pantahub.claimed` | 0 or 1 | 1 if claimed in Pantacor Hub |
| `pantahub.online` | 0 or 1 | 1 if connection to Pantacor Hub was established |
| `pantahub.state` | string | [see Pantacor Hub states](../overview/remote-control.md#pantacor-hub-client) (init, register, claim, sync, login, wait hub, report, idle, prep download or download) |
| `pantavisor.arch` | string | CPU architecture |
| `pantavisor.claimed` | 0 or 1 | 1 if device has ever been claimed (local or remote) |
| `pantavisor.cpumodel` | string | CPU model name |
| `pantavisor.dtmodel` | string | Device Tree model name |
| `pantavisor.mode` | local or remote | [see operation modes](../overview/pantavisor-architecture.md#communication-with-the-outside-world) |
| `pantavisor.revision` | string | [revision number](../../meta-pantavisor/getting-started/develop/cli-tools/workflows.md) |
| `pantavisor.status` | string | [revision status](../overview/containers.md#status) |
| `pantavisor.uname` | json | [uname](https://man7.org/linux/man-pages/man1/uname.1.html) output |
| `pantavisor.version` | string | Pantavisor build version |
| `storage` | json | disk usage of the device (see [live keys](#live-keys)) |
| `sysinfo` | json | [sysinfo](https://man7.org/linux/man-pages/man2/sysinfo.2.html) plus `uptime`, `idle` and `nproc` (see [`sysinfo` format](#sysinfo-format)) |
| `time` | json | time information (see [live keys](#live-keys)) |

## Live keys

`sysinfo`, `storage` and `time` are measurements, not state: they are re-read
every time the device metadata is serialized, so a read always answers with the
current value rather than one captured at boot.

Like every other key they are persisted under `PV_CACHE_DEVMETADIR` and appear
in the container-visible device metadata directory, so a container can read them
straight from the filesystem:

```bash
# from inside a container
cat /pv/device-meta/sysinfo | jq .uptime
cat /pv/device-meta/storage | jq .free
```

What is gated is *when* those files are rewritten, not whether they exist — see
[sync triggers](#sync-triggers). No key is ever staler than
[`PV_METADATA_DEVMETA_SYNCBEAT`](pantavisor-configuration.md#summary), and the
copy left by the previous boot is overwritten before anything can read it.

```bash
# both reads report the current uptime, not the boot-time one
pvcontrol devmeta ls | jq .sysinfo.uptime
sleep 5
pvcontrol devmeta ls | jq .sysinfo.uptime
```

## `sysinfo` format

`sysinfo` carries the fields of [sysinfo(2)](https://man7.org/linux/man-pages/man2/sysinfo.2.html)
plus three that it does not provide:

| Field | Description |
| ----- | ----------- |
| `uptime` | seconds since boot, with the centisecond precision `/proc/uptime` provides |
| `idle` | seconds all CPUs spent idle, **summed over every CPU**, so on an SMP machine it can exceed `uptime`. Absent when `/proc/uptime` cannot be read |
| `nproc` | online CPUs, from `sysconf(_SC_NPROCESSORS_ONLN)`; the divisor that makes `idle` readable |

When `/proc/uptime` is unavailable, `uptime` falls back to the whole-second
value from `sysinfo(2)` and `idle` is omitted.

## Sync triggers

Device metadata is sampled every
[`PH_METADATA_DEVMETA_INTERVAL`](pantavisor-configuration.md#summary) seconds,
but a sample only causes a sync — a write to `PV_CACHE_DEVMETADIR`, a
`PUT /device-meta` to Pantacor Hub — when it carries news. Every field is
published in every sync whatever its kind below; the kind only decides whether a
move in *that* field is a reason to sync now.

| Kind | A sync is triggered when |
| ---- | ------------------------ |
| exact | the value differs at all |
| absolute | the value moved by more than a fixed magnitude |
| fraction | the value moved by more than a fraction of its capacity field |
| rate | the value departed from its expected rate of change |
| opportunistic | never; the field goes out with whatever else syncs |

No threshold is ever relative to the value being measured. A gauge is measured
against the capacity that does not move, so a 25% swing in free memory means the
same thing on a device with 20 MB free as on one with 400 MB free.

### `sysinfo`

| Field | Kind | Default |
| ----- | ---- | ------- |
| `uptime` | rate | expected 1.0/s, tolerance 2s |
| `idle` | rate | expected `nproc`/s, tolerance 2s |
| `loads.0`, `loads.1`, `loads.2` | absolute | 0.5 load |
| `procs` | absolute | 5 |
| `freeram`, `sharedram`, `bufferram` | fraction | 50‰ of `totalram` |
| `freeswap` | fraction | 50‰ of `totalswap` |
| `freehigh` | fraction | 50‰ of `totalhigh` |
| `totalram`, `totalswap`, `totalhigh`, `mem_unit`, `nproc` | exact | — |

`uptime` never triggers on its own — not by exclusion, but because a counter
that advances one second per second is exactly what the rate policy expects.
`idle` runs on the same rule and trips when the CPUs were *busy*, which is the
event worth reporting.

### `storage`

| Field | Kind | Default |
| ----- | ---- | ------- |
| `free`, `real_free` | fraction | 10‰ of `total` |
| `total`, `reserved` | exact | — |

### `time`

| Field | Kind | Default |
| ----- | ---- | ------- |
| `timeval.tv_sec` | rate | expected 1.0/s, tolerance 2s |
| `timeval.tv_usec` | opportunistic | — |
| `timezone.tz_minuteswest`, `timezone.tz_dsttime` | exact | — |

`tv_sec` trips on an NTP **step** and not on the mere passage of time, which no
magnitude threshold could tell apart.

### Everything else

`pantavisor.*`, `pantahub.*`, `interfaces` and every container-written key are
exact: they sync on any change.

### Tuning and bounds

[`PV_METADATA_DEVMETA_THRESHOLD_FACTOR`](pantavisor-configuration.md#summary)
scales every magnitude above by an integer percent — `50` is twice as sensitive,
`400` four times as tolerant, and `0` turns the gate off entirely so any
difference syncs, which is the setting to reach for when diagnosing. It has no
effect on exact or opportunistic fields.

Both keys allow the [user metadata level](../overview/pantavisor-configuration-levels.md#user-metadata),
so they can be changed on a running device without a reboot; the value actually
in force is readable from [`/config`](pantavisor-commands.md#config):

```bash
curl -X GET --unix-socket /pantavisor/pv-ctrl \
     "http://localhost/config" | jq '."metadata.devmeta.threshold_factor"'
```

Regardless of any of the above, nothing is ever staler than
[`PV_METADATA_DEVMETA_SYNCBEAT`](pantavisor-configuration.md#summary) seconds,
on disk or at Pantacor Hub. That bound is measured on a suspend-aware clock, so
a device sleeping under [`PV_POWER_MODE=managed`](../overview/wakelocks.md)
counts the wall-clock seconds it spent asleep rather than only the ones it spent
awake.

A push to Pantacor Hub additionally happens after re-authenticating, and
whenever a container wrote device metadata through
[pv-ctrl](pantavisor-commands.md) that has not reached Hub yet.

## `interfaces` format

The `interfaces` device metadata is a JSON object keyed by `<iface>.<family>`. Each value is an array, since an interface can hold multiple addresses of the same family. The `mac` family carries the interface hardware (MAC) address; interfaces without a hardware address (e.g. `lo`) have no `mac` entry.

```json
{
  "eth0.mac": ["b8:27:eb:00:11:22"],
  "eth0.ipv4": ["192.168.1.10"],
  "eth0.ipv6": ["fe80::ba27:ebff:fe00:1122"],
  "lo.ipv4": ["127.0.0.1"],
  "lo.ipv6": ["::1"]
}
```

## User metadata

This is the user metadata that can be set by the user which is parsed and have some actions on Pantavisor:

| Key | Value | Description |
| --- | ----- | ----------- |
| `pvr-sdk.authorized_keys` | SSH pub key | set [public key](../../meta-pantavisor/getting-started/operate/device-access/local-network.md) to get SSH access |
| `pvr-auto-follow.url` | URL | device will automatically pull every change in the device associated to that [clone URL](../../meta-pantavisor/getting-started/develop/cli-tools/pvr-cli.md) |
| `pantahub.log.push` | 0 or 1 | disable/enable log pushing to Pantacor Hub. Overrides [PV_LOG_PUSH](pantavisor-configuration.md#summary) |
| `<config-key>` | config-value | override any [configuration](pantavisor-configuration.md#summary) keys that allow RUN level |
| `<container>/<key>` | value | send user metadata that can be consumed by one of the containers |
