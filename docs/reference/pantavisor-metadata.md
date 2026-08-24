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
| `storage` | json | disk usage of the device (see [refreshed on read](#refreshed-on-read)) |
| `sysinfo` | json | [sysinfo](https://man7.org/linux/man-pages/man2/sysinfo.2.html) plus `uptime` and `idle` (see [`sysinfo` format](#sysinfo-format)) |
| `time` | json | time information (see [refreshed on read](#refreshed-on-read)) |

## Refreshed on read

`sysinfo`, `storage` and `time` are measurements, not state: they are re-read
every time the device metadata is serialized, so a read always answers with the
current value rather than one captured at boot. Because they change on every
read they are never written to the persistent device metadata directory
(`PV_CACHE_DEVMETADIR`); an older copy left there by a previous Pantavisor
version is removed on start.

Every other key keeps its existing behaviour: its producer publishes it when it
changes, and the value is persisted.

```bash
# both reads report the current uptime, not the boot-time one
pvcontrol devmeta ls | jq .sysinfo.uptime
sleep 5
pvcontrol devmeta ls | jq .sysinfo.uptime
```

## `sysinfo` format

`sysinfo` carries the fields of [sysinfo(2)](https://man7.org/linux/man-pages/man2/sysinfo.2.html)
plus two taken from `/proc/uptime`:

| Field | Description |
| ----- | ----------- |
| `uptime` | seconds since boot, with the centisecond precision `/proc/uptime` provides |
| `idle` | seconds all CPUs spent idle, **summed over every CPU**, so on an SMP machine it can exceed `uptime`. Absent when `/proc/uptime` cannot be read |

When `/proc/uptime` is unavailable, `uptime` falls back to the whole-second
value from `sysinfo(2)` and `idle` is omitted.

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
