---
title: "Reference"
sidebar_position: 0
description: "Exact specifications for state formats, configuration, commands, and schemas."
---

# Reference

Complete, enumerable specifications. Every accepted value, default and field is listed here; the
[Technical Overview](../overview/index.md) explains what they mean.

## Formats

- [State Format](pantavisor-state-format-v2.md) — `state.json` schema (v2): root keys, BSP, drivers, infrastructure, groups, disks, container, service-mesh and signature manifests, with a complete example

## Runtime interfaces

- [Control Socket](pantavisor-commands.md) — pv-ctrl HTTP-over-Unix-socket endpoints: containers, groups, wakelocks, signals, commands, storage, objects, steps, metadata, xconnect graph, config and drivers
- [Log Sockets](logserver-sockets.md) — `pv-ctrl-log` and `pv-fd-log`, the `/dev/log` syslog protocols, output sinks and timestamp formats
- [Metadata](pantavisor-metadata.md) — device and user metadata keys, formats, refresh behaviour and change thresholds

## Configuration

- [Pantavisor Configuration](pantavisor-configuration.md) — every configuration key, its accepted values, built-in default, and the levels it may be set at

## Subsystems

- [Hooks](pantavisor-hooks.md) — hook directory rules, hook points, hook environment variables and failure semantics
- [Power](pantavisor-power.md) — power modes, wakelock scopes, `PV_POWER_*` keys and the `/wakelocks` response
- [IPAM](pantavisor-ipam.md) — pool and per-container network schemas, lease lifecycle, backend plugin hooks, NAT backend and error handling
- [xconnect](pantavisor-xconnect.md) — `services.json` and `run.json` service manifests, mediation patterns and the hosted D-Bus system bus
