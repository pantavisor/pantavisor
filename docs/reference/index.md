---
title: "Reference"
sidebar_position: 2
description: "Exact specifications for state formats, configuration, commands, tools, and schemas."
---

# Reference

- [State Format](pantavisor-state-format-v2.md) — `state.json` schema (v2): root keys, BSP manifest, container manifest, device and groups manifests, signature manifest, and all field definitions
- [Configuration](pantavisor-configuration.md) — All `pantavisor.json` keys, default values, value types, and the configuration level at which each key is effective
- [Control Socket](pantavisor-commands.md) — pv-ctrl HTTP-over-Unix-socket endpoints: containers, groups, signals, daemons, and xconnect graph
- [Tools](pantavisor-tools.md) — On-device CLI tools: `pventer`, `pvcurl`, `pvcontrol`, and `pvtx` — commands, flags, and usage examples
- [xconnect](pantavisor-xconnect.md) — Service mesh manifest format: `services.json` export declarations and `run.json` requirement declarations for Unix sockets, D-Bus, DRM, and Wayland
- [Metadata](pantavisor-metadata.md) — User-defined and system-managed device metadata: key namespaces, update API, and persistence
- [Log Sockets](logserver-sockets.md) — Logserver Unix socket paths, message format, and how containers attach to the log stream
- [IPAM](pantavisor-ipam.md) — IP address management configuration: address pools, container address assignment, and namespace configuration
