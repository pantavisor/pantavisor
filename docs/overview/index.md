---
title: "Technical Overview"
sidebar_position: 1
description: "Concept-level explanations of how Pantavisor works, meant to be read top-to-bottom."
---

# Technical Overview

1. [Architecture](pantavisor-architecture.md) — High-level system design: container orchestration, cloud and local communication, service mesh, and the state machine
2. [Revisions](revisions.md) — The core state model: what a revision is, how state JSON represents it, and how the trail of revisions enables rollback
3. [BSP](bsp.md) — Board Support Package: kernel, modules, firmware, and how they are versioned alongside application containers
4. [Containers](containers.md) — Container runtime, groups, roles, lifecycle, and restart policy
5. [Updates](updates.md) — Atomic update flow, state transitions, success and failure paths
6. [Storage](storage.md) — On-disk layout, object store, logs, and metadata persistence
7. [Disks](disks.md) — Disk types, single and dual-mode partitioning, dm-crypt encryption, and boot sequence
8. [Remote Control](remote-control.md) — Pantacor Hub client, cloud-initiated updates, and remote command handling
9. [Local Control](local-control.md) — pv-ctrl Unix socket, Pantabox, and the pvcontrol CLI
10. [IPAM](ipam.md) — Container IP address management: address allocation and network namespace configuration
11. [Inter-Container Communication](xconnect.md) — xconnect service mesh: service discovery, Unix sockets, D-Bus, DRM, and Wayland mediation between containers
12. [Configuration Levels](pantavisor-configuration-levels.md) — The precedence hierarchy for pantavisor.json configuration across factory, device, and container scopes. See the [Pantavisor Configuration reference](../reference/pantavisor-configuration.md) for the full list of keys, defaults, and levels
13. [Init Mode](init-mode.md) — Embedded, standalone, and appengine operational modes and when to use each
14. [Hooks](hooks.md) — System lifecycle hooks: boot, update, platform-ready, and custom extension points
15. [Watchdog](watchdog.md) — Hardware and software watchdog integration, kick intervals, and failure handling
