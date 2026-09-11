---
title: "Technical Overview"
sidebar_position: 0
description: "Concept-level explanations of how Pantavisor works, meant to be read top-to-bottom."
---

# Technical Overview

How Pantavisor works and why it is built this way, ordered to be read as a book. For the exact
keys, fields and endpoints behind any of it, follow the **Reference** links at the foot of each
page, or start from the [Reference index](../reference/index.md).

## Foundations

1. [Architecture](pantavisor-architecture.md) — the two jobs Pantavisor does, and the state machine it does them in
2. [Revisions](revisions.md) — the unit of state: what a revision is and how state JSON makes it reproducible
3. [BSP](bsp.md) — kernel, modules, firmware and bootloader, versioned alongside application containers
4. [Containers](containers.md) — runtime, groups, roles, status, auto-recovery and lifecycle control

## State and storage

5. [Updates](updates.md) — the atomic update flow, its progress states, and the failure paths
6. [Storage](storage.md) — on-disk layout, object store, logs, metadata and integrity
7. [Disks](disks.md) — disk types, single and dual-mode partitioning, dm-crypt, boot sequence

## Control

8. [Remote Control](remote-control.md) — the Pantacor Hub client and other remote controllers
9. [Local Control](local-control.md) — the pv-ctrl socket, Pantabox and pvcontrol

## Runtime services

10. [IPAM](ipam.md) — container IP address management: pools, allocation, network namespaces
11. [Inter-Container Communication](xconnect.md) — the xconnect service mesh
12. [Hooks](hooks.md) — lifecycle hooks, and how `system-start` gates a revision
13. [Watchdog](watchdog.md) — kernel watchdog integration and the four ping modes
14. [Power and Wakelocks](wakelocks.md) — blocking and scheduling suspend without missing updates

## Configuration and modes

15. [Configuration Levels](pantavisor-configuration-levels.md) — the precedence hierarchy across factory, device and container scopes
16. [Init Mode](init-mode.md) — embedded, standalone and appengine, and when to use each
