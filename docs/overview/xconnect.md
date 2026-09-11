---
title: "Inter-Container Communication"
sidebar_position: 11
description: "The xconnect service mesh: service discovery and resource mediation between containers."
---
# Inter-Container Communication

Pantavisor includes `pv-xconnect`, a built-in service mesh that manages communication between [containers](containers.md) at runtime. It runs as a managed daemon alongside Pantavisor, active in all [init modes](init-mode.md).

## Why xconnect?

In a Pantavisor system, containers are isolated by design. When one container needs to talk to a service in another — a D-Bus system bus, a REST API, a graphics device — this traditionally required manual socket coordination, custom bind mounts, and trusting each container to self-identify correctly.

`pv-xconnect` replaces this with a **mediation layer**: providers declare what services they expose, consumers declare what they need, and Pantavisor injects the correct virtual resources into the consumer's namespace at runtime. Container identity is resolved by Pantavisor itself, not by the container.

## How It Works

The service mesh operates through a graph of connections maintained by `pv-xconnect`:

1. **Providers** declare services in a `services.json` file in their container manifest.
2. **Consumers** declare requirements in their `run.json`, including service name, type, and where the resource should be injected inside the container.
3. `pv-xconnect` periodically reads the xconnect-graph from the [control socket](../reference/pantavisor-commands.md#xconnect-graph), resolves provider/consumer pairs, and injects resources into consumer namespaces.

This is entirely declarative: no code changes are needed in containers to expose or consume services.

`pv-xconnect` runs as a managed daemon spawned by Pantavisor init, in every init mode. Its three
jobs are **discovery and reconciliation** — periodically consuming the `xconnect-graph` from the
`pv-ctrl` socket and maintaining the state of active connects; **plumbing** — namespace-aware
helpers that inject virtual resources inside the consumer's namespace; and **security** — being the
single point of truth for role-based access control.

## Supported Service Types

| Type | Description |
|------|-------------|
| `unix` | Direct Unix socket proxy (supports FD passing and shared memory) |
| `rest` | HTTP-over-Unix-socket with automatic identity injection (`X-PV-Client`, `X-PV-Role` headers) |
| `dbus` | D-Bus proxy with role-based identity masquerading using provider-side `/etc/passwd` |
| `drm` | DRM/KMS device node injection for display servers |
| `wayland` | Wayland protocol mediation for isolated UI rendering |

## Security Model

Pantavisor acts as the security broker. Containers use logical service names rather than raw socket paths. Access must be explicitly declared in the [revision state JSON](revisions.md). The identity presented to the provider is resolved and injected by `pv-xconnect` from the revision's role configuration, not asserted by the consumer.

## Configuration and Control

The xconnect service mesh can be inspected at runtime through the [/xconnect-graph](../reference/pantavisor-commands.md#xconnect-graph) endpoint of the [Pantavisor control socket](local-control.md). The `pv-xconnect` daemon can be started and stopped via the [/daemons](../reference/pantavisor-commands.md#daemons) endpoint.

## Reference

- [xconnect](../reference/pantavisor-xconnect.md) — `services.json` and `run.json` manifest formats, mediation patterns, the hosted D-Bus system bus
- [xconnect Spec](https://github.com/pantavisor/pantavisor/blob/master/xconnect/XCONNECT.md) — full technical design and plugin architecture
- [Control Socket → /xconnect-graph](../reference/pantavisor-commands.md#xconnect-graph) — inspecting the graph at runtime
- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED`
