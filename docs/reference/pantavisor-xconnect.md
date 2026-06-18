---
title: "xconnect"
sidebar_position: 6
description: "Service mesh manifest formats and mediation patterns."
---

# Pantavisor xconnect

The `pv-xconnect` service mesh facilitates efficient container-to-container and container-to-host interactions. It uses a plugin-driven architecture to inject resources (Unix sockets, D-Bus proxies, DRM nodes) into consumer containers on demand.

For information on how to inspect or manage the service mesh via the Pantavisor Control API, see the [Pantavisor Control Socket](pantavisor-commands.md#xconnect-graph) reference.

## Architecture

To manage interactions between containers, a dedicated process called `pv-xconnect` handles the mediation logic via on-demand plugins. It runs as a managed daemon spawned by Pantavisor init and is enabled for all init modes (embedded, standalone, and appengine).

### Core Responsibilities
- **Discovery & Reconciliation**: Periodically consumes an `xconnect-graph` from Pantavisor's `pv-ctrl` socket and maintains the state of active connects.
- **Plumbing**: Provides namespace-aware helpers to inject virtual resources (sockets/device nodes) inside the consumer's namespace.
- **Security**: Acts as the single point of truth for role-based access control.

## Service Manifests

### Provider (`services.json`)
A container declares the services it provides in a `services.json` file. This file must use the `#spec` format for identification by Pantavisor's parser.

#### Example `services.json`:
```json
{
  "#spec": "service-manifest-xconnect@1",
  "services": [
    {
      "name": "network-manager",
      "type": "rest",
      "socket": "/run/network-manager/api.sock"
    },
    {
      "name": "system-bus",
      "type": "dbus",
      "socket": "/run/dbus/system_bus_socket"
    }
  ]
}
```

### Consumer (`args.json` / `run.json`)
Containers that consume services define their requirements in `args.json` during creation (e.g., with `pvr app add --arg-json args.json`). These are then rendered into the final `run.json` manifest.

#### Example `run.json` requirement:
```json
{
  "#spec": "service-manifest-run@1",
  "name": "my-app",
  "services": {
    "required": [
      {
        "name": "system-bus",
        "type": "dbus",
        "interface": "org.pantavisor.Example",
        "target": "/run/dbus/system_bus_socket"
      }
    ]
  },
  "type": "lxc"
}
```

- **`interface`**: Protocol-specific identifier (e.g., D-Bus interface name).
- **`target`**: The path where `pv-xconnect` should inject the proxied resource inside the consumer container.

## Mediation Patterns

### Raw Unix Sockets
Provides direct proxying of Unix Domain Sockets between containers. It supports high-performance features like FD passing (SCM_RIGHTS) and Shared Memory handles.

### REST
Identity-injected HTTP over UDS. `pv-xconnect` automatically injects `X-PV-Client` and `X-PV-Role` headers into the first request, allowing the provider to identify the consumer.

### D-Bus
Policy-aware proxy for the system bus. It performs **Role-Based Identity Masquerading**:
1. `pv-xconnect` intercepts the D-Bus SASL authentication phase.
2. It takes the **Role** from the link and looks up the corresponding **UID** in the provider container's `/etc/passwd`.
3. It replaces the consumer's identity with the resolved UID.

This allows the provider's standard `dbus-daemon` to enforce fine-grained permissions using standard XML policy files based on the assigned role.

#### Pantavisor-Hosted System Bus

As a lower-friction alternative to the per-provider model above, pantavisor can
host a **single shared system bus** itself, so both D-Bus providers and
consumers become equally cheap single-pid containers — no `dbus-daemon`, policy
XML, `/etc/passwd` or bus container to ship.

It is gated by two independent switches: the `xconnect-dbus-systembus` build
feature and the `xconnect.dbus.systembus.enabled` configuration key (default
`1`). When enabled, pantavisor runs the bus as a managed daemon and registers a
builtin `system-bus` export.

A **name-owning app** declares the well-known name it owns, its owner role and
the caller roles allowed to reach it, in its `services.json`:

```json
{
  "#spec": "service-manifest-xconnect@1",
  "services": [
    {
      "type": "dbus",
      "bus": "system-bus",
      "owns": "org.example.Foo",
      "role": "foo-service",
      "allow": ["operator", "monitor"]
    }
  ]
}
```

Both owners and callers attach to the bus with a normal `system-bus`
requirement entry (under their role), e.g.:

```json
{ "name": "system-bus", "type": "dbus", "role": "operator",
  "target": "/run/dbus/system_bus_socket" }
```

Here `name` is always `system-bus` (it selects the builtin hosted-bus export,
not the app's own name), `role` is the identity this connection authenticates
as, and `target` is the path the bus socket is injected at inside the container.
The requirement carries **no** name/interface of its own — the names an app
*owns* are declared only in `services.json`.

Pantavisor allocates a stable numeric UID per role, generates a default-deny
bus policy from the `owns`/`allow` declarations (no XML authoring), and the
proxy masquerades each connection to its role UID. States that shadow the
builtin `system-bus` export or double-own a well-known name are rejected at
validation.

##### Roles

Roles are **free-form strings you choose** — there is no fixed set and nothing
to pre-register. The first time a role name appears (in an `owns` entry's
`role`, in an `allow` list, or in a requirement's `role`) pantavisor assigns it
the next free UID and persists the mapping, so the same role keeps the same UID
across reboots and revisions. To introduce a new role you simply use its name;
to authorise it against a name you add it to that name's `allow` list.

##### Names vs. interfaces

`owns` is a D-Bus **well-known bus name** (a connection-owned destination such
as `org.freedesktop.Avahi`), **not** a D-Bus interface. A single owned name
typically exposes many interfaces on many object paths — for example
`org.freedesktop.Avahi` serves `org.freedesktop.Avahi.Server`,
`.ServiceBrowser`, `.ServiceResolver`, `.EntryGroup` and more — but the daemon
owns only the one bus name. The generated policy authorises by **destination**
(`send_destination`), so owning a name covers *all* of its interfaces and object
paths at once; there is no per-interface or per-method granularity. Declare one
`owns` per bus name the app actually acquires, not one per interface.

##### Multiple names and roles

A single app may own several distinct well-known names. Each name is a separate
object in the `services` array with its **own** owner `role` and its **own**
`allow` list, so different names can expose different permission sets:

```json
{
  "#spec": "service-manifest-xconnect@1",
  "services": [
    {
      "type": "dbus",
      "bus": "system-bus",
      "owns": "org.example.Telemetry",
      "role": "telemetry-service",
      "allow": ["operator", "monitor"]
    },
    {
      "type": "dbus",
      "bus": "system-bus",
      "owns": "org.example.Provisioning",
      "role": "provisioning-service",
      "allow": ["operator"]
    }
  ]
}
```

Each `owns` entry produces an independent default-deny policy block. A name has
exactly one owner `role`; the same name cannot be owned twice (across the whole
state), but its `allow` list may name as many caller roles as needed.

##### Multi-identity consumers

A container that must reach the bus as more than one identity (for example, to
talk to `foo-service` as `operator` *and* to `foo-admin` as itself) declares
several requirement entries, each with a distinct `role` **and** a distinct
`target` so the injected sockets do not collide:

```json
{
  "PV_SERVICES_REQUIRED": [
    { "name": "system-bus", "type": "dbus", "role": "operator",
      "target": "/run/dbus/system_bus_socket" },
    { "name": "system-bus", "type": "dbus", "role": "foo-admin",
      "target": "/run/dbus/admin_bus_socket" }
  ]
}
```

Each entry yields its own socket masqueraded to that role's UID; the app picks
which one to dial per connection.

The full design lives in
[xconnect/XCONNECT.md](https://github.com/pantavisor/pantavisor/blob/master/xconnect/XCONNECT.md).

### DRM / Graphics
- **Master Role**: Injects `/dev/dri/cardX` for display servers (KMS access).
- **Render Role**: Injects `/dev/dri/renderDX` for accelerated applications.

### Wayland
Mediates the Wayland protocol for isolated UI rendering, allowing a containerized compositor to serve multiple isolated clients.

## Tools

### pvcurl
A lightweight shell script wrapping `nc` for HTTP-over-Unix-socket communication. It is preferred in App Engine environments where standard `curl` might not be available.

### pvcontrol
A high-level CLI wrapper around `pvcurl` for common Pantavisor control operations.
