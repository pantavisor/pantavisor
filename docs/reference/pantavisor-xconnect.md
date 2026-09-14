---
title: "xconnect"
sidebar_position: 4
description: "Service mesh manifest formats and mediation patterns."
---

# Pantavisor xconnect

**Overview:** [Inter-Container Communication](../overview/xconnect.md) explains what the service mesh
is for, how mediation works, and the security model. This page is the manifest and mediation
reference.

To inspect or manage the mesh at runtime, see
[`/xconnect-graph`](pantavisor-commands.md#xconnect-graph) and
[`/daemons`](pantavisor-commands.md#daemons).

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

| `type` | What is injected | Notes |
|--------|------------------|-------|
| `unix` | A proxied Unix domain socket | Supports FD passing (`SCM_RIGHTS`) and shared-memory handles |
| `rest` | HTTP over a Unix socket | `X-PV-Client` and `X-PV-Role` headers are injected into the first request so the provider can identify the consumer |
| `dbus` | A policy-aware system-bus proxy | Role-based identity masquerading, see below |
| `drm` | A DRM/KMS device node | |
| `wayland` | A mediated Wayland socket | |

### D-Bus identity masquerading

`pv-xconnect` intercepts the D-Bus SASL authentication phase, takes the **Role** from the link,
looks up the corresponding UID in the provider container's `/etc/passwd`, and substitutes it for
the consumer's identity. The provider's standard `dbus-daemon` then enforces its own XML policy
files against that role.

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
owns only the one bus name. Declare one `owns` per bus name the app actually
acquires, not one per interface.

A plain role string in `allow` grants that role full `send_destination` access
to *all* of the name's interfaces and object paths at once. To narrow a
caller's access, use the object form instead of a string: `{"role": ...,
"interfaces": [...], "members": [...], "paths": [...]}`. Any of the three
arrays may be omitted; an object with none of them behaves exactly like the
plain string. For example:

```json
{
  "type": "dbus",
  "bus": "system-bus",
  "owns": "org.freedesktop.Avahi",
  "role": "avahi",
  "allow": [
    { "role": "operator",
      "interfaces": ["org.freedesktop.Avahi.Server"],
      "members": ["GetVersionString"] }
  ]
}
```

generates one `<allow>` per combination of the listed interfaces and members
(the daemon matches a rule's attributes conjunctively), plus the usual
unnarrowed `receive_sender` so replies and signals still reach the caller:

```xml
<policy user="pv-dbus-operator">
  <allow send_destination="org.freedesktop.Avahi"
         send_interface="org.freedesktop.Avahi.Server"
         send_member="GetVersionString"/>
  <allow receive_sender="org.freedesktop.Avahi"/>
</policy>
```

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

##### Policy fragments

For the cases `allow`'s `interfaces`/`members`/`paths` narrowing does not
cover, an `owns` entry may ship a raw D-Bus policy fragment via `policy`: a
path relative to the owning platform's trail directory (the same directory a
platform's own `lxc.container.conf` lives in), pointing at a plain
`<busconfig>` file checked into the container alongside its other manifests:

```json
{
  "type": "dbus",
  "bus": "system-bus",
  "owns": "org.example.Foo",
  "role": "foo-service",
  "allow": ["operator"],
  "policy": "dbus/foo-policy.xml"
}
```

`dbus/foo-policy.xml` in the platform's trail directory:

```xml
<busconfig>
  <policy user="@role:operator@">
    <deny send_destination="org.example.Foo"
          send_interface="org.example.Foo.Manager"
          send_member="SetProperty"/>
  </policy>
</busconfig>
```

`@role:<name>@` is a placeholder for the role's generated bus user
(`pv-dbus-<name>`); pantavisor substitutes it and splices the fragment's
`<policy>` content into the generated `pv-generated.conf` itself, after the
generated rules — not as a separate included file, since D-Bus's "last
matching rule wins" only applies within one assembled config and a sibling
file loaded via `<includedir>` has no defined ordering relative to it. A
fragment is validated (an attribute scanner and consistency with the
declaration, then well-formedness of the whole merged config by a throwaway
`dbus-daemon`) before the state is allowed to go live — a bad fragment rolls
back the deploy like a duplicate owner does. Concretely, a fragment may only:

- use `<busconfig>`, `<policy>`, `<allow>` and `<deny>` elements — no
  `include`, `includedir`, `listen`, `type`, `auth`, `servicedir`, `limit`,
  `selinux` or `apparmor`;
- put `user="@role:<name>@"` on `<policy>`, where `<name>` already appears in
  this entry's own `allow` list — no `group`, `at_console` or `context`;
- put `send_*`, `receive_*`, `own` or `own_prefix` on `<allow>`/`<deny>` — no
  `eavesdrop`;
- name only this entry's own `owns` value in `own`, `own_prefix`,
  `send_destination` or `receive_sender` — a fragment cannot grant or touch
  another app's name.

The JSON's `allow` list is still the source of truth for *who* may reach a
name; a fragment may only narrow or detail *how*.

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

Inspect and drive the mesh with [`pvcontrol`](../tools/pvcontrol.md#xconnect-graph) or, where a full
`curl` is unavailable, [`pvcurl`](../tools/pantavisor-tools.md#pvcurl).
