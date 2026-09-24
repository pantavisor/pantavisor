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

For a D-Bus consumer, `interface` is deprecated: it is still accepted but carries no runtime
meaning. Declare the well-known names the container actually talks to with `names` instead — see
[Consumer requirements: the `names` form](#consumer-requirements-the-names-form) below.

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

##### Consumer requirements: the `names` form

A consumer can declare the well-known names it needs instead of hardcoding a bus and target
socket. `bus`, the link `name`, and `target` are all derived from each name's owning export:

```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "type": "dbus",
      "role": "operator",
      "names": [
        { "name": "net.connman", "activation": { "mode": "on-owner" } },
        "org.freedesktop.Avahi"
      ]
    }
  ]
}
```

- `names` lists the well-known names reached through this requirement entry. A plain string is
  shorthand for `{"name": "...", "activation": {"mode": "none"}}`.
- Each name must resolve to an export with a matching `owns` somewhere in the state; a name nobody
  owns fails validation, and all names in one entry must resolve to the same bus.
- `target` defaults to `/run/dbus/system_bus_socket` for `system-bus`. Only one entry per bus may
  take the default; further entries must set `target` explicitly, and no two entries on the same
  container may share a target.
- `role` stays required — it is the identity the owner's `allow` list is written against, and roles
  are shared across containers by design, so it cannot be derived.

The legacy form (`name`, `type`, `role`, `target`, no `names`) keeps working unchanged; use it for a
provider-owned bus pantavisor knows nothing about.

##### Consumer activation (`on-owner`)

A `names` entry's `activation.mode` can be `"none"` (default) or `"on-owner"`. A container with at
least one `on-owner` name is authored with `status_goal: "STAGED"` (`PV_STATUS_GOAL: "STAGED"` in
`args.json`; `MOUNTED` still works but is warned as deprecated):

```json
{
  "#spec": "service-manifest-run@1",
  "name": "my-ui",
  "status_goal": "STAGED",
  "services": {
    "required": [
      { "type": "dbus", "role": "operator",
        "names": [{ "name": "net.connman", "activation": { "mode": "on-owner" } }] }
    ]
  },
  "type": "lxc"
}
```

It stays passive (volumes mounted, drivers loaded, no process) until **every** `on-owner` name in its
requirements has an owner on the bus, then pantavisor promotes it `STAGED -> STARTED` the same way it promotes
an on-demand provider — see
[D-Bus Service Activation](https://github.com/pantavisor/pantavisor/blob/master/xconnect/XCONNECT.md#d-bus-service-activation).
Names without `on-owner` do not gate startup, and `on-owner` and a provider's own `on-demand`
activation are independent of each other.

##### Role UID pinning

Roles normally get a synthetic UID from a persistent pool starting at 90000
(`/storage/config/dbus-role-uids.json`). A top-level `roles` map in a provider's `services.json`
pins a role name to a real uid instead:

```json
{
  "#spec": "service-manifest-xconnect@1",
  "services": [
    { "type": "dbus", "bus": "system-bus", "owns": "net.connman",
      "role": "connman", "allow": ["admin"] }
  ],
  "roles": {
    "admin": { "uid": 0 }
  }
}
```

- Use a pin for a legacy daemon that authorizes callers via `GetConnectionUnixUser` or polkit
  rather than the generated bus policy — without a pin it sees a pool uid (90000+), not the uid it
  expects.
- Pins are device-wide by role name: two providers pinning the same role to different uids, or to a
  uid already used by the pool, fail state validation.
- Only a provider (an export with `owns`) may pin a role; a consumer cannot promote its own
  identity.
- Pinning uid 0 is accepted but risky: `pv-xconnect`'s own ownership-monitor connection also
  authenticates as uid 0, so a uid-0 pin makes that role's policy also match the monitor's
  connection.

`GetConnectionUnixProcessID` still returns `pv-xconnect`'s pid regardless of any pin; that is not
masqueraded.

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

##### Migrating an existing D-Bus stack

Two behaviors surprise a service moved onto the hosted bus unchanged.

**Deny-by-default is stricter than a distribution's default policy.** Most distributions ship a
`<policy context="default"><allow send_destination="*"/></policy>` fallback; the hosted bus has
none. A legacy client whose role does not appear in the owner's `allow` list fails immediately:

```
$ pventer -c my-legacy-client dbus-send --system --print-reply \
    --dest=net.connman / net.connman.Manager.GetProperties
Error org.freedesktop.DBus.Error.AccessDenied: ...
```

Fix: add the role to the owner's `allow` list in its `services.json` export:

```json
{ "owns": "net.connman", "role": "connman", "allow": ["operator", "monitor", "your-role-here"] }
```

**Legacy uid-based authorization sees a synthetic pool uid.** A daemon that calls
`GetConnectionUnixUser` on its caller, or checks a polkit rule keyed on a real uid, sees a number
from pantavisor's role-uid pool (90000+) — not the uid an equivalent host process would present.
Fix: pin the role to the uid the daemon expects with a top-level `roles` map (see
[Role UID pinning](#role-uid-pinning) above):

```json
"roles": { "admin": { "uid": 0 } }
```

Caveat: `pv-xconnect`'s own ownership-monitor connection also authenticates as uid 0, so pinning a
role to uid 0 makes that role's policy also match the monitor's connection — avoid pinning uid 0 to
a role a real caller also holds if that distinction matters for your policy.

**`GetConnectionUnixProcessID` is not masqueraded.** It always returns `pv-xconnect`'s own pid, not
the calling container's init pid. There is no pin or fix for this today; a daemon that authorizes on
the caller's pid cannot be migrated onto the hosted bus as-is.

The full design lives in
[xconnect/XCONNECT.md](https://github.com/pantavisor/pantavisor/blob/master/xconnect/XCONNECT.md).

### DRM / Graphics
- **Master Role**: Injects `/dev/dri/cardX` for display servers (KMS access).
- **Render Role**: Injects `/dev/dri/renderDX` for accelerated applications.

### Wayland
Mediates the Wayland protocol for isolated UI rendering, allowing a containerized compositor to serve multiple isolated clients.

## Graph Output

[`GET /xconnect-graph`](pantavisor-commands.md#xconnect-graph) (what `pvcontrol graph ls` prints)
returns a flat JSON array mixing three kinds of elements, distinguished by which key is present.

### Link

One element per resolved consumer/provider pair:

| Field | Description |
|-------|-------------|
| `consumer` | The container name requesting the service. |
| `consumer_pid` | PID of the consumer container's init process. |
| `provider` | The container name providing the service (`_pv_` for the hosted bus). |
| `provider_pid` | PID of the provider container's init process (`0` for the hosted bus). |
| `name` | The service name as declared in `services.json`/the requirement. |
| `type` | The connection type (`unix`, `rest`, `dbus`, `drm`, `wayland`). |
| `role` | The role assigned to this link. Defaults to `"any"`. |
| `interface` | Legacy protocol identifier; defaults to `type` if unset. |
| `target` | The path where the proxy is injected in the consumer. |
| `socket` | The path to the real socket in the provider namespace. |
| `uid` | Hosted-bus links only: the role's masqueraded uid. |

```json
{ "consumer": "pv-example-unix-client", "consumer_pid": 1234,
  "provider": "pv-example-unix-server", "provider_pid": 5678,
  "name": "raw", "type": "unix", "role": "any", "interface": "unix",
  "target": "/run/pv/services/raw.sock", "socket": "/run/example/raw.sock" }
```

### Activatable

One element per hosted-bus name declared with `activation.mode: on-demand` (see
[Pantavisor-Hosted System Bus](#pantavisor-hosted-system-bus)):

| Field | Description |
|-------|-------------|
| `activatable` | The well-known name that starts its owner on first use. |
| `bus` | The bus the name lives on (`system-bus`). |
| `owner` | The container that owns the name. |
| `socket` | The host-side bus socket, so `pv-xconnect`'s ownership monitor knows where to connect. |

```json
{ "activatable": "org.example.Foo", "bus": "system-bus",
  "owner": "foo-app", "socket": "/run/pv/dbus/system_bus_socket" }
```

### Consumes

One element per resolved name in a consumer's `names` requirement (see
[Consumer requirements: the `names` form](#consumer-requirements-the-names-form)):

| Field | Description |
|-------|-------------|
| `consumes` | The well-known name this consumer depends on. |
| `bus` | The bus the name resolved to. |
| `consumer` | The container declaring the requirement. |
| `owner` | The container that owns the name. |
| `activation` | `"on-owner"` or `"none"`. |
| `socket` | The host-side bus socket. |

```json
{ "consumes": "net.connman", "bus": "system-bus", "consumer": "my-ui",
  "owner": "connman", "activation": "on-owner",
  "socket": "/run/pv/dbus/system_bus_socket" }
```

## Tools

Inspect and drive the mesh with [`pvcontrol`](../tools/pvcontrol.md#xconnect-graph) or, where a full
`curl` is unavailable, [`pvcurl`](../tools/pantavisor-tools.md#pvcurl).
