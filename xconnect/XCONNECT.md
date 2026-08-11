# pv-xconnect: Pantavisor Cross-Connect Service

To manage container-to-container and container-to-host interactions efficiently, a dedicated process called `pv-xconnect` handles the mediation logic via on-demand plugins. It runs as a single-threaded process driven by `libevent`.

## Architecture

### Core Process Responsibilities
- **Discovery & Reconciliation**: Consumes an `xconnect-graph` from Pantavisor's `pv-ctrl` socket and maintains the state of active connects.
- **Plumbing Helpers**: Provides a "Toolbox" of namespace-aware helpers (e.g., `inject_unix_socket`, `inject_devnode`) so plugins don't have to manage low-level `setns()` logic.
- **Security**: Acts as the single point of truth for role-based access control.

### Plugin-Driven Injection
Plugins are responsible for triggering the resource injection into the container. This ensures that the specific needs of a protocol (e.g., a Wayland socket vs. a DRM device node) are handled correctly.

1.  **Reconciliation**: Core identifies a new connect and loads the required plugin.
2.  **Setup**: Core calls `plugin->on_link_added(link)`.
3.  **Injection**: The plugin calls a core helper to plant the virtual resource (socket/device) inside the consumer's namespace.
4.  **Mediation**: The plugin attaches the resulting File Descriptors to the shared `libevent` base for data processing.

### Daemon Mode

pv-xconnect runs as a daemon spawned by Pantavisor init. It is enabled for all init modes (embedded, standalone, and appengine).

## Service Manifests

### Exports (`services.json`)
A file within a container (e.g., `services.json`) that declares what services it provides. The file uses the `#spec` format for identification by pantavisor's parser.

#### Example `services.json` (Provider):
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

The `#spec` field is required — pantavisor's parser uses it to identify and process the service manifest.

### Arguments (`args.json`)
For containers that consume services, requirements are defined in `args.json` during the container creation process (e.g., with `pvr app add --arg-json args.json`). These arguments are then rendered into the final `run.json` manifest.

#### Example `args.json` (Consumer):
```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "name": "raw-unix",
      "type": "unix",
      "target": "/run/pv/services/raw-unix.sock"
    },
    {
      "name": "system-bus",
      "type": "dbus",
      "interface": "org.pantavisor.Example",
      "target": "/run/dbus/system_bus_socket"
    }
  ]
}
```

- **`interface`**: Protocol-specific identifier (e.g., D-Bus interface name).
- **`target`**: The path where `pv-xconnect` should inject the proxied resource inside the consumer container.

### Requirements (`run.json`)
A container requests access to services in its `run.json` manifest. These are rendered by `pvr` from the `args.json` templates.

#### Example Requirement in `run.json` (Consumer):
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

## Mediation Patterns

### REST
- **Mechanism**: Identity-injected HTTP over UDS.
- **Injection**: Injects `X-PV-Client` and `X-PV-Role` headers into the first request.

### D-Bus
- **Mechanism**: Role-aware proxy for the system bus.
- **Note**: This section describes the current per-provider bus model, which remains fully supported. See [Pantavisor-Hosted System Bus (Design)](#pantavisor-hosted-system-bus-design) for the planned low-friction alternative where pantavisor itself hosts a shared system bus.
- **Protocol**: Mediates D-Bus messages over Unix Domain Sockets between isolated containers.
- **Injection**: Injects a proxied D-Bus socket (e.g., `/run/dbus/system_bus_socket`) into the consumer container's namespace.
- **Role-Based Identity Masquerading**: 
  - `pv-xconnect` intercepts the D-Bus SASL authentication phase to provide identity to the provider.
  - **UID Lookup**: The proxy take the **Role** from the Pantavisor connect graph and looks up the corresponding **UID** by reading `/etc/passwd` inside the **provider** container namespace.
  - **SASL Injection**: The proxy replaces the consumer's `AUTH EXTERNAL <identity>` command with the resolved UID.
  - **Example**: If a link has role `"operator"`, and the provider's `/etc/passwd` maps `"operator"` to UID `1001`, the proxy sends `AUTH EXTERNAL 31303031` (hex for `"1001"`).
  - **Fallbacks**: 
    - If the role string is numeric, it is used directly as the UID.
    - If the role is not found in the provider's `/etc/passwd`, it defaults to UID `65534` (`nobody`).
- **Security Enforcement**:
  - This mechanism allows the provider's standard `dbus-daemon` to enforce fine-grained permissions using standard XML policy files based on the assigned role.
  - The consumer container remains completely isolated from the host bus and other containers.

#### Example Role-Based Policy (`.conf`):
```xml
<busconfig>
  <!-- Allow containers with the 'root' role (mapped to provider's 'root' user) to own the name -->
  <policy user="root">
    <allow own="org.pantavisor.Example"/>
    <allow send_destination="org.pantavisor.Example"/>
  </policy>
  
  <!-- Allow containers with the 'operator' role (mapped to provider's UID 1001) -->
  <policy user="1001">
    <allow send_destination="org.pantavisor.Example"/>
  </policy>

  <!-- Allow any other connected container (mapped to 'nobody') basic access -->
  <policy user="nobody">
    <allow send_destination="org.pantavisor.Example"/>
  </policy>
</busconfig>
```

### Raw Unix Sockets
- **Identity**: Handled via Greeting Packets, SCM_CREDENTIALS, or Role-Based Socket mapping.
- **High-Performance**: Supports FD passing (SCM_RIGHTS) and Shared Memory handles.

### DRM / Graphics
- **Master Role**: Inject `/dev/dri/cardX` for display servers (KMS access).
- **Render Role**: Inject `/dev/dri/renderDX` for accelerated apps.
- **Wayland**: Mediates the Wayland protocol for isolated UI rendering.

## Plugin Interface

### Link Structure

Each service connection is represented as a link with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Connection type: `unix`, `rest`, `dbus`, `drm`, `wayland` |
| `name` | string | Service name from services.json |
| `consumer` | string | Container name requesting the service |
| `role` | string | Access role (e.g., "client", "admin") |
| `socket` | string | Provider's socket/device path |
| `interface` | string | Consumer's target path for injection |
| `consumer_pid` | int | PID of consumer container's init process |
| `provider_pid` | int | PID of provider container's init process |

### Plugin Callbacks

```c
struct xconnect_plugin {
    const char *name;
    const char *type;
    int (*on_link_added)(struct xconnect_link *link);
    int (*on_link_removed)(struct xconnect_link *link);
};
```

### Namespace Access

Plugins access container filesystems via `/proc/{pid}/root/` paths:

- **Provider socket**: `/proc/{provider_pid}/root{socket_path}`
- **Consumer injection**: Uses `setns()` into consumer's mount namespace

## Build & Integration

- **CMake Flag**: `PANTAVISOR_XCONNECT`
- **Binary**: `pv-xconnect` is installed to `/usr/bin/`
- **Dependencies**: `libevent`, `libevent_pthreads`, `dl`

## API

### Daemons Endpoint

pv-xconnect runs as a managed daemon. Its lifecycle can be controlled via the `/daemons` API:

- `GET /daemons` — List all managed daemons with PID and respawn status
- `PUT /daemons/pv-xconnect` with `{"action":"stop"}` — Disable respawn and kill
- `PUT /daemons/pv-xconnect` with `{"action":"start"}` — Enable respawn and start

```bash
# Use pvcurl (lightweight curl wrapper using nc, preferred in appengine)
pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/daemons
pvcurl -X PUT --data '{"action":"stop"}' --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/daemons/pv-xconnect
```

### xconnect-graph Endpoint

Query the current service mesh topology:

```bash
pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/xconnect-graph
```

#### Graph Fields

| Field | Description |
|-------|-------------|
| `consumer` | The container name requesting the service. |
| `consumer_pid` | The PID of the consumer container's init process. |
| `provider` | The container name providing the service. |
| `provider_pid` | The PID of the provider container's init process. |
| `name` | The service name as defined in `services.json`. |
| `type` | The connection type (e.g., `unix`, `dbus`, `rest`). |
| `role` | The role assigned to this link. Defaults to `"any"`. |
| `interface` | Protocol identifier. Defaults to the `type` string if not set (e.g., `"unix"`). |
| `target` | The path where the proxy is injected in the consumer. |
| `socket` | The path to the real socket in the provider namespace. |

#### Roles and Permissions

Roles are used to define fine-grained access control between containers. 

- **Custom Roles**: Containers can define specific roles (e.g., `"admin"`, `"readonly"`) to restrict access to certain subsets of a service.
- **The `"any"` Role**: If no role is specified in the service requirement, Pantavisor assigns the special `"any"` role. This indicates that the link is open to any consumer that matches the service name and type, provided the provider's policy allows it.

Response Example:
```json
[{
  "type": "unix",
  "name": "raw",
  "consumer": "pv-example-unix-client",
  "role": "any",
  "socket": "/run/example/raw.sock",
  "interface": "unix",
  "target": "/run/pv/services/raw.sock",
  "consumer_pid": 1234,
  "provider_pid": 5678
}]
```

## Pantavisor-Hosted System Bus (Design)

> **Status**: design proposal — not yet implemented. The per-provider bus model described under [Mediation Patterns / D-Bus](#d-bus) remains fully supported; this adds a second, lower-friction option.

### Motivation

In the per-provider model, every container that offers a D-Bus service must run its own `dbus-daemon` next to the service binary: daemon supervision, socket bootstrap, policy XML hosting, and an `/etc/passwd` that defines the role users. That forces D-Bus providers to be full system containers while consumers stay single-pid apps.

The hosted-bus model removes all of that. Pantavisor itself runs a single shared system bus as managed infrastructure, and D-Bus providers and clients become equally cheap single-pid apps. Adopting D-Bus then requires only JSON manifest entries — no daemon, no policy XML, no passwd, no bus container.

### Topology

```
            pantavisor (initramfs / host side)
            ┌─────────────────────────────────────────────┐
            │ dbus-daemon (managed daemon, like            │
            │ pv-xconnect; build- and config-gated)        │
            │ /run/pv/dbus/system_bus_socket               │
            │ generated config: default-deny base +        │
            │ per-name policy blocks (numeric role UIDs)   │
            └────────────────▲────────────────────────────┘
                             │ per-link proxy (SASL masquerade,
                             │ UID resolved by pantavisor)
            ┌────────────────┼──────────────────┐
            ▼                ▼                  ▼
       server app       client app         client app
       single pid,      single pid,        single pid,
       owns             calls              calls
       org.example.Foo  org.example.Foo    org.example.Bar
```

- `dbus-daemon` runs as a **pantavisor-managed daemon**, using the same lifecycle infrastructure as `pv-xconnect`: spawned by init, respawned on failure, visible and controllable via the `/daemons` endpoint.
- The bus socket lives on a **host path that is never visible inside containers**. The only way to reach it is through an injected xconnect proxy, so every connection carries a masqueraded role identity by construction.
- Pantavisor registers a **builtin host export** named `system-bus` (`provider_pid = 0` in the graph). Apps attach to it with a normal service requirement, identical to consuming any dbus-type service today.
- D-Bus is peer-to-peer over the broker: once attached, a peer can own well-known names, receive method calls, emit/receive signals, and publish callback endpoints on its unique connection name. Callbacks into "client" apps ride the already-established proxied connection — no extra xconnect wiring.

### Enablement

Two independent gates, both required:

- **Build**: the feature is compiled in via the Yocto `PANTAVISOR_FEATURES` flag (which also adds `dbus` to the initramfs image).
- **Runtime**: a `pantavisor.config` entry, **defaulting to true** when built in:

```
xconnect.dbus.systembus.enabled=true
```

Setting it to `false` disables the hosted daemon and the builtin `system-bus` export entirely; behavior is then identical to a build without the feature. Like all config entries it can also be set via kernel command line (`PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED`).

### Role-per-Socket Semantics

A D-Bus identity is negotiated once per connection (SASL), so a role is bound to the **socket** the peer dials — not to interfaces, destinations, or individual messages. The proxy performs no wire introspection beyond the existing AUTH-phase handling.

- **Common case** — one role per container: a single requirement entry, injected at the standard path. Stock D-Bus applications work unmodified.

```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "name": "system-bus",
      "type": "dbus",
      "role": "operator",
      "target": "/run/dbus/system_bus_socket"
    }
  ]
}
```

- **Advanced case** — multiple identities in one container: declare multiple requirement entries for the same service `name` with distinct `role` + `target` pairs. Each target is its own injected socket, its own proxied connection, and its own masqueraded UID. The application opts into an identity by dialing the corresponding socket.

```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "name": "system-bus",
      "type": "dbus",
      "role": "operator",
      "target": "/run/dbus/system_bus_socket"
    },
    {
      "name": "system-bus",
      "type": "dbus",
      "role": "admin",
      "target": "/run/pv/dbus/admin.sock"
    }
  ]
}
```

The effective requirement tuple is `(name, role, target)`. The `interface` field is informational only and carries no runtime semantics.

### No passwd: Pantavisor-Allocated Role UIDs

D-Bus policy accepts numeric UIDs, so no user database is needed anywhere:

- Pantavisor allocates a **numeric UID per role name** from a reserved range. The mapping is persisted on storage so it stays stable across reboots and revisions.
- The xconnect graph carries the resolved `uid` on each hosted-bus link; the dbus plugin uses it directly for the SASL masquerade when `provider_pid == 0`.
- Per-provider links (`provider_pid > 0`) keep the existing role → UID lookup via the provider container's `/etc/passwd`, unchanged.

### Generated Policy

Bus policy is generated by pantavisor from manifest declarations — nobody authors D-Bus XML:

- A **name-owning app** declares its owned names and the roles allowed to call them in its `services.json` export:

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

- From all declarations in the state, pantavisor generates the daemon configuration: a **default-deny** base, `<allow own="..."/>` for the owner role's UID, and `<allow send_destination="..."/>` / `<allow receive_sender="..."/>` for each role listed in `allow`. The daemon is reloaded (`SIGHUP`) when the revision changes.
- Most callback patterns need no `own` grant at all: a peer exports an object path on its *unique* connection name and passes it in a method call; the counterpart calls back to `(unique-name, path)`. Only claiming a *well-known* name requires an `own` rule.
- Method/interface-granular policy is out of scope for generation. Stacks that need it keep using the per-provider model with hand-written XML — that is the escape hatch, not a parallel mechanism to maintain inside the generator.

### Coexistence and Collision Validation

- The per-provider model is **unchanged and remains supported**. Both models can be mixed in one stack: common services on the hosted bus, plus a private daemon container where full isolation or custom XML policy is needed.
- **Collisions fail state validation** (and therefore roll the device back on a conflicting deploy):
  - a platform `services.json` export whose `name` collides with the builtin host export (`system-bus`) while the hosted bus is enabled;
  - two apps declaring `owns` for the same well-known name on the same bus.
- Validation happens alongside the existing required-services check (`pv_state_validate_services()`), so a conflicting state never goes live.

### Implementation Notes

- **Link keying**: links are currently keyed on `(consumer, name)` in `xconnect/main.c` (`find_link()` / `reconcile_link()`). Multiple requirement entries with the same `name` but different targets would collide and tear each other down on every reconcile cycle. The key must become `(consumer, name, target)`, and the graph generation in `state.c` must emit one link per requirement entry rather than deduplicate by name.
- **Host-side provider**: the dbus plugin already branches on `provider_pid > 0` vs host-side (`dbus_on_accept()` dials the socket path directly when the pid is 0); the new work is on the state side — registering the builtin export and emitting graph entries with `provider_pid = 0` and the resolved role `uid`.
- **Daemon hardening** (follow-up): the hosted daemon can later be chrooted into a minimal directory and dropped to an unprivileged UID via the generated config's `<user>` element; the initial implementation runs it like any other managed daemon.
- **Example restructure** (meta-pantavisor): new single-pid `pv-example-dbus-host-server` (owns a name via an `owns` declaration) and `pv-example-dbus-host-client`; the existing per-provider examples stay as regression coverage for the legacy model.
- **Verification first**: the first thing the example stack must prove is the SASL `AUTH EXTERNAL` masquerade against the pantavisor-hosted daemon (claimed UID differs from the proxy's socket credentials — works against per-provider daemons today; must hold for the host daemon).

### Future Work

- **Raw policy escape hatch**: an optional field for embedding a raw XML policy snippet into the generated config, if generation granularity proves insufficient.
- **Lazy activation**: starting a name-owning app container on first demand for its well-known name. The `owns` declaration introduced by the hosted bus is the prerequisite "provides name" information. This is now specified separately — see [D-Bus Service Activation (Design)](#d-bus-service-activation-design).

## D-Bus Service Activation (Design)

> **Status**: design proposal — not yet implemented. Builds directly on [Pantavisor-Hosted System Bus](#pantavisor-hosted-system-bus-design); the `owns` declaration introduced there is the prerequisite. Scoped to the hosted system bus only.

### Motivation

The hosted bus makes D-Bus providers and clients equally cheap single-pid apps, but every declared provider still starts at boot. Service activation makes ownership **declarative enough to assemble a system from mostly passive containers**:

- containers are mounted but not initially started;
- a container starts when someone sends traffic to a D-Bus name it owns;
- a container starts only once the services it itself requires are available;
- dependency chains activate in order;
- existing always-on behavior is unchanged — activation is strictly opt-in.

This is the standard D-Bus *bus activation* contract (a message to an un-owned but activatable name triggers the owner's startup), mapped onto Pantavisor's container lifecycle instead of onto `systemd`/`exec`.

### Authoring Model

The model is a small extension of the hosted-bus manifests — no new lifecycle state.

**Provider** marks an owned name activatable in its `services.json` export:

```json
{
  "#spec": "service-manifest-xconnect@1",
  "services": [
    {
      "type": "dbus",
      "bus": "system-bus",
      "owns": "org.example.Foo",
      "role": "foo-service",
      "allow": ["operator"],
      "activation": { "mode": "on-demand" }
    }
  ]
}
```

- `activation.mode`: `"always"` (default — start at boot, current behavior) or `"on-demand"` (start on first message to `owns`).
- `activation` is only valid on a D-Bus export that has `owns`. It is rejected elsewhere at validation.

**Passivity reuses the existing lifecycle mechanism** — there is no new `PASSIVE` status goal. A container is made activatable-but-not-started with `status_goal: MOUNTED`, which already means "prepared but not started", plus the services it depends on:

```json
{
  "#spec": "service-manifest-run@1",
  "name": "foo-app",
  "status_goal": "MOUNTED",
  "services": {
    "required": [
      {
        "name": "system-bus",
        "type": "dbus",
        "bus": "system-bus",
        "role": "foo-service",
        "target": "/run/dbus/system_bus_socket"
      }
    ]
  },
  "type": "lxc"
}
```

`MOUNTED` + `activation.mode=on-demand` gives the passive-until-called behavior without inventing a parallel lifecycle state. In the runtime (`pv_state_start_platform`), a platform whose `status_goal` is `MOUNTED` has its **volumes mounted** and then stops there — drivers are not loaded and no init process is started, so there is no container namespace or pid until activation. A per-platform `status_goal: "MOUNTED"` in `run.json` is honored and overrides the group default.

Activation drives the container out of `MOUNTED` by reusing the normal start machinery, not a parallel lifecycle: the engine flips the platform's goal to `STARTED` and re-injects it into the run loop (`set_status_goal(STARTED)` + `set_installed`), after which the existing reconcile tick performs mount → driver load → start. Note this is done through the activation path itself: the generic container lifecycle API (`PUT /containers/<name>` `start`) only accepts containers already in `STOPPED`/`STOPPING`/`RECOVERING`, so it cannot start a never-started `MOUNTED` container and is not the activation mechanism.

`restart_policy: container` is **recommended** for activatable containers so that, once activated, the container stays independently stoppable/restartable via the lifecycle API (see [Container Restart Policy](../docs/overview/containers.md#restart-policy)). It is not required to *start* on demand — activation uses its own internal path and is not bound by the lifecycle API's restart-policy gate.

### Runtime Design

Activation happens **inside `pv-xconnect`**, not via `dbus-daemon`'s own bus activation. There is **no activation helper process and no generated `.service` files** — the long-lived xconnect daemon is already the man-in-the-middle on every hosted-bus connection (the bus socket is never visible inside containers), so it is the natural and cheapest place to detect first use and trigger startup. No process is exec'd per activation.

Two pieces cooperate:

- **xconnect** — detects the cold call, holds it, asks Pantavisor to start the owner, waits for the name to be owned, then releases the held call.
- **Pantavisor** — owns all the heavy logic (index, validation, dependency recursion, the `MOUNTED → STARTED` transition) behind one internal endpoint.

#### Trigger: in-proxy hold

On the hosted bus a consumer dials a single `system-bus` socket and chooses destinations at the D-Bus layer, so the *connection* does not reveal which name is wanted — only the *messages* do. Each proxied connection therefore runs a small per-session state machine:

- **WARM** (default — every non-activatable link, and any link once its target name is owned): byte-splice exactly as today, **zero message inspection**. The cost below exists only while a link is *cold*.
- **COLD** (the call targets an activatable name with no current owner): the client→provider direction is **framed** as D-Bus messages instead of spliced. Framing is cheap (the 16-byte fixed header yields body length + header-array length → message boundary). Only on a `method_call` does the proxy decode the header fields to read `DESTINATION` (field code 6). `Hello` and all other traffic splice through untouched so the client connects normally.

When a `method_call` to a cold activatable name is seen:

1. The message (and any trailing bytes) is **held** in the session buffer and the client read side is paused. Nothing is forwarded to the daemon — forwarding would only earn a `NameHasNoOwner` error.
2. xconnect calls Pantavisor:

   ```
   POST /xconnect/dbus/activate   { "bus": "system-bus", "name": "org.example.Foo" }
   ```

   If an activation for that name is already in flight (another session triggered it), the session simply **coalesces** onto the existing one rather than re-posting.
3. xconnect waits — asynchronously (see [Async Activation](#async-activation-no-mainloop-blocking)) — for the name to gain an owner.
4. On ownership, the held bytes are written to the daemon and the session reverts to **WARM**. Because the message never left its own connection, the method reply routes back to the caller naturally — no re-delivery, no cross-connection serial correlation.

A `method_call` carrying the `NO_AUTO_START` flag (`0x2`) is **not** activated: it is forwarded as-is and the daemon's normal `NameHasNoOwner` error stands, matching D-Bus semantics.

#### Owner startup: the Pantavisor endpoint

`POST /xconnect/dbus/activate` is handled entirely inside Pantavisor:

1. map `(bus, name)` to the owning platform via the activation index;
2. validate the name was declared activatable;
3. resolve the owner's required services and **recursively** activate any passive providers first;
4. wait until those dependencies are available;
5. start the owner container (`MOUNTED → STARTED`), which then claims `org.example.Foo`.

All dependency recursion and cycle handling live here. xconnect never models the dependency tree — it waits on exactly one condition: *did the requested name get an owner.*

The owner is promoted `MOUNTED → STARTED` (never `READY`): `STARTED` is enough to run the app, and the bus name — not the platform goal — is the activation handshake. Releasing the held call is therefore **independent of `status_goal`**; xconnect reads name ownership, not platform status. (Promoting to `READY` would couple activation to the container's separate pv-ctrl `ready` signal, which a name-owning app generally never sends, so its goal timer would spuriously time out even though activation succeeded.)

#### Readiness: the monitor connection

xconnect opens **one** persistent connection to the hosted daemon at startup, authenticated as itself, with a match rule for `NameOwnerChanged`. That single connection is the ownership oracle: it tells a cold session the moment its target name acquires an owner (driving step 4 above), answers "is this name already owned?" when a session first inspects a call (so an already-owned name skips activation entirely), and backs the dependency engine's hosted-bus readiness checks (`NameHasOwner`). This connection is the only place xconnect constructs/parses D-Bus method calls and signals; the per-session cold path only needs to *frame* messages and read one header field.

### Dependency Semantics

Recursive activation is a first-class part of the design — it is the useful system-assembly model:

```
client calls org.example.Foo
  Foo (passive) requires org.example.Bar
    Bar (passive, activatable) is started first
    Bar owns org.example.Bar
  Foo is started
  Foo owns org.example.Foo
client call proceeds
```

For v1, **"available"** is defined per dependency type:

- **hosted D-Bus name** — the name has an owner on the hosted bus. This is the authoritative signal, read directly off xconnect's [monitor connection](#readiness-the-monitor-connection) (`NameHasOwner` / `NameOwnerChanged`), because it matches the actual D-Bus contract rather than container status. With the monitor connection in place this is cheap and always available, so it is the primary path — not a fallback.
- **non-D-Bus xconnect service** — the provider platform has reached its configured `status_goal` (no name to observe on the bus).
- **safety net** — if a provider container started but never claimed its name, the per-wait `evtimer` (see [Async Activation](#async-activation-no-mainloop-blocking)) catches it and the dependent activation fails with a typed error.

Requirements:

- **Cycle detection**: the activation engine must detect dependency cycles between activatable services and fail clearly rather than recurse indefinitely.
- **Clear failure reporting**: every activation failure (no provider, dependency unavailable, cycle, start failure, timeout) must surface a distinct, logged reason.

### Async Activation (no mainloop blocking)

`pv-xconnect` is a single-threaded `libevent` loop, so the activation wait must **never** be a blocking call — a deep chain could otherwise stall every other link for seconds. The wait is modelled purely as event state:

- A cold session that triggers activation **disables its client read side** and holds the matched message; it does not read or block.
- Readiness arrives as an **event**: the monitor connection's `NameOwnerChanged` callback fires the waiting session(s) when the name gains an owner. Multiple sessions waiting on the same name are fired together (coalesced).
- A per-wait **`evtimer`** bounds failure, set *below* the client's own D-Bus reply timeout (libdbus default ~25s). If it fires first, xconnect synthesizes a proper `org.freedesktop.DBus.Error` reply to the client (so the call fails cleanly with a reason, and the client may retry against a now-partially-warm chain) rather than letting the connection hang or dropping it opaquely.

There is no single timer bounding the whole chain and no synchronous wait anywhere: the loop keeps servicing all other links throughout. The only end-to-end ceiling is the client's own reply timeout, which is outside our control; xconnect's `evtimer` deliberately sits under it. Recursion depth is bounded by that same client ceiling — a chain that cannot warm in time returns a typed error for that call, and the partial progress (dependencies already started) makes a retry cheaper.

### Validation Rules

Added to the existing state validation (`pv_state_validate_services()`), so a conflicting state never goes live (and a bad deploy rolls back):

- one owner per `(bus, owns)` name (already required by the hosted bus; activation reuses it);
- `activation` is only valid on a D-Bus export that declares `owns`;
- activation is limited to the hosted `system-bus` in the first implementation;
- an activatable passive container should use `restart_policy: container` (recommended, warned-not-rejected) so it stays independently controllable after activation — it is not required to start on demand;
- an activation dependency with no provider in the state fails validation clearly;
- dependency cycles between activatable services are detected and rejected.

### Scope Boundaries (v1)

- **Hosted system bus only.** Activation across arbitrary provider-owned buses needs different namespace and daemon integration and would blur the first implementation.
- **No idle shutdown / deactivation.** Starting on demand is independently useful; deciding *when to stop* a container needs its own policy model and is deferred to a separate effort. Once started, an activated container follows its normal restart policy.

### Implementation Phases

1. **Spec/docs** (this section): `activation.mode`, the passive-container pattern, the in-proxy trigger, async activation, dependency semantics, failure modes.
2. **Parser/state model**: add `activation` metadata to `pv_platform_service_export`; build an index from `(bus, owns)` to owner platform; expose the activatable-name set to xconnect (alongside the `uid` already carried on hosted-bus graph entries).
3. **Monitor connection**: in xconnect, open the single persistent connection to the hosted daemon — SASL + `Hello` + `AddMatch` for `NameOwnerChanged` — and a small D-Bus codec for that connection (build `Hello`/`AddMatch`/`NameHasOwner`, parse signals and method returns). This is the ownership oracle; no `.service` files or daemon activation config are generated.
4. **In-proxy cold/warm state machine + control endpoint**: teach the dbus plugin to frame messages and read `DESTINATION` on the cold path, hold/coalesce/release with the async `evtimer` bound and synthesized error reply; add `POST /xconnect/dbus/activate` (mirrors the existing `GET /xconnect-graph` client in `main.c`). Revert to splice once warm. Honor `NO_AUTO_START`.
5. **Dependency engine** (Pantavisor): behind the endpoint, resolve required services, recursively activate passive dependencies, wait for readiness, handle cycles/timeout/failure. Perform the `MOUNTED → STARTED` transition by flipping the platform goal and re-injecting it into the reconcile loop (`set_status_goal(STARTED)` + `set_installed`); the existing `pv_state_run` then drives mount → drivers → start. Verify `pv_volume_mount` is idempotent on already-mounted volumes (the start path re-runs it). Note the per-service dependency activation here is genuinely new — the existing prev-group goal ordering (`pv_state_check_goal_prev_group`) sequences *groups*, not on-demand per-service dependencies.
6. **Tests**: passive service not started at boot; client call activates it transparently; chained activation starts the dependency first; activation fails with a typed D-Bus error when a dependency is unavailable; duplicate owned names rejected; `NO_AUTO_START` is not activated; always-on behavior unchanged.

## Tools

### pvcurl

A lightweight shell script wrapping `nc` for HTTP-over-Unix-socket communication. Preferred over `curl` in appengine environments where standard curl is not available.

Supports: `-X` (method), `-T` (timeout), `-v` (verbose), `-o` (output file), `-w` (response code), `--data`, `--unix-socket`.

```bash
# Query API
pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/xconnect-graph

# PUT with data
pvcurl -X PUT --data '{"action":"stop"}' --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/daemons/pv-xconnect
```

### pvcontrol

A CLI wrapper around pvcurl for common pv-ctrl operations.

## Testing

For testing instructions and example containers, see the `meta-pantavisor` layer documentation:
- [EXAMPLES.md](https://github.com/pantavisor/meta-pantavisor/blob/main/EXAMPLES.md) - Example containers and testing
- [DEVELOPMENT.md](https://github.com/pantavisor/meta-pantavisor/blob/main/DEVELOPMENT.md) - Development workflow
- [TESTPLAN-pvctrl.md](https://github.com/pantavisor/meta-pantavisor/blob/main/TESTPLAN-pvctrl.md) - 31 pv-ctrl API tests
