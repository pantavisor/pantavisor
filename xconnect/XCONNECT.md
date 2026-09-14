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

## Name-Based D-Bus Requirements, Consumer Activation and Policy (Design)

This section extends the hosted system bus and D-Bus service activation with
four related pieces:

1. consumers declare the **well-known names** they use, not just the bus socket;
2. a consumer can stay passive until a name it needs **has an owner**;
3. a role can be **pinned to a real uid** for legacy authorization;
4. providers can **refine the generated bus policy**, declaratively or with a
   validated policy fragment.

Everything here builds on what already exists: `owns`/`allow` exports, the
role-per-socket rule, the generated default-deny policy, `status_goal: MOUNTED`
as the passive state, and the ownership monitor in `pv-xconnect`. No new
lifecycle state and no new daemon.

### Motivation

Today a consumer's requirement says only *who I am when I dial this socket*
(`role`). It does not say *what I am going to talk to*. The `interface` field
exists but carries no runtime meaning. That leaves four gaps:

- **No dependency graph.** `pvcontrol graph ls` links a consumer to
  `system-bus`, not to the service it actually uses.
- **No validation.** A consumer whose role is missing from the provider's
  `allow`, or that needs a name nobody owns, deploys fine and fails at runtime.
- **No consumer-side activation.** Pantavisor cannot start a container "when
  service X is available" because nothing tells it which X.
- **No way to express legacy policy.** The generated policy covers owner and
  callers per name; it cannot express per-interface restrictions or real uids
  that legacy daemons check.

### Settled Decisions

These were agreed and are not open for re-discussion in the implementation:

- **One target socket carries exactly one role.** D-Bus negotiates identity
  once per connection, so a socket is an identity. Several names may be reached
  through one socket; a different role needs a different socket.
- **Names are the unit of dependency.** Bus and socket are derived from the
  name's owner; the author does not have to write them.
- **The JSON declaration is the source of truth** for who talks to whom. Policy
  fragments may only narrow or detail *how*, never widen *who*.
- **Role uids stay synthetic by default.** Pinning a role to a real uid is
  explicit, per role, and validated for conflicts.
- **The legacy socket form keeps working unchanged.** Nothing existing has to
  move.

### Authoring Model

#### Provider export (unchanged shape, extended `allow` and new `roles`)

```json
{
  "#spec": "service-manifest-xconnect@1",
  "services": [
    {
      "type": "dbus",
      "bus": "system-bus",
      "owns": "net.connman",
      "role": "connman",
      "allow": [
        "monitor",
        { "role": "operator",
          "interfaces": ["net.connman.Manager"],
          "members": ["GetProperties", "GetServices"] }
      ],
      "activation": { "mode": "on-demand" },
      "policy": "dbus/connman-policy.xml"
    }
  ],
  "roles": {
    "admin": { "uid": 0 }
  }
}
```

- `allow` entries are either a role string (full send/receive access to the
  name, as today) or an object that narrows that role. Optional keys
  `interfaces`, `members`, `paths` map one-to-one onto the daemon's
  `send_interface`, `send_member`, `send_path` attributes. An object with none
  of them is the same as the string form.
- `policy` (optional) names a policy fragment shipped in the container's trail
  directory. See [Policy Fragments](#policy-fragments).
- `roles` (optional, top level) pins role names to real uids. See
  [Role UID Pinning](#role-uid-pinning).

#### Consumer requirement (new `names`, derived bus and socket)

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

- `names` lists the well-known names reached through this entry. A string is
  shorthand for `{ "name": "...", "activation": { "mode": "none" } }`.
- `bus` is derived: every name must resolve to an export with `owns` in the
  state, and all names in one entry must resolve to the same bus. Today that is
  always `system-bus`.
- `name` (the link name) is derived from the bus and may be omitted.
- `target` is derived per bus. For `system-bus` it defaults to
  `/run/dbus/system_bus_socket`, the path stock clients dial. Only one entry per
  bus may take the default; further entries must set `target` explicitly and no
  two entries may share a path.
- `role` stays required. It is the identity `allow` lists are written against
  and roles are shared across containers by design, so it cannot be derived.
- `interface` is deprecated in favour of `names`. It is still accepted and
  still means nothing.

The legacy form (`name`, `type`, `role`, `target`, no `names`) is untouched and
is the right form for a provider-owned bus that pantavisor knows nothing about.

#### Multiple identities in one container

One entry per role, one socket per entry:

```json
"PV_SERVICES_REQUIRED": [
  { "type": "dbus", "role": "operator", "names": ["org.freedesktop.Avahi"] },
  { "type": "dbus", "role": "admin", "names": ["net.connman"],
    "target": "/run/pv/dbus/admin.sock" }
]
```

Processes opt into the second identity by dialing that socket, typically via
`DBUS_SYSTEM_BUS_ADDRESS`.

### Consumer Activation (`on-owner`)

A consumer with at least one name marked `activation.mode: on-owner` is
authored with `status_goal: MOUNTED`, exactly like an on-demand provider. It
stays passive (volumes mounted, no process) until **every** `on-owner` name in
its requirements has an owner on the bus. Names without `on-owner` do not gate
startup.

This is the mirror image of provider activation and shares its machinery:

- The ownership monitor in `pv-xconnect` already watches `NameOwnerChanged`.
  It gains a second waiter kind: instead of "release a held call when this name
  is owned", it is "tell pantavisor to start this container when all of its
  names are owned".
- At start and after a monitor reconnect the waiters are seeded from
  `ListNames`, so a name owned before `pv-xconnect` came up still fires.
- The promotion path is the existing one: `POST /xconnect/dbus/activate` with
  `{"container": "<name>"}` performs `MOUNTED -> STARTED` through
  `set_status_goal` + `set_installed`. The endpoint accepts either `name` (a
  bus name, today's provider activation) or `container`.
- There is no held call, no timer and no synthesized error. The only failure
  mode is "the name never appears", and the correct behaviour is to keep
  waiting.

Interactions, all intended:

- **Passive consumer waiting on a passive provider**: nothing starts until an
  always-on container makes the first call. That is the low-power outcome the
  feature exists for, not a deadlock. Document it, do not "fix" it.
- **Owner goes away later**: the consumer is not stopped. Deactivation remains
  out of scope, as for providers.
- **Group ordering**: a `MOUNTED` consumer satisfies its group's goal
  immediately, so it never delays later groups.
- **`on-owner` and `on-demand` are independent.** A consumer wakes when the
  name appears, however it came to be owned.

### Role UID Pinning

Role uids are allocated from a persistent pool starting at 90000
(`/storage/config/dbus-role-uids.json`). That is invisible to well-behaved
software, because identity is decided at the connection by the proxy. It breaks
legacy daemons that authorize on the caller's uid (`GetConnectionUnixUser`,
polkit): they see 90001 where they expect 0.

The `roles` map in a provider export pins a role to a real uid:

```json
"roles": { "admin": { "uid": 0 } }
```

- A pinned role is handed that uid by `pv_dbus_daemon_role_uid()` instead of one
  from the pool. Nothing else in the masquerade or policy path changes.
- Pins are device-wide by role name. Two containers pinning the same role to
  different uids, or pinning a role to a uid already used by the pool, fail
  validation.
- Only providers may pin, since the provider is the thing doing the check. A
  consumer cannot promote its own identity.
- The pool stays the default so nobody presents root on the bus by accident.

Note that `GetConnectionUnixProcessID` still returns `pv-xconnect`'s pid. That
is not addressed here.

### Policy Generation

The generated policy stays deny-by-default and per role. The `allow` object
form adds narrowing on the same `<allow>` line:

```xml
<policy user="pv-role-operator">
  <allow send_destination="net.connman"
         send_interface="net.connman.Manager"
         send_member="GetProperties"/>
  <allow send_destination="net.connman"
         send_interface="net.connman.Manager"
         send_member="GetServices"/>
  <allow receive_sender="net.connman"/>
</policy>
```

One line per member (or per path, per interface) because the daemon matches
attributes on a single rule conjunctively. `receive_sender` is never narrowed;
replies and signals from the service must always reach an allowed caller.

Deny-by-default is stricter than what distributions ship, where
`context="default"` allows sending to nearly everything. A legacy client that
was never listed anywhere fails until its role appears in an `allow`. This is
intended and belongs in the migration notes.

### Policy Fragments

For the cases the declarative vocabulary does not cover, a provider may ship a
raw fragment for its own names, referenced by `policy` in its export. The
fragment is a plain `<busconfig>` with `<policy>` elements, using
`@role:<name>@` placeholders wherever a user is meant:

```xml
<busconfig>
  <policy user="@role:operator@">
    <deny send_destination="net.connman"
          send_interface="net.connman.Manager"
          send_member="SetProperty"/>
  </policy>
</busconfig>
```

Pantavisor substitutes placeholders with the generated user names and appends
the result to the policy directory after the generated rules.

#### Validation

Fragments are validated at state validation time, so a bad one rolls back the
deploy like a duplicate owner does. Three levels:

1. **Well-formedness, by the daemon itself.** The candidate policy directory
   (generated rules plus all fragments) is assembled in a temporary location
   with a temporary `busconfig` that listens on a throwaway socket and uses the
   same generated passwd as the real daemon. `dbus-daemon --config-file=<tmp>
   --nofork --print-address` is run with a short timeout. Printing an address
   means the configuration parsed; the instance is then killed. A non-zero exit
   fails validation and its stderr is the diagnostic. This catches unknown
   elements and attributes with line numbers.
2. **Our rules, by a small attribute scanner.** Because step 1 guarantees the
   grammar, this only walks `policy`, `allow` and `deny` attributes:
   - `policy` may carry only `user="@role:<name>@"` where the role is declared
     in the state. No `group`, `at_console` or `context`.
   - `allow`/`deny` may carry only `send_*`, `receive_*`, `own` and
     `own_prefix`. `eavesdrop` is rejected.
   - `own`, `own_prefix`, `send_destination` and `receive_sender` must name one
     of this container's own `owns`. A fragment cannot grant or touch someone
     else's name.
   - Any element other than `busconfig`, `policy`, `allow`, `deny` is rejected
     (`include`, `includedir`, `listen`, `type`, `auth`, `servicedir`, `limit`,
     `selinux`, `apparmor`).
3. **Consistency with the declaration.** A role granted access in a fragment
   must appear in the export's `allow`. The JSON says *who*; the fragment may
   only narrow or detail *how*.

Unknown users are a warning in the daemon, not an error, so step 2 must reject
any placeholder that does not resolve before the daemon ever sees it.

#### Reload

When a state goes live the policy is reloaded through
`org.freedesktop.DBus.ReloadConfig` on the ownership-monitor connection, not
SIGHUP. The method returns an error if the new configuration fails to parse;
that error fails the state transition. The throwaway instance is the pre-flight
check, the reload result is the confirmation, and there is no window in which a
broken policy is silently ignored.

### Validation Rules (summary)

Added to `pv_state_validate_services()`:

- every entry in `names` resolves to exactly one export with `owns` in the
  state; a name nobody owns fails;
- the entry's `role` is present in that export's `allow` (string or object
  form);
- all names in one entry resolve to the same bus;
- at most one entry per bus takes the default `target`; explicit targets are
  unique per container;
- a container with any `on-owner` name has `status_goal: MOUNTED` (warned, not
  rejected, matching the `restart_policy` recommendation for providers);
- role pins are consistent device-wide and do not collide with the pool;
- policy fragments pass the three validation levels above.

### Graph Exposure

`GET /xconnect-graph` gains, per resolved name, a descriptor alongside links
and activatable entries:

```json
{ "consumes": "net.connman", "bus": "system-bus",
  "consumer": "my-ui", "owner": "connman", "activation": "on-owner" }
```

This is what `pvcontrol graph ls` shows and what the consumer-activation
waiters in `pv-xconnect` are built from.

### Scope Boundaries

- Hosted `system-bus` only, as for provider activation.
- No deactivation when an owner disappears.
- No `eavesdrop`, no group or console based policy.
- `GetConnectionUnixProcessID` is not masqueraded.

### Implementation Plan

Each phase is one PR-sized unit and leaves the tree working. Phases 1 to 3 are
independent of 4 and 5 and can be built in parallel.

1. **Names in the state model** (pantavisor: `parser/parser_system1.c`,
   `platforms.h`, `state.c`).
   Parse `names` (string and object forms) into `pv_platform_service`; keep
   `interface` parsed but unused. Resolve each name to its owner export at
   validation, derive `bus`, link `name` and default `target`; apply the
   validation rules above. Emit the `consumes` descriptors in the graph.
   Existing goldens for `local/xconnect/*` must not change.
   Acceptance: a consumer with `names` and no `target` gets the default
   socket; a name nobody owns fails validation; two default targets in one
   container fail validation.

2. **pvr template and meta examples** (pvr `templates/builtin-lxc-docker.go`;
   meta `recipes-containers/pv-examples`, `recipes-containers/pantavisor`).
   Render `names` from `PV_SERVICES_REQUIRED` outside the `MOUNTED` gate (see
   the `status_goal` pitfall in `container-pvrexport.bbclass`). Move
   `pv-avahi-browse` and `pv-example-system-dbus-client` to the `names` form.
   Acceptance: rebuilt containers carry `names` in `run.json`; `local/xconnect`
   suite still green.

3. **Consumer activation** (pantavisor: `xconnect/dbus_activation.c`,
   `xconnect/main.c`, `ctrl/ctrl_xconnect_activate_ep.c`, `dbus_daemon.c`).
   Add the container waiter kind fed from `consumes` descriptors with
   `on-owner`; seed from `ListNames`; fire when all names are owned; extend the
   activate endpoint with `container`; reuse `pv_dbus_daemon_activate`'s
   promotion. New pvtest `local/xconnect/dbus-consumer-activation`: passive
   consumer, always-on provider, consumer reaches `STARTED` only after the
   provider owns its name; plus the passive-on-passive case stays idle.

4. **Policy vocabulary and role pins** (pantavisor: `parser_system1.c`,
   `dbus_daemon.c`).
   Parse `allow` objects and the `roles` map. Generate narrowed `<allow>` lines.
   Honour pins in `pv_dbus_daemon_role_uid()` with the conflict checks.
   pvtests: a narrowed role can call the listed member and is denied another;
   a pinned role shows the pinned uid via `GetConnectionUnixUser`.

5. **Policy fragments** (pantavisor: `dbus_daemon.c`, new
   `dbus_policy_check.c`, `xconnect/dbus_activation.c` for `ReloadConfig`).
   Copy fragments from the trail, substitute placeholders, run the throwaway
   `dbus-daemon` pre-flight, run the attribute scanner and the consistency
   check, switch live reload to `ReloadConfig` and fail the transition on
   error. pvtests: a fragment that narrows a member is enforced; a fragment
   with `include`, with a foreign `own`, or with an unknown role placeholder
   fails validation and rolls back.

6. **Docs and migration notes** (pantavisor `docs/`, meta `docs/`).
   Update the manifest reference, `pvcontrol graph ls` output, and write the
   migration note about deny-by-default versus distribution policies and the
   uid-checking legacy daemons.

Facts an implementer should not have to rediscover:

- Roles are a device-wide vocabulary by string equality; the map lives in
  `/storage/config/dbus-role-uids.json` and is append-only.
- `pv_dbus_daemon_role_uid()` is the single choke point for role to uid; pins
  belong there.
- The generated passwd is what makes `policy user=` resolvable; the throwaway
  validator instance must see the same one.
- `pvr app add --status-goal MOUNTED` drops `type`/`config` and skips the LXC
  render; set `status_goal` via `PVR_APP_POST_FIXUP` instead.
- Test tarballs come from `PV_PVTEST_CONTAINERS_XCONNECT` in
  `pantavisor-appengine-distro.bb`; a new example container must be added
  there to reach the tester.
- Test usrmeta is applied after the initial revision boots, so tests must not
  rely on it to keep a container idle at boot.


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
