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
- **Lazy activation**: starting a name-owning app container on first demand for its well-known name. The `owns` declaration introduced here is the prerequisite "provides name" information; the remaining work is start-and-wait plumbing in pantavisor. Out of scope for the initial hosted-bus work.

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
