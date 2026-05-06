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

## Service-IP layer (k8s-Services-style)

On top of the legacy unix-socket / dbus / drm / wayland mediation, xconnect supports **named TCP services with stable virtual ClusterIPs and DNS** (`<service>.pv.local`). Provider declares `type: tcp, port: N` in `services.json`, consumer declares the service name in `args.json`, and the runtime wires up:

1. **ClusterIP** — deterministic FNV-1a hash of the service name into a configurable subnet (default `198.18.0.0/15`, RFC 2544 benchmark range; override via `pantavisor.config` key `xconnect.services.cidr` or env `PV_XCONNECT_SERVICES_CIDR`). Reboot-stable without on-disk allocator state.
2. **`pv-services` bridge** — owns each ClusterIP as a `/32`. Brought up by `pv-xconnect` on start; idempotent.
3. **Two-tier data plane**:
   - **Tier 1 (TCP→TCP, kernel forward)**: `inet pvx_services` PREROUTING rule rewrites `cluster_ip:port → backend_ip:port`. Zero-copy. Used by default for embedded throughput.
   - **Tier 2 (cross-transport)**: userspace listener on ClusterIP, proxies bytes to a unix-socket backend (or to TCP with TLS termination etc.). Same `evconnlistener` shape as `unix.c` / `rest.c`.
4. **DNS** — `<service>.pv.local` injected into the consumer's `/etc/hosts` via mount-namespace setns. Marker comment (`# pvx-services managed`) so re-injection / removal touches only managed lines.
5. **Failure semantics** — hosts injection failure (read-only fs, missing file, EPERM, setns fail) is a **hard link establishment failure**: `last_error` is set, link stays in retry queue, never silently dropped. Surfaces via `/xconnect-graph/status` (v1.1) to drive pantavisor's health/rollback path.

Manifest example (provider):
```json
{"#spec": "service-manifest-xconnect@2", "services": [{"name": "my-api", "type": "tcp", "port": 8080}]}
```

Code map: `xconnect/services.c` (hash + range parsing), `xconnect/services_bridge.{c,h}` (bridge + /32s + ip_forward), `xconnect/services_nft.{c,h}` (DNAT table), `xconnect/plugins/tcp.c` (per-link plugin with kernel-forward / userspace-proxy branch), `xconnect/plumbing.c:pvx_helper_inject_hosts_entry`. pv-ctrl side: `state.c:pv_state_get_xconnect_graph_json` emits `cluster_ip` / `provider_ip` / port / transport when `svc_type == SVC_TYPE_TCP`.

Status (v1): TCP→TCP fast path, ClusterIP, DNS, config knob, IPAM coexistence — all wired and tested. Cross-transport plugin, `/xconnect-graph/status` endpoint, and `pv_platform_start` health gate are deferred to v1.1; multi-backend policies and an explicit `services` block in `device.json` to v2.

See [meta-pantavisor `docs/overview/xconnect-services.md`](https://github.com/pantavisor/meta-pantavisor/blob/master/docs/overview/xconnect-services.md) for the integrator's view.

## Testing

For testing instructions and example containers, see the `meta-pantavisor` layer documentation:
- [EXAMPLES.md](https://github.com/pantavisor/meta-pantavisor/blob/main/EXAMPLES.md) - Example containers and testing
- [DEVELOPMENT.md](https://github.com/pantavisor/meta-pantavisor/blob/main/DEVELOPMENT.md) - Development workflow
- [TESTPLAN-pvctrl.md](https://github.com/pantavisor/meta-pantavisor/blob/main/TESTPLAN-pvctrl.md) - 31 pv-ctrl API tests
