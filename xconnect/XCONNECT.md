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
A file within a container (e.g., `services.json`) that declares what services it provides.

#### Example `services.json` (Provider):
```json
[
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
```

### Arguments (`args.json`)
For containers that consume services, requirements are defined in `args.json` during the container creation process (e.g., with `pvr app add --arg-json args.json`). These arguments are then rendered into the final `run.json` manifest.

#### Example `args.json` (Consumer):
```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "name": "network-manager",
      "target": "/run/nm/api.sock"
    }
  ],
  "PV_SERVICES_OPTIONAL": [
    {
      "name": "system-bus",
      "interface": "org.freedesktop.NetworkManager"
    }
  ]
}
```

### Requirements (`run.json`)
A container requests access to services in its `run.json` manifest.

#### Example Requirement in `run.json` (Consumer):
```json
{
  "#spec": "service-manifest-run@1",
  "name": "my-app",
  "services": {
    "required": [
      {
        "name": "network-manager",
        "role": "admin",
        "target": "/run/nm/api.sock"
      }
    ],
    "optional": [
      {
        "name": "system-bus",
        "interface": "org.freedesktop.NetworkManager"
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
- **Mechanism**: Policy-aware proxy for the system/session bus.
- **Filtering**: Access is restricted to specific D-Bus Names and Interfaces declared in `run.json`.

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

### xconnect-graph Endpoint

Query the current service mesh topology:

```bash
curl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/xconnect-graph
```

Response:
```json
[{
  "type": "unix",
  "name": "raw",
  "consumer": "pv-example-unix-client",
  "role": "client",
  "socket": "/run/example/raw.sock",
  "interface": "/run/pv/services/raw.sock",
  "consumer_pid": 1234,
  "provider_pid": 5678
}]
```

## Testing

For testing instructions and example containers, see the `meta-pantavisor` layer documentation:
- [EXAMPLES.md](https://github.com/pantavisor/meta-pantavisor/blob/main/EXAMPLES.md) - Example containers and testing
- [DEVELOPMENT.md](https://github.com/pantavisor/meta-pantavisor/blob/main/DEVELOPMENT.md) - Development workflow
