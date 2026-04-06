# Pantavisor xconnect

The `pv-xconnect` service mesh facilitates efficient container-to-container and container-to-host interactions. It uses a plugin-driven architecture to inject resources (Unix sockets, D-Bus proxies, DRM nodes) into consumer containers on demand.

For information on how to inspect or manage the service mesh via the Pantavisor Control API, see the [Pantavisor Control Socket](../legacy/pantavisor-commands.md#xconnect-graph) reference.

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
