# Design: pv-xconnect Ingress & Routing

This document outlines the design and implementation plan for adding TCP and HTTP Ingress capabilities to `pv-xconnect`. This enables automatic routing and filtering behind a single ingress point.

## 1. Overview

The goal is to allow a single "Ingress" container to expose ports (e.g., 80, 443, 2222) that are automatically routed to other containers based on `pv-xconnect` topology.

- **TCP Ingress**: L4 tunneling. Maps an external port on the ingress container to a provider's socket or port.
- **HTTP Ingress**: L7 routing. Maps HTTP paths (e.g., `/api`, `/app`) on a single port (80) to different provider containers.

## 2. Architecture

### 2.1 TCP Plugin (`plugins/tcp.c`)
- **Type**: `"tcp"`
- **Target**: `IP:PORT` (e.g., `0.0.0.0:2222`) inside the *Consumer* namespace.
- **Behavior**:
  - `pv-xconnect` enters Consumer namespace.
  - Binds a listening TCP socket at `target`.
  - Proxies incoming connections to the Provider's socket (Unix or TCP).

### 2.2 HTTP Plugin (`plugins/http.c`)
- **Type**: `"http"`
- **Target**: `IP:PORT/PATH` (e.g., `0.0.0.0:80/api/v1`) inside the *Consumer* namespace.
- **Behavior**:
  - **Multiplexing**: Maintains a registry of active `evhttp` servers keyed by `IP:PORT`.
  - If a server exists for `0.0.0.0:80`, it registers a new handle for `/api/v1`.
  - If no server exists, it creates a new `evhttp` server and binds it (inside Consumer namespace).
  - **Routing**: Requests matching the prefix are proxied to the Provider (stripping the prefix if configured, or keeping it).

## 3. Configuration Format

### 3.1 run.json Specification

The `run.json` manifest for the consumer (ingress) container must specify the required services. These are processed by `pv-xconnect` to establish the listeners.

```json
{
  "services": {
    "required": [
      {
        "name": "<service-name>",
        "type": "tcp",
        "target": "<bind-ip>:<bind-port>"
      },
      {
        "name": "<service-name>",
        "type": "http",
        "target": "<bind-ip>:<bind-port>/<path-prefix>"
      }
    ]
  }
}
```

| Field | Type | Description | Example |
|---|---|---|---|
| `name` | string | Name of the service to connect to (must match a provider). | `"ssh-service"` |
| `type` | string | Protocol type: `"tcp"` or `"http"`. | `"tcp"` |
| `target` | string | **TCP**: `IP:PORT` to bind in the consumer.<br>**HTTP**: `IP:PORT/PATH` to bind/route. | `"0.0.0.0:2222"`<br>`"0.0.0.0:80/api"` |
| `interface`| string | (Optional) Protocol interface. | |

### 3.2 PVR Template (`args.json`)

When using `pvr` or the `pvr-native` template system, you typically configure these requirements via `args.json`. The standard template variable `PV_SERVICES_REQUIRED` is used to inject the service array into `run.json`.

**Example `args.json`**:

```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "name": "ssh-service",
      "type": "tcp",
      "target": "0.0.0.0:2222"
    },
    {
      "name": "web-ui",
      "type": "http",
      "target": "0.0.0.0:80/"
    },
    {
      "name": "api-backend",
      "type": "http",
      "target": "0.0.0.0:80/api/v1"
    }
  ]
}
```

This configuration will tell `pv-xconnect` to:
1.  Open port **2222** (TCP) in the container and tunnel it to the provider of `ssh-service`.
2.  Open port **80** (HTTP) in the container.
3.  Route requests for **`/`** to the provider of `web-ui`.
4.  Route requests for **`/api/v1`** to the provider of `api-backend`.

## 4. Implementation Plan

### 4.1 Plumbing Changes (`plumbing.c`)

We need a helper to inject TCP sockets. This is similar to `pvx_helper_inject_unix_socket` but uses `sockaddr_in`.

```c
/* plumbing.c additions */

int pvx_helper_inject_tcp_socket(const char *addr_str, int pid);
```

### 4.2 Header Updates (`include/xconnect.h`)

```c
/* include/xconnect.h diff */

+ int pvx_helper_inject_tcp_socket(const char *addr_str, int pid);

// Add plugin declarations if we don't use dynamic loading yet
+ extern struct pvx_plugin pvx_plugin_tcp;
+ extern struct pvx_plugin pvx_plugin_http;
```

### 4.3 TCP Plugin (`plugins/tcp.c`)

```c
/* plugins/tcp.c (New File) */

static int tcp_on_link_added(struct pvx_link *link)
{
    // 1. Inject TCP listener into consumer
    int fd = pvx_helper_inject_tcp_socket(link->consumer_socket, link->consumer_pid);
    
    // 2. Create listener event
    link->listener = evconnlistener_new(..., tcp_on_accept, ...);
    return 0;
}

static void tcp_on_accept(...)
{
    // Standard proxy logic (similar to existing rest.c/unix.c)
    // Connects to link->provider_socket
}

struct pvx_plugin pvx_plugin_tcp = {
    .type = "tcp",
    .on_link_added = tcp_on_link_added,
    .on_accept = tcp_on_accept
};
```

### 4.4 HTTP Plugin (`plugins/http.c`)

This is more complex due to the shared `evhttp` server state.

```c
/* plugins/http.c (New File) */

struct http_ingress_server {
    char *listen_addr; // "0.0.0.0:80"
    struct evhttp *http;
    struct evhttp_bound_socket *handle;
    struct dl_list list; // Global list of servers
};

static void http_generic_cb(struct evhttp_request *req, void *arg)
{
    struct pvx_link *link = arg;
    // Proxy logic:
    // 1. Convert evhttp_request to raw buffer or use a client bev
    // 2. Forward to provider link->provider_socket
}

static int http_on_link_added(struct pvx_link *link)
{
    // 1. Parse target "0.0.0.0:80/path" -> host="0.0.0.0:80", path="/path"
    
    // 2. Find or Create Server
    struct http_ingress_server *srv = find_server(host);
    if (!srv) {
        srv = create_server(host);
        // Inject socket into consumer namespace
        int fd = pvx_helper_inject_tcp_socket(host, link->consumer_pid);
        srv->http = evhttp_new(pvx_get_base());
        evhttp_accept_socket(srv->http, fd);
    }

    // 3. Register Callback
    evhttp_set_cb(srv->http, path, http_generic_cb, link);
    
    return 0;
}
```

### 4.5 Integration (`main.c`)

Register the new plugins in the array.

```c
/* main.c diff */

static struct pvx_plugin *plugins[] = { 
    &pvx_plugin_unix, 
    &pvx_plugin_rest,
    &pvx_plugin_dbus, 
    &pvx_plugin_drm,
    &pvx_plugin_wayland,
+   &pvx_plugin_tcp,
+   &pvx_plugin_http,
    NULL 
};
```

## 5. Security & Roles

The HTTP plugin can inject `X-PV-Role` headers based on the `role` field in the link. This allows the backend provider to trust the header because the connection comes from the `pv-xconnect` proxy (via UDS), which is trusted.

- **Ingress**: Public facing (Port 80).
- **Proxy**: Adds `X-PV-Role: anonymous` (or specific role).
- **Provider**: Reads header to determine access.