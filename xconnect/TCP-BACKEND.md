# TCP Backend Connection Support for Ingress

This document describes the implementation required to support TCP backend connections for Pattern 2b (Isolated Hybrid Proxy) ingress.

## Problem Statement

Currently, the TCP ingress plugin can bind a listening socket on the host (or in a consumer namespace), but it cannot proxy connections to TCP backends in IPAM containers. The current implementation only supports Unix socket backends.

### Current Flow (Working)

```
External Request → 0.0.0.0:80 (pv-xconnect listener) → ??? (backend)
```

### Current Limitation

In `xconnect/plugins/tcp.c:123-127`:
```c
// Connect to provider (currently assuming Unix socket provider)
struct sockaddr_un sun;
memset(&sun, 0, sizeof(sun));
sun.sun_family = AF_UNIX;
strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);
```

For IPAM containers with TCP services:
- Container has IP 10.0.4.2 (from IPAM pool)
- Nginx listens on port 80 inside container's network namespace
- Backend address should be `10.0.4.2:80`
- But `link->provider_socket` is empty because parser doesn't construct it

## Solution Overview

Three components need changes:

1. **Parser**: Extract `"port"` from services.json and store it
2. **xconnect-graph builder**: Construct `<ip>:<port>` socket address for TCP services
3. **TCP plugin**: Support TCP backend connections (not just Unix sockets)

## Implementation

### Phase 1: Parser Changes (`parser/parser_system1.c`)

**1.1 Add port field to service export structure** (`platforms.h`):

```c
struct pv_platform_service_export {
    service_type_t svc_type;
    char *name;
    char *socket;
    int port;           // NEW: TCP port number (0 if not specified)
    struct dl_list list;
};
```

**1.2 Update `pv_platform_add_service_export()`** to accept port parameter.

**1.3 Update `parse_service_exports()`** (~line 730):

```c
char *sock = pv_json_get_value(svc_s, "socket", sv, svc_c);
char *port_s = pv_json_get_value(svc_s, "port", sv, svc_c);  // NEW
int port = port_s ? atoi(port_s) : 0;                        // NEW

pv_platform_add_service_export(p, service_str_to_type(t_s), n, sock, port);

if (port_s)
    free(port_s);
```

### Phase 2: xconnect-graph Builder (`state.c`)

**2.1 Construct socket address for TCP services with port**

In `pv_state_get_xconnect_graph_json()` around line 2090, when serializing the `"socket"` field for ingress entries:

```c
// For TCP services with port, construct IP:port from IPAM address
char socket_buf[64] = "";
if (exp->svc_type == SVC_TYPE_TCP && exp->port > 0 && !exp->socket) {
    // Get container's IPAM IP address
    const char *ip = pv_platform_get_ipv4_address(pp);
    if (ip) {
        // ip is in CIDR format (e.g., "10.0.4.2/24"), extract just the IP
        char *slash = strchr(ip, '/');
        int ip_len = slash ? (slash - ip) : strlen(ip);
        snprintf(socket_buf, sizeof(socket_buf), "%.*s:%d", ip_len, ip, exp->port);
    }
}
pv_json_ser_key(&js, "socket");
pv_json_ser_string(&js, socket_buf[0] ? socket_buf : (exp->socket ? exp->socket : ""));
```

**2.2 Add helper function** to get platform's IPAM IP:

```c
// In platforms.c or ipam.c
const char *pv_platform_get_ipv4_address(struct pv_platform *p)
{
    if (!p || !p->network)
        return NULL;

    struct pv_platform_network_iface *iface;
    dl_list_for_each(iface, &p->network->interfaces,
                     struct pv_platform_network_iface, list) {
        if (iface->ipv4_address)
            return iface->ipv4_address;
    }
    return NULL;
}
```

### Phase 3: TCP Plugin (`xconnect/plugins/tcp.c`)

**3.1 Detect TCP vs Unix socket backend**

Update `tcp_on_accept()` to handle both TCP and Unix socket backends:

```c
static void tcp_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
                          struct sockaddr *address, int socklen, void *arg)
{
    struct pvx_link *link = arg;
    struct event_base *base = pvx_get_base();

    if (!link->name || !link->provider_socket) {
        close(fd);
        return;
    }

    // Determine if provider_socket is TCP (IP:port) or Unix socket (path)
    bool is_tcp_backend = (strchr(link->provider_socket, ':') != NULL &&
                           link->provider_socket[0] != '/');

    struct tcp_proxy_session *session = calloc(1, sizeof(*session));
    if (!session) {
        close(fd);
        return;
    }

    session->link = link;
    session->be_client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    session->be_provider = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    int connect_result;
    if (is_tcp_backend) {
        connect_result = tcp_connect_to_tcp_backend(session, link->provider_socket);
    } else {
        connect_result = tcp_connect_to_unix_backend(session, link);
    }

    if (connect_result < 0) {
        bufferevent_free(session->be_client);
        bufferevent_free(session->be_provider);
        free(session);
        return;
    }

    bufferevent_setcb(session->be_client, tcp_read_cb, NULL, proxy_event_cb, session);
    bufferevent_setcb(session->be_provider, tcp_read_cb, NULL, proxy_event_cb, session);
    bufferevent_enable(session->be_client, EV_READ | EV_WRITE);
    bufferevent_enable(session->be_provider, EV_READ | EV_WRITE);
}
```

**3.2 Add TCP backend connection function**:

```c
static int tcp_connect_to_tcp_backend(struct tcp_proxy_session *session,
                                      const char *addr_str)
{
    char host[256];
    int port;

    // Parse "IP:port" format
    const char *colon = strchr(addr_str, ':');
    if (!colon)
        return -1;

    size_t host_len = colon - addr_str;
    if (host_len >= sizeof(host))
        return -1;

    strncpy(host, addr_str, host_len);
    host[host_len] = '\0';
    port = atoi(colon + 1);

    if (port <= 0 || port > 65535)
        return -1;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &sin.sin_addr) <= 0)
        return -1;

    printf("%s: Connecting to TCP backend %s:%d\n", MODULE_NAME, host, port);

    return bufferevent_socket_connect(session->be_provider,
                                      (struct sockaddr *)&sin, sizeof(sin));
}
```

**3.3 Refactor Unix socket connection** (existing code):

```c
static int tcp_connect_to_unix_backend(struct tcp_proxy_session *session,
                                       struct pvx_link *link)
{
    char provider_path[256];

    if (link->provider_pid > 0) {
        snprintf(provider_path, sizeof(provider_path),
                 "/proc/%d/root%s", link->provider_pid, link->provider_socket);
    } else {
        strncpy(provider_path, link->provider_socket, sizeof(provider_path) - 1);
        provider_path[sizeof(provider_path) - 1] = '\0';
    }

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

    printf("%s: Connecting to Unix backend %s\n", MODULE_NAME, provider_path);

    return bufferevent_socket_connect(session->be_provider,
                                      (struct sockaddr *)&sun, sizeof(sun));
}
```

## Testing

After implementation, Test 11 should pass:

```bash
# Verify xconnect-graph shows constructed socket address
docker exec pva-test sh -c 'echo -e "GET /xconnect-graph HTTP/1.0\r\n\r\n" | nc -U /run/pantavisor/pv/pv-ctrl' | tail -1 | jq '.[] | select(.name=="nginx-http") | .socket'
# Expected: "10.0.4.2:80"

# Verify end-to-end HTTP via ingress
docker exec pva-test wget -q -O - http://127.0.0.1:80/ | head -5
# Expected: <!DOCTYPE html> ... Welcome to nginx!
```

## Files Changed

| File | Change |
|------|--------|
| `platforms.h` | Add `port` field to `pv_platform_service_export` |
| `platforms.c` | Update `pv_platform_add_service_export()`, add `pv_platform_get_ipv4_address()` |
| `parser/parser_system1.c` | Parse `"port"` field from services.json |
| `state.c` | Construct `IP:port` socket address for TCP services |
| `xconnect/plugins/tcp.c` | Support TCP backend connections |

## Alternative Approaches Considered

### A. Namespace injection approach
Instead of connecting to the container's IP from the host network, pv-xconnect could enter the container's network namespace and connect to `localhost:port`. This would work but adds complexity and requires namespace management in the proxy path.

### B. iptables/nftables DNAT
Use iptables rules to DNAT traffic to the container IP. This works for simple cases but doesn't provide the visibility and control that pv-xconnect offers (logging, access control, service mesh features).

The chosen approach (TCP backend connection) is simplest and maintains pv-xconnect's role as the service mesh proxy.
