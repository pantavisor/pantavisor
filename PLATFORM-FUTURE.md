# Platform Future: Deferred Features

This document tracks future enhancements not yet scheduled for implementation.
For current features, see [PLATFORM.md](PLATFORM.md).

---

## 1. Advanced Networking

### 1.1 Multi-Interface Containers

Allow containers to connect to multiple pools simultaneously.

**Use case:** Management plane + data plane separation

```json
{
    "name": "gateway",
    "network": {
        "interfaces": [
            {"name": "eth0", "pool": "management", "default_route": true},
            {"name": "eth1", "pool": "data"}
        ]
    }
}
```

**Status:** Deferred. Initial implementation supports single interface only.

### 1.2 IPv6 Support

Dual-stack pools with IPv6 addressing.

```json
{
    "network": {
        "pools": {
            "internal": {
                "subnet": "10.0.3.0/24",
                "subnet6": "fd00:pv::0/64",
                "gateway6": "fd00:pv::1"
            }
        }
    }
}
```

**Status:** Deferred. IPv4-only for initial implementation.

### 1.3 DHCP Server

Run lightweight DHCP server on bridges for containers that expect DHCP.

**Use case:** Full system containers that run their own DHCP client.

**Status:** Deferred. Static assignment only for initial implementation. Containers receive IP via LXC config injection; no DHCP needed.

### 1.4 CNI Backend

Optional CNI plugin support for Kubernetes-adjacent deployments.

```json
{
    "network": {
        "backend": "cni",
        "cni_path": "/opt/cni/bin",
        "pools": { ... }
    }
}
```

**Status:** Deferred. Native netns implementation first; CNI as optional backend later.

### 1.5 Macvlan/IPvlan Pools

Direct attachment to physical network without bridge overhead.

```json
{
    "network": {
        "pools": {
            "direct-lan": {
                "type": "macvlan",
                "parent": "eth0",
                "mode": "bridge"
            }
        }
    }
}
```

**Status:** Deferred. Bridge pools first.

---

## 2. Advanced Recovery

### 2.1 Failure Escalation

Escalate container failure to system reboot after recovery exhaustion.

```json
{
    "auto_recovery": {
        "type": "on-failure",
        "maximum_retry_count": 5,
        "escalate_to": "reboot"
    }
}
```

**Status:** Deferred. Current behavior: container enters FAILED state.

### 2.2 Health Checks

Proactive health checking with custom commands or HTTP endpoints.

```json
{
    "health_check": {
        "type": "http",
        "endpoint": "http://localhost:8080/health",
        "interval": 30,
        "timeout": 5,
        "retries": 3
    }
}
```

**Status:** Not planned. Consider for future.

---

## 3. Service Mesh Extensions

### 3.1 TCP Proxy Plugin

Extend pv-xconnect with TCP proxying for legacy network applications.

**Modes:**
- Unix-to-TCP: Consumer uses UDS, proxied to provider TCP port
- TCP-to-TCP: Port mapping within network namespace

**Status:** See [xconnect/XCONNECT-FUTURE.md](xconnect/XCONNECT-FUTURE.md)

### 3.2 Container DNS

DNS server for container name resolution.

```bash
# Inside container:
ping webserver.pv.local  # Resolves to 10.0.3.5
```

**Status:** Deferred. Use API resolution for now.

### 3.3 HTTP Ingress

Layer 7 routing for multi-container HTTP services.

**Status:** See [xconnect/XCONNECT-FUTURE.md](xconnect/XCONNECT-FUTURE.md)

---

## 4. Alternative Runtimes

### 4.1 Runc Network Support

OCI container networking via config.json modification or pre-created netns.

**Status:** Deferred. pv_runc is PoC; focus on pv_lxc first.

### 4.2 Wasmedge Networking

WASI sockets support for WebAssembly workloads.

**Status:** Deferred. pv_wasmedge is PoC.

---

## 5. Roadmap

| Feature | Priority | Dependencies |
|---------|----------|--------------|
| Multi-interface | Medium | IPAM core |
| IPv6 | Low | IPAM core |
| CNI backend | Low | IPAM core |
| DHCP server | Low | Bridge setup |
| Failure escalation | Medium | Auto-recovery |
| Health checks | Low | - |
| TCP proxy | Medium | xconnect |
| Container DNS | Medium | IPAM core |
| Runc networking | Low | IPAM core |
