# IPAM - IP Address Management for Pantavisor

## Overview

IPAM provides automatic IP address allocation and network configuration for containers. Instead of manually configuring network settings in each container's `lxc.container.conf`, you define IP pools in `device.json` and reference them from container `run.json` files.

## Features

- **Bridge Pool Creation**: Automatically creates Linux bridge interfaces with NAT
- **IP Allocation**: Sequential IP assignment from configured subnet
- **MAC Generation**: Deterministic MAC addresses derived from allocated IPs (collision-free)
- **Hostname Configuration**: Per-container hostname support
- **Lease Management**: Tracks allocations, supports container restart with same IP

## Configuration

### device.json - Pool Definition

Define network pools in the `device.json` file:

```json
{
  "groups": [...],
  "network": {
    "pools": {
      "internal": {
        "type": "bridge",
        "bridge": "pvbr0",
        "subnet": "10.0.5.0/24",
        "gateway": "10.0.5.1",
        "nat": true
      },
      "dmz": {
        "type": "bridge",
        "bridge": "pvbr1",
        "subnet": "192.168.100.0/24",
        "gateway": "192.168.100.1",
        "nat": false
      }
    }
  }
}
```

#### Pool Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Pool type: `"bridge"` or `"macvlan"` |
| `bridge` | string | Yes (bridge) | Host bridge interface name |
| `parent` | string | Yes (macvlan) | Parent interface for macvlan |
| `subnet` | string | Yes | CIDR notation (e.g., `"10.0.5.0/24"`) |
| `gateway` | string | Yes | Gateway IP address |
| `nat` | boolean | No | Enable NAT for outbound traffic (default: false) |

### run.json - Container Network Reference

Reference a pool from the container's `run.json`:

```json
{
  "#spec": "service-manifest-run@1",
  "name": "my-container",
  "type": "lxc",
  "config": "lxc.container.conf",
  "root-volume": "root.squashfs",
  "network": {
    "pool": "internal",
    "hostname": "myhost"
  }
}
```

#### Network Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pool` | string | Yes | Pool name from device.json |
| `hostname` | string | No | Container hostname |

## How It Works

### Startup Sequence

1. **IPAM Initialization**: `pv_ipam_init()` initializes the subsystem
2. **Pool Parsing**: `device.json` is parsed, pools registered via `pv_ipam_add_pool()`
3. **Bridge Setup**: For each bridge pool, creates bridge interface with gateway IP and optionally enables NAT
4. **Container Start**: When a container starts:
   - `pv_ipam_allocate()` assigns next available IP from pool
   - MAC address generated from IP (ensures uniqueness)
   - LXC network configuration injected dynamically

### IP Allocation

IPs are allocated sequentially starting from gateway + 1:
- Gateway: 10.0.5.1
- First container: 10.0.5.2
- Second container: 10.0.5.3
- etc.

The broadcast address is reserved and skipped.

### MAC Address Generation

MAC addresses are deterministically derived from the allocated IP to ensure:
- **Uniqueness**: IPs are unique within a pool, so MACs are too
- **Stability**: Same IP always produces same MAC
- **Predictability**: Easy to correlate MACs with IPs for debugging

Format: `02:00:AA:BB:CC:DD` where `AA.BB.CC.DD` is the IP address.

Examples:
- IP `10.0.5.2` → MAC `02:00:0a:00:05:02`
- IP `10.0.5.3` → MAC `02:00:0a:00:05:03`
- IP `192.168.1.100` → MAC `02:00:c0:a8:01:64`

The `02` prefix indicates a locally administered unicast address.

### Lease Persistence

Leases are tracked in memory. If a container restarts, it receives the same IP if its lease still exists. Leases are released when the platform is freed.

## LXC Integration

When a container uses pool-based networking, IPAM dynamically configures LXC:

```
lxc.net.0.type = veth
lxc.net.0.link = pvbr0
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = 10.0.5.2/24
lxc.net.0.ipv4.gateway = 10.0.5.1
lxc.net.0.hwaddr = 02:00:0a:00:05:02
lxc.net.0.flags = up
lxc.uts.name = myhost
```

The `net` namespace is removed from `lxc.namespace.keep` so the container gets its own network namespace.

## NAT Configuration

When `nat: true` is set for a pool, IPAM configures:
1. IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
2. iptables MASQUERADE rule for the subnet

This allows containers to access external networks through the host.

## Example: Two-Container Setup

### device.json
```json
{
  "groups": [{"name": "root", "restart_policy": "container", "status_goal": "STARTED"}],
  "network": {
    "pools": {
      "internal": {
        "type": "bridge",
        "bridge": "pvbr0",
        "subnet": "10.0.5.0/24",
        "gateway": "10.0.5.1",
        "nat": true
      }
    }
  }
}
```

### server/run.json
```json
{
  "#spec": "service-manifest-run@1",
  "name": "server",
  "type": "lxc",
  "network": {
    "pool": "internal",
    "hostname": "server"
  }
}
```

### client/run.json
```json
{
  "#spec": "service-manifest-run@1",
  "name": "client",
  "type": "lxc",
  "network": {
    "pool": "internal",
    "hostname": "client"
  }
}
```

### Result
```
$ lxc-ls -f
NAME   STATE   IPV4
client RUNNING 10.0.5.3
server RUNNING 10.0.5.2

$ pventer -c client ping -c1 10.0.5.2
PING 10.0.5.2: 64 bytes, seq=0 ttl=64 time=0.063 ms
```

## API Reference

### Pool Management

```c
// Add a pool (called during device.json parsing)
struct pv_ip_pool *pv_ipam_add_pool(const char *name, pv_pool_type_t type,
                                     const char *bridge_or_parent,
                                     const char *subnet_cidr,
                                     const char *gateway, bool nat);

// Find a pool by name
struct pv_ip_pool *pv_ipam_find_pool(const char *name);
```

### IP Allocation

```c
// Allocate IP for a container (returns "IP/prefix" string)
char *pv_ipam_allocate(const char *pool_name, const char *container_name);

// Release container's IP back to pool
void pv_ipam_release(const char *pool_name, const char *container_name);

// Get existing lease
struct pv_ip_lease *pv_ipam_get_lease(const char *pool_name,
                                       const char *container_name);
```

### Utilities

```c
// Generate MAC from IP (IP in network byte order)
char *pv_ipam_generate_mac(uint32_t ip_net);

// Convert IP to string
char *pv_ipam_ip_to_str(uint32_t ip);

// Parse CIDR notation
int pv_ipam_parse_cidr(const char *cidr, uint32_t *subnet, uint32_t *mask);
```

## Troubleshooting

### Container fails to start with network error

Check that:
1. Pool is defined in `device.json`
2. Pool name in `run.json` matches exactly
3. Bridge interface was created: `ip link show pvbr0`

### Containers can't communicate

Verify:
1. Both containers are on the same pool/bridge
2. Bridge has gateway IP: `ip addr show pvbr0`
3. Containers have IPs: `lxc-ls -f`

### No external network access

If NAT is enabled but containers can't reach external hosts:
1. Check IP forwarding: `cat /proc/sys/net/ipv4/ip_forward` (should be 1)
2. Check iptables rules: `iptables -t nat -L POSTROUTING`

## Limitations

- IPv4 only (no IPv6 support yet)
- Maximum ~254 containers per /24 pool
- Bridge pools require NET_ADMIN capability
- Leases are not persisted across pantavisor restarts (containers get same IP if started in same order)
