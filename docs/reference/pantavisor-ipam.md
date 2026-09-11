---
title: "IPAM"
sidebar_position: 7
description: "IP address management configuration: pools, leases, and per-container networks."
---

# Pantavisor IPAM

**Overview:** [IPAM](../overview/ipam.md) explains why pools exist, how allocation works, and how IPAM
coexists with backend-native static IPs.

Reference for the IP Address Management (IPAM) subsystem: `device.json` pool schema, per-container `run.json` / `args.json` schema, lifecycle behaviors, and backend-plugin hook.

For the narrative overview, see [Technical Overview — IPAM](../overview/ipam.md).

## `device.json` — Pools

Pools are declared under `network.pools`, keyed by pool name:

```json
{
  "network": {
    "pools": {
      "internal": {
        "type": "bridge",
        "bridge": "pvbr0",
        "subnet": "10.0.5.0/24",
        "gateway": "10.0.5.1",
        "nat": true
      },
      "lab": {
        "type": "bridge",
        "bridge": "pvbr1",
        "subnet": "10.0.6.0/24",
        "gateway": "10.0.6.1",
        "nat": false
      }
    }
  }
}
```

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | Pool backend. `"bridge"` is the supported value today; `"macvlan"` is reserved for future use. |
| `bridge` | string | for `type=bridge` | Host-side bridge interface name. Pantavisor creates it if missing and assigns `gateway` to it. |
| `parent` | string | for `type=macvlan` | Parent netdev for macvlan. |
| `subnet` | string | yes | CIDR, e.g. `"10.0.5.0/24"`. |
| `gateway` | string | yes | Host-side bridge IP, within the subnet. Served as the gateway for containers on this pool. |
| `nat` | bool | no (default `false`) | When `true`, installs a MASQUERADE rule so containers in this pool can reach the external network through the host. When `false`, the pool is bridge-local only. |

Pools are validated at parse time and registered in the in-memory IPAM registry; setup runs during `pv_ipam_setup_bridges()` in pantavisor init.

## `run.json` — Per-Container Network

A container declares how it attaches to IPAM under a top-level `network` block:

```json
{
  "network": {
    "mode": "pool",
    "pool": "internal",
    "hostname": "my-container"
  }
}
```

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `mode` | string | yes | Networking mode. `"pool"` opts the container into IPAM-managed networking. `"host"` uses the host netns. `"none"` leaves pantavisor out of the network setup entirely. |
| `pool` | string | for `mode=pool` | Name of a pool declared in `device.json`. If the pool does not exist at start time the container is refused. |
| `hostname` | string | no | Value assigned to `lxc.uts.name`; sets the container's hostname. |
| `interfaces` | array | no | Per-interface overrides (static IP, static MAC). See below. |

### `interfaces[]` overrides

When the defaults (eth0, auto-allocated IP, derived MAC) are not enough:

| Field | Type | Description |
|---|---|---|
| `name` | string | Container-side interface name. Default `"eth0"`. |
| `pool` | string | Pool name for this interface. Default: top-level `pool`. |
| `ipv4_address` | string | Static IP (CIDR or bare address). Reserved in the pool; start fails if the IP is outside the subnet or already in use. |
| `mac_address` | string | Static MAC. Default is deterministic `02:00:<ip_octets>`. |

## `args.json` — PVR Template Variables

When building a container image via `pvr` / Yocto, these arguments are templated into the generated `run.json`:

| Arg | Target run.json field |
|---|---|
| `PV_NETWORK_POOL` | `network.pool` (also sets `network.mode = "pool"`) |
| `PV_NETWORK_HOSTNAME` | `network.hostname` |
| `PV_NETWORK_IP` | `network.interfaces[0].ipv4_address` |
| `PV_NETWORK_MAC` | `network.interfaces[0].mac_address` |

## Lease Lifecycle

Leases are keyed by `(pool_name, container_name)` and held in each pool's in-memory `leases` list.

| Event | Lease behavior |
|---|---|
| First start of a pool-using container | New lease allocated from `next_ip`, or reserved to a static IP. Deterministic MAC derived if none provided. |
| `pvcontrol containers stop` / `start` | Lease preserved. The start path's `pv_ipam_allocate` finds the existing lease and reuses it. |
| Auto-recovery restart (immediate and delayed) | Same — lease is reused. |
| Platform teardown (state transition, reboot, rollback) | Lease released in `pv_platform_free`. |
| IPAM alloc failure mid-start (e.g. static IP collision) | Any partial leases for the platform are released in the `ipam_error` rollback path. |

## Backend plugin hooks

Two optional symbols are `dlsym`'d on the container-backend plugin. A backend that does not provide
them simply contributes nothing.

| Symbol | Called from | Effect |
|--------|-------------|--------|
| `pv_validate_container_config(p, conf_file)` | `pv_platform_start`, before IPAM allocation | Non-zero refuses the start. The LXC plugin uses it to reject a pool-using container whose `lxc.container.conf` bakes `lxc.net.*` entries. `lxc.namespace.keep = net` is not flagged |
| `pv_enumerate_static_ips(p, conf_file, cb, ctx)` | `pv_platforms_reserve_static_ips`, once at startup after `pv_ipam_setup_bridges` | Invokes `cb(ip_in_host_order, ctx)` per hard-coded address found. The LXC plugin greps `lxc.net.N.ipv4.address = X.Y.Z.W[/M]`, ignoring the `auto` and `dhcp` sentinels |

Each enumerated address is routed into `pv_ipam_reserve_static(ip, source)`:

| Address | Disposition |
|---------|-------------|
| Inside a pool's subnet | Leased to that pool, tagged `pv:static:<source>`, so `is_ip_available()` skips it |
| Outside every pool's subnet | Logged at DEBUG, ignored |
| Equal to a pool's gateway | Logged at WARN, not reserved |
| Already leased | Skipped |

## NAT backend

NAT is installed per pool with `nat: true`, using the first available backend:

| Order | Condition | Rule installed |
|-------|-----------|----------------|
| 1 | `nft` is on `PATH` | `table ip nat`, `postrouting` chain at `srcnat` priority, one `ip saddr <subnet> oifname != "<bridge>" masquerade` rule per pool |
| 2 | `iptables` is on `PATH` | `iptables -t nat -A POSTROUTING -s <subnet> ! -o <bridge> -j MASQUERADE` |
| 3 | neither | WARN logged; the pool runs without NAT |

Bridge creation itself uses netlink.

## Error Handling

| Condition | Behavior |
|---|---|
| `pool` field references an undefined pool | Refuse at `pv_platform_start`: `refusing to start, triggering rollback if in try-boot`. Bubbles up to rollback/reboot. |
| Baked `lxc.net.*` in a pool-using container | Refuse via the LXC plugin's `validate_config` hook. Bubbles up to rollback/reboot. |
| Static IP outside pool subnet | Refuse at `pv_platform_start`. Bubbles up. |
| Static IP already in use | Refuse at `pv_platform_start`. Bubbles up. |
| Pool exhausted (no free IPs) | Refuse at `pv_platform_start`. Bubbles up. |
| NAT setup fails | Logged as WARN; the pool is still usable for same-pool traffic. |
