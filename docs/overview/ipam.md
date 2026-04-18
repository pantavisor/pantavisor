---
nav_order: 9.5
---
# IPAM — Container IP Address Management

Pantavisor includes an IP Address Management (IPAM) subsystem that assigns networking resources to [containers](containers.md) at start time. Containers declare a named **pool** in their manifest; pantavisor allocates an IP from that pool, sets up the backing bridge, and wires the interface into the container's network namespace.

## Why IPAM?

Without IPAM, each container's networking had to be hand-configured in its `lxc.container.conf` — bridge name, IP, MAC, gateway, namespace handling, all baked per-revision. That is painful for multi-container setups, fragile across BSPs, and leaks implementation details into application images.

IPAM replaces this with a declarative model:

- The device declares **pools** (subnet + bridge + optional NAT) centrally in `device.json`.
- Each container just says "attach me to pool *internal*" in its `run.json` — by name.
- Pantavisor handles IP allocation, MAC derivation, bridge creation, NAT, and — in a follow-up — cross-pool isolation.

The allocation is keyed by `(pool, container_name)` and persisted in-memory, so a container keeps its IP across stop/start cycles and auto-recovery restarts.

## How It Works

Setup runs once at pantavisor init, per revision:

1. The parser reads `network.pools` from `device.json` and registers each pool in the IPAM registry.
2. `pv_ipam_setup_bridges()` walks the registry, creates each bridge with the configured gateway IP, and — if the pool has `nat: true` — installs a MASQUERADE rule via nftables (iptables fallback).
3. For every container that declares `PV_NETWORK_POOL`, the platform parser stores the pool name on `struct pv_platform_network_iface`. No network work happens yet.

Per-container setup runs at `pv_platform_start`:

1. A backend-plugin hook (see [Pre-start validation](#pre-start-validation)) gets a chance to reject the container if its baked config conflicts with IPAM.
2. The IPAM allocator looks up the pool, picks the next free IP (or reserves a requested static one), and records the lease.
3. A deterministic MAC is derived from the IP (`02:00:<IP_OCTETS>`), unless a static MAC was provided.
4. The LXC plugin reads the assigned IP/MAC/bridge off the platform's network interfaces and injects `lxc.net.0.*` into the LXC config at start time. `'net'` is stripped from `lxc.namespace.keep` so the container gets its own netns.

## Pools

A pool is a named L3 segment with a bridge and optional NAT:

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
      }
    }
  }
}
```

The `nat` flag is independent per pool — you can have one pool that reaches the external network through a MASQUERADE rule, and another that is only routable on its own bridge.

Today only `type: "bridge"` is wired up end-to-end. A `macvlan` type is sketched in the schema for future work.

See [Pantavisor IPAM reference](../reference/pantavisor-ipam.md) for the full schema.

## Per-Container Configuration

A container opts into a pool from its `run.json` (typically generated via `args.json` / `PV_NETWORK_POOL`):

```json
{
  "network": {
    "mode": "pool",
    "pool": "internal",
    "hostname": "my-container"
  }
}
```

Static IP and MAC overrides are available under `interfaces[]` — see the reference for exact field names.

## Pre-start validation

A container that opts into an IPAM pool **must not** bake `lxc.net.*` entries into its `lxc.container.conf`. Pantavisor owns the container's network namespace when IPAM is in use and injects its own `lxc.net.0.*` at start time; silently overwriting a user-baked entry would leak orphan attributes (e.g. `lxc.net.0.macvlan.mode` from the previous type), and silently ignores the user's stated intent.

The refusal is enforced through a plugin hook on the container backend (LXC today). If the backend plugin detects a conflict, it returns non-zero, `pv_platform_start` returns `-1`, and the error bubbles up through `pv_state_run` → `_pv_run` into `PV_STATE_ROLLBACK` (in a TESTING update) or `PV_STATE_REBOOT` (steady state) — the same path as an unknown pool reference.

`lxc.namespace.keep = net` (present in pvr's default template) is not treated as a conflict; pantavisor strips `net` from the keep list at runtime when it injects the veth.

Short version: **if a container declares a pool, don't hand-roll `lxc.net.*` in its image. If it hand-rolls `lxc.net.*`, don't declare a pool.**

## Lifecycle

- **Stop / start via the container-control API**: the lease is preserved. The container comes back with the same IP.
- **Auto-recovery restart** (both immediate and delayed): also preserves the IP by reusing the existing lease in `pv_ipam_allocate`.
- **Platform teardown** (state transition / reboot / rollback): releases the lease. The new revision's allocation starts clean.
- **Unknown pool reference**: the container is refused at start time; the revision is torn down and rolled back in TESTING.

## Isolation (follow-up)

Today the kernel's default `FORWARD` policy is `ACCEPT`, so containers in different pools can reach each other at L3. That is a gap, tracked as a separate effort that defaults all pools to isolated and expects cross-pool service access to go through the [xconnect service mesh](xconnect.md) rather than flat routing.
