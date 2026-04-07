# Pantavisor State Format (state.json)

A Pantavisor revision is defined by a single JSON object called `state.json`. It acts as a **virtual filesystem manifest** where every key represents a relative file path within the revision, and every value is either a nested configuration object or a SHA256 identifier for a binary artifact.

## 1. Root Level (`state.json`)

These keys represent the files at the root of a revision.

| Key | Value Type | Mandatory | Description |
|:---|:---|:---:|:---|
| `#spec` | string | Yes | Parser version. Must be `"pantavisor-service-system@1"`. |
| `README.md` | string | No | Documentation for the revision in Markdown format. |
| `bsp/run.json` | [BSP Manifest](#2-bsp-runjson) | Yes | Board Support Package configuration. |
| `bsp/drivers.json` | [Drivers Manifest](#3-bsp-driversjson) | No | Abstract driver mapping for the kernel. |
| `device.json` | [Infrastructure Manifest](#4-devicejson) | No | Unified physical storage and logical group definition. |
| `groups.json` | [Groups Manifest](#5-groupsjson) | No | (Legacy) Logical container orchestration groups. |
| `disks.json` | [Disks Manifest](#6-disksjson) | No | (Legacy) Physical storage medium definitions. |
| `<container>/run.json` | [Container Manifest](#7-containerrunjson) | Yes | Individual container configuration. |
| `<container>/services.json` | [Service Exports](#8-containerservicesjson) | No | Services exported to the xconnect mesh. |
| `_sigs/<container>.json` | [Signature Manifest](#9-_sigscontainerjson) | No | Security signature for container artifacts. |
| `_config/<container>/<path>` | string | No | Injects data into `<path>` inside the container's rootfs. |
| `<any/other/path>` | string | No | SHA256 identifier for a binary artifact at that path. |

---

## 2. BSP (`bsp/run.json`)

Defines the core system boot assets.

| Key | Value Type | Description |
|:---|:---|:---|
| `linux` | path string | Path to the Linux kernel image. |
| `initrd` | path string | Path to the Pantavisor initrd binary. |
| `modules` | path string | Path to the modules squashfs image. |
| `firmware` | path string | Path to the firmware squashfs image. |
| `fdt` | path string | Path to the Flattened Device Tree binary. |
| `fit` | path string | Path to a FIT image (replaces linux/initrd/fdt). |
| `rpiab` | path string | Path to a Raspberry Pi boot image. |
| `addons` | array of paths | List of CPIO addons to merge into the initrd rootfs. |
| `initrd_config` | path string | Custom configuration for the initrd process. |

---

## 3. Drivers (`bsp/drivers.json`)

Maps abstract driver names to kernel modules based on hardware.

| Key | Value Type | Description |
|:---|:---|:---|
| `#spec` | string | Must be `"driver-aliases@1"`. |
| `all` | object | Default module mappings for all hardware. |
| `dtb:<name>` | object | Module mappings specific to a Device Tree model. |
| `ovl:<name>` | object | Module mappings specific to a DT Overlay. |

**Example module list:**
```json
"wifi": [ "cfg80211", "brcmfmac ${user-meta:wifi.opts}" ]
```

---

## 4. Infrastructure (`device.json`)

The unified hardware and orchestration manifest.

| Key | Value Type | Description |
|:---|:---|:---|
| `disks` | array | List of [Disk Definitions](#6-disksjson). |
| `groups` | array | List of [Orchestration Groups](#5-groupsjson). |
| `volumes` | object | List of [Persistent Volumes](#storage-object) for Pantavisor itself. |

---

## 5. Orchestration (`groups.json`)

Defines how containers are grouped and started.

| Key | Value Type | Default | Description |
|:---|:---|:---:|:---|
| `name` | string | **Mandatory** | Unique logical name for the group. |
| `description` | string | empty | Human-readable description. |
| `status_goal` | enum | `STARTED` | Goal for all members: `MOUNTED`, `STARTED`, `READY`. |
| `restart_policy` | enum | `container` | Policy on failure: `system`, `container`. |
| `timeout` | integer | 30 | Seconds to wait for members to reach `status_goal`. |
| `auto_recovery` | object | none | Default [auto-recovery](#auto-recovery-object) for containers in this group. Inherited all-or-nothing by containers without their own `auto_recovery`. |

---

## 6. Storage (`disks.json`)

Defines physical storage mediums.

| Key | Value Type | Default | Description |
|:---|:---|:---:|:---|
| `name` | string | **Mandatory** | Unique name used in `run.json` storage keys. |
| `type` | enum | **Mandatory** | `directory`, `dm-crypt-versatile`, `swap-disk`, `volume-disk`. |
| `path` | string | **Mandatory** | Path to block device or image file. |
| `format` | enum | `ext4` | Filesystem format (`ext3`, `ext4`, `swap`). |
| `provision` | string | empty | Provisioning source (e.g., `zram`). |
| `mount_target` | path | empty | Where to mount the disk on the host. |
| `mount_options` | string | empty | Comma-separated mount flags. |
| `format_options` | string | empty | Arguments for the `mkfs` command. |
| `default` | string | `"no"` | If `"yes"`, this disk is used for all volumes without a `disk` key. |

---

## 7. Container (`<container>/run.json`)

Configures an individual container runtime.

| Key | Value Type | Mandatory | Description |
|:---|:---|:---:|:---|
| `#spec` | string | Yes | Must be `"service-manifest-run@1"`. |
| `name` | string | Yes | Logical name of the container. |
| `type` | enum | Yes | Runtime type (currently only `lxc`). |
| `config` | path string | Yes | Path to the LXC configuration file. |
| `root-volume` | path string | Yes | Path to the rootfs squashfs artifact. |
| `volumes` | array | No | Additional artifacts to mount as volumes. |
| `group` | string | No | Orchestration group name (from `device.json`). |
| `status_goal` | enum | No | Target state: `MOUNTED`, `STARTED`, `READY`. |
| `restart_policy` | enum | No | `system` (reboot on crash) or `container` (restart LXC). |
| `roles` | array | No | Capability roles: `mgmt` (control API access) or `nobody`. |
| `storage` | object | Yes | [Persistence settings](#storage-object) for rootfs paths. |
| `drivers` | object | No | Requirements: `required`, `optional`, or `manual`. |
| `services` | object | No | [Service mesh requirements](#service-requirements). |
| `logs` | array | No | [Logger configurations](#loggers-array). |
| `exports` | array | No | (Boolean flag in code) Marks container as an exporter. |
| `auto_recovery` | object | No | [Auto-recovery configuration](#auto-recovery-object). If absent, inherited from group. |

### Auto-Recovery Object

Configures automatic restart behavior when a container crashes. See [Auto-Recovery overview](../overview/containers.md#auto-recovery) for the broader context.

| Key | Value Type | Default | Description |
|:---|:---|:---:|:---|
| `policy` | enum | `no` | Recovery policy: `no`, `always`, `on-failure`, `unless-stopped`. Note: the current implementation does not distinguish exit codes — `on-failure` behaves the same as `always`. |
| `max_retries` | integer | 0 | Maximum restart attempts. 0 = unlimited. |
| `retry_delay` | integer | 0 | Initial delay in seconds before first restart. |
| `backoff_factor` | number | 1.0 | Multiplier applied to `retry_delay` on each subsequent retry. |
| `reset_window` | integer | 0 | Seconds of continuous uptime after which the retry counter resets to 0. |
| `stable_timeout` | integer | 0 | Seconds the container must survive after reaching its status goal to be considered stable. Used to gate [TESTING](../overview/updates.md#testing) commit. |
| `backoff_policy` | string | `reboot` | Action after `max_retries` exhausted in steady state: `reboot`, `never`, or a duration string (`10min`, `1h`, `30s`). |

### Storage Object
Defines persistence for specific directories. Keys are paths relative to container root.
*   **`persistence`**: `permanent` (survives updates), `revision` (survives reboots), `boot` (volatile).
*   **`disk`**: Logical disk name from `device.json`.

### Service Requirements
Under the `services` key in `run.json`.
*   **`required` / `optional`**: Arrays of service requirement objects.
    *   `name`: Logical name of the service to find.
    *   `type`: Protocol (`rest`, `dbus`, `unix`, `drm`, `wayland`).
    *   `target`: Path where Pantavisor should inject the socket/resource.
    *   `role`: Masquerade as this role when connecting.
    *   `interface`: Protocol-specific identifier.

---

## 8. Service mesh (`<container>/services.json`)

Declares services this container provides to others.

| Key | Value Type | Description |
|:---|:---|:---|
| `#spec` | string | Must be `"service-manifest-xconnect@1"`. |
| `services` | array | List of service objects (`name`, `type`, `socket`). |

---

## 9. Security (`_sigs/<container>.json`)

JWS-based artifact verification.

| Key | Value | Description |
|:---|:---|:---|
| `#spec` | `"pvs@2"` | Parser version. |
| `protected` | base64 string | Encoded headers including `alg`, `typ`, and `pvs` path filters. |
| `signature` | base64 string | The cryptographic signature of the protected header and payload. |
| `x5c` | array | (In protected) Certificate chain for verification. |
| `jwk` | object | (In protected) JSON Web Key for verification. |
