---
title: "State Format"
sidebar_position: 1
description: "state.json schema (v2): root keys and all manifest definitions."
---

# Pantavisor State Format (state.json)

**Overview:** [Revisions](../overview/revisions.md) explains what a revision is and how state.json
represents it. [Disks](../overview/disks.md) and [Containers](../overview/containers.md) explain the
subsystems the `device.json` and `run.json` manifests configure.

A Pantavisor revision is defined by a single JSON object called `state.json`. It acts as a **virtual filesystem manifest** where every key represents a relative file path within the revision, and every value is either a nested configuration object or a SHA256 identifier for a binary artifact.

## 1. Root Level (`state.json`)

These keys represent the files at the root of a revision.

| Key | Value Type | Mandatory | Description |
|:---|:---|:---:|:---|
| `#spec` | string | Yes | Parser version. Must be `"pantavisor-service-system@1"`. |
| `README.md` | string | No | Documentation for the revision in Markdown format. |
| `bsp/run.json` | [BSP Manifest](#2-bsp-bsprunjson) | Yes | Board Support Package configuration. |
| `bsp/drivers.json` | [Drivers Manifest](#3-drivers-bspdriversjson) | No | Abstract driver mapping for the kernel. |
| `device.json` | [Infrastructure Manifest](#4-infrastructure-devicejson) | No | Unified physical storage and logical group definition. |
| `groups.json` | [Groups Manifest](#5-orchestration-groupsjson) | No | (Legacy) Logical container orchestration groups. |
| `disks.json` | [Disks Manifest](#6-storage-disksjson) | No | (Legacy) Physical storage medium definitions. |
| `<container>/run.json` | [Container Manifest](#7-container-containerrunjson) | Yes | Individual container configuration. |
| `<container>/services.json` | [Service Exports](#8-service-mesh-containerservicesjson) | No | Services exported to the xconnect mesh. |
| `_sigs/<container>.json` | [Signature Manifest](#9-security-_sigscontainerjson) | No | Security signature for container artifacts. |
| `_config/<container>/<path>` | string | No | Injects data into `<path>` inside the container's rootfs. |
| `<PV_OEM_NAME>/<PV_POLICY>.config` | string | No | [OEM configuration](../overview/pantavisor-configuration-levels.md#oem) file with `key=value` overrides, loaded on revision startup. |
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
| `disks` | array | List of [Disk Definitions](#6-storage-disksjson). Strict parsing — unknown types are fatal. |
| `disks_v2` | array | Same schema as `disks`, additive. Parsed independently. |
| `disks_v3` | array | Same schema as `disks` with lenient parsing (unknown types are warned and skipped). Required for the `dual` type — old firmware safely ignores this key. |
| `groups` | array | List of [Orchestration Groups](#5-orchestration-groupsjson). |
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

Defines physical storage mediums. Each entry in the `disks`, `disks_v2`,
or `disks_v3` array uses this schema. See the
[Disks overview](../overview/disks.md) for type-specific details and
examples.

| Key | Value Type | Default | Description |
|:---|:---|:---:|:---|
| `name` | string | **Mandatory** | Unique name used in `run.json` storage keys and mount paths. |
| `aliases` | string array | empty | Additional names this disk answers to. Volumes referring to any alias resolve to this disk. Aliases must not shadow another disk's `name` or be claimed by more than one disk; conflicts make the state refuse to boot. See [Aliases](../overview/disks.md#aliases) in the overview. |
| `type` | enum | **Mandatory** | `dm-crypt-caam`, `dm-crypt-dcp`, `dm-crypt-versatile`, `swap-disk`, `volume-disk`, `dual`. |
| `path` | string | **Mandatory** (crypt, swap, vol with provision) | Device/image path. CAAM v2: `-v2 <img>,<size>,<key>`. DCP/versatile: `<img>,<size>,<key>`. Not required for `volume-disk` without `provision`. |
| `mode` | enum | **Mandatory** (crypt) | `mainline` or `nxp`. Selects key subsystem. |
| `format` | enum | `ext4` | Filesystem format: `ext4`, `ext3`, or `swap`. |
| `provision` | string | empty | Backend provisioning: `zram`, `file`, or a custom value. Required for swap; optional for `volume-disk` (absent → bind-mount backend). |
| `provision_options` | string | empty | Backend-specific options (e.g. `disksize=128M comp_algorithm=lz4`). |
| `mount_target` | path | empty | Where to mount the disk on the host. Required for `volume-disk`. |
| `mount_options` | string | empty | Comma-separated mount flags (e.g. `MS_NOATIME,MS_NOSUID`). |
| `format_options` | string | empty | Arguments for the `mkfs` or `mkswap` command. |
| `default` | string | `"no"` | If `"yes"`, this disk is used for all volumes without a `disk` key. |
| `uuid` | string | empty | Disk UUID. |
| `disks` | array | **Mandatory** (dual) | Sub-disk names: `["primary-name", "secondary-name"]`. |
| `init_order` | array | **Mandatory** (dual) | Actions tried in sequence, see below. |

#### `init_order` actions

| Action | Description |
|--------|-------------|
| `primary` | Mount the existing primary disk (`--no-create`). Fails if it is not initialized. |
| `secondary` | Mount the existing secondary disk (`--no-create`). Fails if it is not initialized. |
| `create-primary` | Create, format and mount the primary disk. |
| `create-secondary` | Create, format and mount the secondary disk. |
| `copy-once-to-primary` | Mount the secondary read-only, create the primary, and copy all data with file-level verification. Skipped once the dual `init_done` marker is set. |

#### Required fields per disk type

| Type | Mandatory | Optional | Ignored |
|------|-----------|----------|---------|
| `swap-disk` | `name`, `provision` (`file`, `zram`, or any other value for a block device), `path` unless `provision` is `zram`; `provision_options` must carry `size=<value>` when `provision` is `file` | `format_options` (passed to `mkswap`), `mount_options` (passed to `swapon`) | `path` when `provision` is `zram` |
| `volume-disk` without `provision` | `name` | `aliases` | `path`, `format`, `mount_target` |
| `volume-disk` with `provision` | `name`, `format` (`ext4` or `ext3`), `mount_target`, `path` unless `provision` is `zram` | `format_options`, `mount_options`, `provision_options` | `path` when `provision` is `zram` |
| `dm-crypt-caam`, `dm-crypt-dcp`, `dm-crypt-versatile` | `name`, `path`, `mode` (`mainline` or `nxp`) | `format`, `format_options`, `mount_options` | — |
| `dual` | `name`, `disks`, `init_order` | `aliases` | `path`, `format` |

`mount_options` accepts a comma-separated list of: `MS_NOATIME`, `MS_NODEV`, `MS_NOEXEC`,
`MS_NOSUID`, `MS_RDONLY`, `MS_RELATIME`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_LAZYTIME`,
`MS_MANDLOCK`, `MS_NODIRATIME`, `MS_REC`, `MS_SILENT`, `MS_STRICTATIME`.

When `provision` is `zram`, `provision_options` is a space-separated list of `key=value` pairs
written to `/sys/block/zramX/*` (e.g. `disksize=128M comp_algorithm=lz4`), and `path` is overwritten
with the allocated `/dev/zramX`.

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
| `logs` | array | No | [Logger configurations](../overview/containers.md#loggers). |
| `dev-log` | boolean | No | Whether to bind-mount `/dev/log` into this container. Overrides the global [`PV_LOG_AUTO_DEVLOG`](pantavisor-configuration.md#summary) setting for this container. |
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

---

## 10. Complete example

A minimal revision made of a BSP and one container named `awconnect`:

```
{
  "#spec": "pantavisor-service-system@1",
  "_hostconfig/pvr/docker.json": {
    "platforms": [
      "linux/arm64",
      "linux/arm"
    ]
  },
  "awconnect/lxc.container.conf": "153d58588b0327f73c8424c214c039fcdd975814bc075bc5c72f82fd3cdfd7b6",
  "awconnect/root.squashfs": "e1ddabe573021b48dd5d66d59593d94fbc57b7a2f85dac59628959ae6955d2e2",
  "awconnect/root.squashfs.docker-digest": "828054813b64d71d26756903010a52828941f6bb0859e878cb70f6f1e0ec7d2d",
  "awconnect/run.json": {
    "#spec": "service-manifest-run@1",
    "config": "lxc.container.conf",
    "name": "awconnect",
    "root-volume": "root.squashfs",
    "storage": {
      "docker--etc-NetworkManager-system-connections": {
        "persistence": "permanent"
      },
      "lxc-overlay": {
        "persistence": "boot"
      }
    },
    "type": "lxc",
    "volumes": []
  },
  "awconnect/src.json": {
    "#spec": "service-manifest-src@1",
    "docker_config": {
      "AttachStderr": false,
      "AttachStdin": false,
      "AttachStdout": false,
      "Cmd": [
        "/lib/systemd/systemd"
      ],
      "Domainname": "",
      "Env": [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      ],
      "Hostname": "",
      "Image": "sha256:a8c4da0f0bde245a971a4a63a205cf56e071611f78b3d650715f309b7cefc57b",
      "OpenStdin": false,
      "StdinOnce": false,
      "Tty": false,
      "User": "",
      "Volumes": {
        "/etc/NetworkManager/system-connections/": {}
      },
      "WorkingDir": "/opt/wifi-connect/"
    },
    "docker_digest": "registry.gitlab.com/pantacor/pv-platforms/wifi-connect@sha256:b2ad073c0a41d186b6338fb8b81714eb1b8da9421383bbf8914fb86a01bbcafb",
    "docker_name": "registry.gitlab.com/pantacor/pv-platforms/wifi-connect",
    "docker_source": "remote,local",
    "docker_tag": "arm32v5",
    "persistence": {},
    "template": "builtin-lxc-docker"
  },
  "bsp/addon-plymouth.cpio.xz4": "beae6a7bb235916cac52bcfece64c30615cded8c4c640e6941e7ecabe53b4920",
  "bsp/build.json": {
    "altrepogroups": "",
    "branch": "master",
    "commit": "e2a4911eb35de2032e85f74c8f239de81c6f622b",
    "gitdescribe": "014-rc14-18-ge2a4911",
    "pipeline": "436189414",
    "platform": "rpi64",
    "project": "pantacor/pv-manifest",
    "pvrversion": "pvr version 026-52-gbf3bd5d6",
    "target": "arm-rpi64",
    "time": "2021-12-24 01:25:27 +0000"
  },
  "bsp/firmware.squashfs": "f37e9699ea8add7042e2843d095e68a316e6344d832b74d41244cb0bca29464e",
  "bsp/kernel.img": "990f8b0fcab8b99f631497753cc55b70f6f522a1d91cd4ae0777a7747b98509e",
  "bsp/modules.squashfs": "0e202a7ee3a575bc502ec3869251a3587a3110079f221fc15c63da1e8d8a08ae",
  "bsp/pantavisor": "1e6561f75cba98500f023e09aae430557fe0d1b02aeb1fa9adb3c2d3b6d250c6",
  "bsp/run.json": {
    "addons": [
      "addon-plymouth.cpio.xz4"
    ],
    "firmware": "firmware.squashfs",
    "initrd": "pantavisor",
    "initrd_config": "",
    "linux": "kernel.img",
    "modules": "modules.squashfs"
  },
  "bsp/src.json": {
    "#spec": "bsp-manifest-src@1",
    "pvr": "https://pvr.pantahub.com/pantahub-ci/arm_rpi64_bsp_latest#bsp"
  }
}
```
