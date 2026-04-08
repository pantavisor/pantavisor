# Pantavisor Disk Management

## Overview

Pantavisor manages persistent storage through disk definitions in
`device.json`. Disk types range from encrypted dm-crypt volumes with
hardware-backed keys to swap devices, plain ext4 volumes, and composite
dual disks for key migration. All disk types share a common `struct
pv_disk` and lifecycle (init, status, format, mount, umount) but use
type-specific implementations.

Disk definitions can live in three arrays inside `device.json`:
- `disks` — original format, strict parsing (unknown types are fatal)
- `disks_v2` — same as disks, additive
- `disks_v3` — lenient parsing (unknown types are warned and skipped),
  supports the `dual` type. Old firmware safely ignores this key.

All three arrays are parsed independently — the absence of one does
not prevent parsing the others.

## Disk Types

### swap-disk

Swap space from a block device, file, or zram.

- `path`: block device or file path (ignored when `provision` is `"zram"`)
- `provision`: required by the dispatcher — `"file"` for file-backed
  swap, `"zram"` for compressed RAM (see Zram section). For block
  device swap, set to any non-zram value (e.g. `"block"`).
- `provision_ops`: for file-backed swap, must contain `size=<value>`
  (e.g. `"size=64M"`)
- `format_ops`: optional — passed to `mkswap`
- `mount_ops`: optional — passed to `swapon`

Swap disks are mounted first during boot, before all other disk types.

**Block device:**
```json
{
    "name": "my-swap",
    "type": "swap-disk",
    "path": "/dev/mmcblk0p4",
    "format": "swap"
}
```

**File-backed:**
```json
{
    "name": "my-swap",
    "type": "swap-disk",
    "provision": "file",
    "provision_ops": "size=64M",
    "path": "/storage/swapfile",
    "format": "swap"
}
```

**Zram:**
```json
{
    "name": "my-zram-swap",
    "type": "swap-disk",
    "provision": "zram",
    "provision_ops": "disksize=128M comp_algorithm=lz4",
    "format": "swap"
}
```

### volume-disk (EXPERIMENTAL)

> **WARNING**: volume-disk runs `mkfs` on every mount cycle —
> **it reformats the block device every boot**. This is safe for zram
> backends (ephemeral RAM) but **will destroy data on real block
> devices**. Do not use with persistent block devices until a
> `format` policy (`auto`/`no`) is implemented. See TODO section.

Plain (unencrypted) ext4/ext3 volume mounted at a specified target.

- `format`: required — `"ext4"` or `"ext3"`
- `mount_target`: required — where to mount the filesystem
- `path`: required — block device path (ignored when `provision` is `"zram"`)
- `provision`: required by the dispatcher — set to `"zram"` for
  compressed RAM backend (see Zram section). For block device backed
  disks, set to any non-zram value (e.g. `"block"`).
- `format_ops`: optional — passed to `mkfs.<format>`
- `mount_ops`: optional — comma-separated mount flags:
  `MS_NOATIME`, `MS_NODEV`, `MS_NOEXEC`, `MS_NOSUID`, `MS_RDONLY`,
  `MS_RELATIME`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_LAZYTIME`,
  `MS_MANDLOCK`, `MS_NODIRATIME`, `MS_REC`, `MS_SILENT`, `MS_STRICTATIME`

**Block device backed:**
```json
{
    "name": "my-data",
    "type": "volume-disk",
    "format": "ext4",
    "path": "/dev/mmcblk0p5",
    "mount_target": "/data",
    "mount_options": "MS_NOATIME,MS_NOSUID"
}
```

**Zram backed:**
```json
{
    "name": "my-tmpdata",
    "type": "volume-disk",
    "provision": "zram",
    "provision_ops": "disksize=64M",
    "format": "ext4",
    "mount_target": "/tmp/data"
}
```

### Zram Backend (swap-disk and volume-disk)

When `provision` is `"zram"`, a compressed RAM-backed block device is
created dynamically instead of using a physical device. Works for both
swap and volume disk types.

- `provision_ops`: space-separated `key=value` pairs written to
  `/sys/block/zramX/*` — e.g. `"disksize=128M comp_algorithm=lz4"`
- `path`: ignored (overwritten with `/dev/zramX`)

The zram device is reset on umount.

```json
{
    "name": "my-zram-swap",
    "type": "swap-disk",
    "provision": "zram",
    "provision_ops": "disksize=128M comp_algorithm=lz4"
}
```

### dm-crypt-caam

NXP CAAM (Cryptographic Acceleration and Assurance Module) backed
encryption. Requires an explicit `mode` field.

**mode: nxp** — NXP proprietary tagged key API.
- Cipher: `capi:tk(cbc(aes))-plain`
- Key type: `logon` (kernel keyring)
- Key generation: `caam-keygen create` produces a black blob (`.bb` file)
- Key import: `caam-keygen import` + `keyctl padd logon`

**mode: mainline** — Upstream Linux trusted key subsystem.
- Cipher: `capi:cbc(aes)-plain64`
- Key type: `trusted` (kernel keyring)
- Key generation: `keyctl add trusted <name> "new 32"`, sealed blob as `.bb`
- Key import: `keyctl add trusted <name> "load <blob>"`

Both modes require the path to start with `-v2 ` prefix as a safety
measure preventing old code from mounting with the wrong mode.

Path format: `-v2 <imgpath>,<size-in-MB>,<keyname>`

### dm-crypt-dcp

NXP DCP (Data Co-Processor) backed encryption (i.MX6ULL and similar).
Requires an explicit `mode` field.

**mode: nxp** — Legacy NXP grey blob key format.
- Cipher: `capi:cbc(aes)-essiv:sha256`
- Uses `cryptsetup open --type plain`
- Requires a `x--pv-dcp-tool` command (not included, must be provided)
  that implements two operations:
  - `x--pv-dcp-tool encrypt <outfile>`: read plaintext key from stdin,
    encrypt it using the DCP hardware UNIQUE key, write sealed blob to
    `<outfile>`
  - `x--pv-dcp-tool decrypt <infile>`: read sealed blob from `<infile>`,
    decrypt it using the DCP hardware UNIQUE key, write plaintext key
    to stdout
- Key generation: `dd if=/dev/random bs=32 count=1 | x--pv-dcp-tool encrypt <keyfile>`
- At mount time the plaintext key is recovered via `x--pv-dcp-tool decrypt`
  and passed to cryptsetup via a temporary key file

**mode: mainline** — Upstream Linux trusted key subsystem (`trusted.source=dcp`).
- Cipher: `capi:cbc(aes)-essiv:sha256`
- Key type: `trusted` (kernel keyring, plaintext never leaves kernel)
- Key generation: `keyctl add trusted <name> "new 32"`, sealed blob as `.bb`
- Key import: `keyctl add trusted <name> "load <blob>"`
- Uses `dmsetup create` with kernel keyring reference
- Kernel requirement: Linux 6.14+ (or 6.13 with VMAP_STACK fix backported)

**Key migration (nxp → mainline):** When mode is `mainline` and a legacy
NXP grey blob exists but no `.bb` file is found, automatic migration runs:
1. Decrypt NXP grey blob via `x--pv-dcp-tool decrypt` to recover plaintext key
2. Pipe plaintext into `dcp-blob-create` to create a valid kernel DCP
   trusted key blob
3. Save blob as `.bb.pending`
4. Load blob via `keyctl`, mount disk
5. Only on successful mount: finalize `.bb.pending` → `.bb`
6. Stale `.pending` files are cleaned up on retry (idempotent)

Migration requires `x--pv-dcp-tool` (see nxp mode above) and the
`dcp-blob-create` tool which needs an NXP DCP kernel patch that maps
zero-length key in `mxs_dcp_aes_setkey()` to `DCP_PAES_KEY_UNIQUE`.

Path format: `<imgpath>,<size-in-MB>,<keyname>`

### dm-crypt-versatile

Software-only encryption using a plaintext key file.
- Cipher: `aes-cbc-essiv:sha256`
- Uses `cryptsetup open --type plain`
- Key: plaintext file `<keyname>.txt` (generated from `/dev/random`)

### dual

Composite disk type that orchestrates a primary and secondary sub-disk
as a single logical disk. Sub-disks are mounted under their own name
and the dual disk bind-mounts from the sub-disk path to its own path.

Must be defined in `disks_v3` — old firmware does not recognize the
`"dual"` type and would fail if it appeared in `disks` or `disks_v2`.

- `disks`: JSON array of sub-disk names (first = primary, second = secondary)
- `init_order`: JSON array of actions tried in sequence — first to succeed wins

Sub-disks are normal disk entries (typically dm-crypt) that can also be
referenced directly by volumes. The dual impl uses `--no-create` on
sub-disks when probing (primary/secondary steps) to avoid creating
disks that don't exist yet.

```json
{
    "disks": [
        {
            "name": "_INT-dm-secrets-mainline",
            "type": "dm-crypt-caam",
            "mode": "mainline",
            "path": "-v2 /storage/dm-crypt-files/secrets-ml/caam-mainline.img,2,key-ml"
        },
        {
            "name": "_INT-dm-secrets-nxp",
            "type": "dm-crypt-caam",
            "mode": "nxp",
            "path": "-v2 /storage/dm-crypt-files/secrets/caam.img,2,key"
        }
    ],
    "disks_v3": [
        {
            "name": "dm-secrets",
            "type": "dual",
            "disks": ["_INT-dm-secrets-mainline", "_INT-dm-secrets-nxp"],
            "init_order": ["copy-once-to-primary", "primary", "create-primary"]
        }
    ]
}
```

Volumes reference the dual disk by name (`"disk": "dm-secrets"`).
Sub-disks can use the `_` prefix naming convention to signal they
are internal (see Internal Disks section below).

#### init_order Actions

| Action | Description |
|--------|-------------|
| `primary` | Try mounting existing primary disk (`--no-create`). Fails if not initialized. |
| `secondary` | Try mounting existing secondary disk (`--no-create`). Fails if not initialized. |
| `create-primary` | Create, format, and mount primary disk. |
| `create-secondary` | Create, format, and mount secondary disk. |
| `copy-once-to-primary` | Mount secondary read-only, create primary, copy all data with file-level verification. Skipped if already done (tracked by dual `init_done` marker). |

#### Common Policies

**Migration (nxp to mainline):**
```json
"init_order": ["copy-once-to-primary", "primary", "create-primary"]
```
First boot: copy data from nxp to mainline. Subsequent boots: mount
mainline directly. If nxp doesn't exist, create empty mainline.

**Mainline-only (no legacy fallback):**
```json
"init_order": ["primary", "create-primary"]
```
Mount or create mainline. No nxp involvement.

**Either-or (mainline preferred, nxp fallback):**
```json
"init_order": ["primary", "secondary", "create-primary"]
```
Try mainline, fall back to nxp if it exists, create mainline if neither.
No data migration.

#### Bind-Mount Architecture

The dual impl mounts sub-disks under their own name and then creates
a bind-mount to the dual disk's path:

```
Sub-disk mounted:  /media/pv/dmcrypt/_INT-dm-secrets-mainline
Bind-mount:        /media/pv/dmcrypt/dm-secrets → (bind) → /media/pv/dmcrypt/_INT-dm-secrets-mainline
```

This means:
- No name-swapping hacks — sub-disks keep their canonical name
- No double dm-crypt mappings — each image is opened once
- Sub-disks can be shared with direct volume references
- Umount: unbind the dual path, then umount the sub-disk

#### Power-Loss Safety

The `copy-once-to-primary` action uses a dual-level `init_done` marker:

- **Sub-disk `init_done`**: created by `do_crypt_init` — means the key
  and image exist and the disk is mountable.
- **Dual `init_done`**: created only after the init_order step fully
  succeeds (data copied and verified, or disk mounted).

If power is lost during `copy-once-to-primary`:
1. Sub-disk mainline may have `init_done` (image exists, mountable)
2. Dual `init_done` is missing (copy didn't complete)
3. Next boot: `copy-once-to-primary` sees no dual marker → re-runs copy
4. Primary image exists → idempotent init (no recreation) → mounts →
   copy → verify → touches dual marker

### directory (not implemented)

Defined in the type enum but has no implementation. Will fail at runtime.

## Internal Disks

Disks with names starting with `_` are considered internal — intended
only as sub-disk references for composite types (dual, future raid).
The `pv_disk_is_internal()` helper checks for this convention. This is
advisory — pantavisor does not enforce it, but platform builders can
use it to signal "don't reference these directly from volumes."

## device.json Fields

| Field | Required | Applies to | Description |
|-------|----------|------------|-------------|
| `name` | yes | all | Disk identifier, used for mount path and volume references |
| `type` | yes | all | `dm-crypt-caam`, `dm-crypt-dcp`, `dm-crypt-versatile`, `swap-disk`, `volume-disk`, `dual` |
| `path` | yes | crypt, swap, vol | Device/image path. CAAM: `-v2 <img>,<size>,<key>` |
| `mode` | yes | crypt | `mainline` or `nxp` |
| `disks` | yes | dual | JSON array of sub-disk names: `["primary-name", "secondary-name"]` |
| `init_order` | yes | dual | JSON array of actions (see Dual Mode section) |
| `format` | yes | volume | `ext4`, `ext3`, or `swap` |
| `provision` | yes | swap, vol | Backend type. `"zram"` for zram, `"file"` for file-backed swap |
| `provision_ops` | no | swap, vol | Backend-specific options (see type docs above) |
| `mount_target` | yes | volume | Filesystem mount point |
| `mount_options` | no | volume | Comma-separated mount flags (e.g. `MS_NOATIME`) |
| `format_options` | no | swap, vol | Options passed to mkfs/mkswap |
| `default` | no | all | `"yes"`: use as default disk for volumes without explicit disk ref |
| `uuid` | no | all | Disk UUID |

## Volume Disk References

Volumes reference disks by name via the `"disk"` field in the container's
storage section:

```json
"storage": {
    "docker--secrets": {
        "disk": "dm-secrets",
        "persistence": "permanent"
    }
}
```

If a volume explicitly references a disk name that is not found in the
parsed disks list, the volume mount fails with an error:

```
volume 'docker--secrets' requires disk 'dm-secrets' which was not found
```

This prevents silent fallthrough to another disk or diskless operation
when a required disk is missing.

## Boot Sequence

1. **Swap disks** — `pv_disk_mount_swap()` mounts all `swap-disk` type disks
2. **BSP volumes** — volumes without a platform trigger on-demand disk mount
3. **Platform volumes** — platform-specific volumes trigger on-demand disk mount

Volumes reference disks by name. When a volume mounts and its referenced
disk is not yet mounted, the disk is mounted on demand.

## Encrypted Disk First Init (do_crypt_init)

On first mount (no `<keyname>.init_done` sentinel file):

1. Generate encryption key (type-specific)
2. Create image file (`dd if=/dev/zero`)
3. Set up loop device and dm-crypt mapping
4. Format with `mkfs.ext4`
5. Tear down dm-crypt and loop device
6. Write `<keyname>.init_done` sentinel

Key writes use atomic `.tmp` + `sync` + `mv` pattern for power-loss safety.
If init is interrupted (power loss), the next boot detects the missing
`init_done` file and retries. Key creation is idempotent — existing keys
are reused.

The `--no-create` flag skips init entirely — if `init_done` is missing,
the mount fails immediately (returns 1). Used by the dual impl for
`primary`/`secondary` probe steps.

## Mount Recovery (fsck/backup)

On encrypted disk mount failure (ext4 corruption):

1. `prebak` — image backup taken before each mount attempt
2. `fsck.ext4 -y` — attempt filesystem repair, retry mount
3. `goodbak` — last known-good image (created after first successful mount)
4. If fsck fails and `goodbak` exists, restore from backup and retry
5. If all recovery fails, mount returns error (triggers state rollback)

## Mount Paths

Crypt disks: `<mediadir>/pv/dmcrypt/<disk-name>`
(default: `/media/pv/dmcrypt/<disk-name>`)

Volume disks: configured via `mount_target` field.

Swap disks: no mount point (activated via `swapon`).

## C Code Structure

| File | Purpose |
|------|---------|
| `disk/disk.h` | `struct pv_disk`, type enums, inline string converters, `pv_disk_is_internal()` |
| `disk/disk.c` | Dispatcher: `pv_disk_mount()`, `pv_disk_find()`, boot sequence |
| `disk/disk_crypt.c` | Crypt impl: builds command string with `--no-create` support, invokes crypt script |
| `disk/disk_dual.c` | Dual impl: init_order walk, sub-disk resolution, bind-mount, copy+verify |
| `disk/disk_swap.c` | Swap impl: mkswap, swapon/swapoff |
| `disk/disk_volume.c` | Volume impl: mkfs, mount/umount to mount_target |
| `disk/disk_zram.c` | Zram backend: creates zram device, delegates to swap/volume impl |
| `disk/disk_zram_utils.c` | Zram sysfs helpers: compression, size, streams |
| `disk/disk_utils.c` | Shared: `pv_disk_utils_run_cmd()`, mount/format/swap helpers |
| `disk/disk_impl.h` | `struct pv_disk_impl` interface (init/status/format/mount/umount) |
| `parser/parser_system1.c` | `parse_disks_ex()` — JSON parsing with lenient mode for disks_v3 |
| `volumes.c` | Volume-disk reference resolution with `disk_ref` safety check |
| `utils/tsh.c` | `tsh_run_io()` — command execution with quote-aware arg splitting |
| `scripts/volmount/crypt/crypt` | Shell script: key mgmt, dm-crypt setup, mount/umount/recovery |

## TODO

- **GC cleanup of orphaned dm-crypt-files**: When a disk is removed from
  `device.json`, its files under `/storage/dm-crypt-files/<disk>/` (image,
  keys, backups) are not cleaned up by `pv_storage_gc_run()`. Adding this
  requires scanning the dm-crypt-files directory and comparing against
  disk paths in the current state. Care needed: misconfigured device.json
  temporarily missing a disk entry could cause irreversible key deletion.
- **Remove `set -x` debug tracing** from crypt script before production.
- **volume-disk format policy**: Currently reformats every boot. Add a
  `format` policy field: `"auto"` (detect existing FS, format only if
  none found — safe default), `"no"` (never format, fail if not
  mountable), `"always"` (current behavior, only sane for zram).
- **raid disk type**: Composite disk that combines multiple sub-disks
  into an mdadm array. Single `DISK_RAID` type with a `level` field
  (0, 1, 5, 6, 10, linear). Reuses `disks` array from dual. Requires
  `open`/`close` actions in the crypt script (dm-crypt setup without
  mount) and matching callbacks in `struct pv_disk_impl`. See
  [ROADMAP.md](ROADMAP.md) for full design.
- **UUID/LABEL path resolution**: Allow `path` to accept `UUID=`,
  `LABEL=`, `PARTUUID=`, `PARTLABEL=` syntax (resolved via `blkid`
  at mount time). Stable across hardware changes and boot order
  variations. Applies to all disk types that take a `path`.
- **Implicit pvroot disk**: The root storage partition (configured via
  `PV_STORAGE_DEVICE` in pantavisor.config, typically `LABEL=root`)
  is mounted at init before device.json is parsed. It should be
  exposed as an implicit disk entry named `pvroot` in the disk list
  with `default: true`. This unifies the model — all storage goes
  through the disk subsystem, and volumes without an explicit `"disk"`
  ref resolve to pvroot. Device.json disks are additive alongside it.
  The pvroot disk is never reformatted and cannot be defined in
  device.json (chicken-and-egg: device.json lives on pvroot).
- **Source abstraction**: Decouple "where the block device comes from"
  from "what to do with it." Replace the overloaded `path` field with
  a structured `source` object supporting `image` (loop-backed file),
  `device` (fixed block device), `partition` (match by label/UUID/bus),
  and `zram` (compressed RAM) source types. The current `path` field
  maps transparently to the new format.
- **Hotplug slots**: New `hotplug-slot` disk type for removable and
  external storage. Defines abstract storage endpoints (slots) that
  physical devices get bound to at runtime. Key features:
  - **Auto-assign strategies**: `first-fit` (first match wins),
    `replace` (new device replaces current), `partlabel` (match by
    GPT partition label — the USB stick declares what it's for),
    `priority` (prefer by size/serial), `manual` (API only).
  - **Multi-device slots**: `multi: true` allows multiple devices
    bound to one slot. Merge strategies: `subdirs` (each device gets
    a subdirectory), `overlay-ro` (overlayfs merged read-only view),
    `overlay-rw` (merged view with write layer).
  - **Bind modes**: `remember` (persist binding by serial+UUID for
    dedicated drives), `auto` (policy match only, no memory — for
    media import), `manual` (always ask platform via API).
  - **Accept criteria**: filter by `bus`, `bus_path_prefix` (specific
    USB port), `fstype`, `partlabel`, `min_size`, `max_size`,
    `vendor`, `model`.
  - **Format policies**: `preserve`, `format-if-empty`, `always-format`,
    `ask` (notify platform via API).
  - **Mount propagation**: Slot directory is bind-mounted into
    containers at start (empty). When a device is bound on the host,
    `MS_SHARED` propagation makes content appear inside running
    containers automatically — no restart, no dynamic mount injection.
  - **Ctrl API**: `GET /slots`, `GET /slots/{name}`, `POST /slots/{name}/bind`,
    `POST /slots/{name}/unbind`, `GET /devices/unbound`.
  - **Status notification**: per-slot status file at
    `/run/pantavisor/slots/<name>/status.json`, watchable via inotify.
  - Slot definitions are OTA-managed (device.json). Bindings are local
    persistent state (`/storage/pantavisor/slot-bindings.json`).
  - RAID should use internal (permanently attached) legs only. Hotplug
    slots handle removable media — keep them separate.
