# Pantavisor Disk Management

## Overview

Pantavisor manages persistent storage through disk definitions in
`device.json`. Disk types range from encrypted dm-crypt volumes with
hardware-backed keys to swap devices and plain ext4 volumes. All disk
types share a common `struct pv_disk` and lifecycle (init, status,
format, mount, umount) but use type-specific implementations.

## Disk Types

### swap-disk

Swap space, either from a block device or a file.

- `provision`: required — `"file"` for file-backed swap, any other value
  for block device
- `provision_ops`: for file-backed swap, must contain `size=<value>`
  (e.g. `"size=64M"`)
- `format_ops`: optional — passed to `mkswap`
- `mount_ops`: optional — passed to `swapon`
- `path`: block device path or file path

If `provision` is `"zram"`, a zram device is created instead (see Zram below).

Swap disks are mounted first during boot, before all other disk types.

```json
{
    "name": "my-swap",
    "type": "swap-disk",
    "provision": "file",
    "provision_ops": "size=64M",
    "path": "/storage/swapfile"
}
```

### volume-disk

Plain (unencrypted) ext4/ext3 volume mounted at a specified target.

- `provision`: required (any value; `"zram"` selects zram backend)
- `format`: required — `"ext4"` or `"ext3"`
- `mount_target`: required — where to mount the filesystem
- `path`: required — block device path
- `format_ops`: optional — passed to `mkfs.<format>`
- `mount_ops`: optional — comma-separated mount flags:
  `MS_NOATIME`, `MS_NODEV`, `MS_NOEXEC`, `MS_NOSUID`, `MS_RDONLY`,
  `MS_RELATIME`, `MS_SYNCHRONOUS`, `MS_DIRSYNC`, `MS_LAZYTIME`,
  `MS_MANDLOCK`, `MS_NODIRATIME`, `MS_REC`, `MS_SILENT`, `MS_STRICTATIME`

```json
{
    "name": "my-data",
    "type": "volume-disk",
    "provision": "block",
    "format": "ext4",
    "path": "/dev/mmcblk0p5",
    "mount_target": "/data",
    "mount_options": "MS_NOATIME,MS_NOSUID"
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

### directory (not implemented)

Defined in the type enum but has no implementation. Will fail at runtime.

## device.json Fields

| Field | Required | Applies to | Description |
|-------|----------|------------|-------------|
| `name` | yes | all | Disk identifier, used for mount path and volume references |
| `type` | yes | all | `dm-crypt-caam`, `dm-crypt-dcp`, `dm-crypt-versatile`, `swap-disk`, `volume-disk` |
| `path` | yes | all | Device/image path. CAAM: `-v2 <img>,<size>,<key>` |
| `mode` | caam, dcp | crypt | `mainline` or `nxp` — required for caam and dcp |
| `format` | volume | volume | `ext4`, `ext3`, or `swap` |
| `provision` | swap/vol | swap, volume | Backend type. `"zram"` for zram, `"file"` for file-backed swap |
| `provision_ops` | no | swap, volume | Backend-specific options (see type docs above) |
| `mount_target` | volume | volume | Filesystem mount point |
| `mount_options` | no | volume | Comma-separated mount flags (e.g. `MS_NOATIME`) |
| `format_options` | no | swap, volume | Options passed to mkfs/mkswap |
| `default` | no | all | `"yes"`: use as default disk for volumes without explicit disk ref |
| `always_on` | no | all | `"true"`: mount at boot regardless of volume references |
| `read_only` | no | crypt | `"true"`: dm-crypt device created read-only, mount with `-o ro` |
| `copy_from` | no | crypt | Source disk name to copy content from on first init |
| `uuid` | no | all | Disk UUID |

## Boot Sequence

1. **Swap disks** — `pv_disk_mount_swap()` mounts all `swap-disk` type disks
2. **Always-on disks** — `pv_disk_mount_always_on()` mounts disks with `always_on: true`
3. **BSP volumes** — volumes without a platform trigger on-demand disk mount
4. **Platform volumes** — platform-specific volumes trigger on-demand disk mount

Volumes reference disks by name. When a volume mounts and its referenced
disk is not yet mounted, the disk is mounted on demand.

## Encrypted Disk First Init (do_crypt_init)

On first mount (no `<keyname>.init_done` sentinel file):

1. Generate encryption key (type-specific)
2. Create image file (`dd if=/dev/zero`)
3. Set up loop device and dm-crypt mapping
4. Format with `mkfs.ext4`
5. If `copy_from` is set: mount, copy content from source, verify checksums
6. Tear down dm-crypt and loop device
7. Write `<keyname>.init_done` sentinel

Key writes use atomic `.tmp` + `sync` + `mv` pattern for power-loss safety.
If init is interrupted (power loss), the next boot detects the missing
`init_done` file and retries. Key creation is idempotent — existing keys
are reused.

## copy_from Migration

Enables populating a new encrypted disk from an existing read-only source:

```json
{
    "disks": [
        {
            "name": "secrets-legacy",
            "type": "dm-crypt-caam",
            "mode": "nxp",
            "path": "-v2 /storage/dm-crypt-files/secrets/caam.img,2,key",
            "always_on": "true",
            "read_only": "true"
        },
        {
            "name": "secrets",
            "type": "dm-crypt-caam",
            "mode": "mainline",
            "path": "-v2 /storage/dm-crypt-files/secrets-ml/caam.img,2,key",
            "always_on": "true",
            "copy_from": "secrets-legacy"
        }
    ]
}
```

Requirements:
- Source disk must be listed before target (mounted first via `always_on`)
- Source disk must be `read_only: true` (verified at block device level)
- Copy is verified by comparing md5 checksums of all files
- `init_done` is only written after successful verification
- If copy fails, next boot retries from scratch (mkfs + copy)

After migration completes, the legacy disk entry can remain (read-only,
minimal overhead) or be removed.

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
| `disk/disk.h` | `struct pv_disk`, type enums, inline string converters |
| `disk/disk.c` | Dispatcher: `pv_disk_mount()`, `pv_disk_mount_swap()`, `pv_disk_mount_always_on()` |
| `disk/disk_crypt.c` | Crypt impl: builds command string, invokes crypt script |
| `disk/disk_swap.c` | Swap impl: mkswap, swapon/swapoff |
| `disk/disk_volume.c` | Volume impl: mkfs, mount/umount to mount_target |
| `disk/disk_zram.c` | Zram backend: creates zram device, delegates to swap/volume impl |
| `disk/disk_zram_utils.c` | Zram sysfs helpers: compression, size, streams |
| `disk/disk_utils.c` | Shared: `pv_disk_utils_run_cmd()`, mount/format/swap helpers |
| `disk/disk_impl.h` | `struct pv_disk_impl` interface (init/status/format/mount/umount) |
| `parser/parser_system1.c` | `parse_disks()` — JSON parsing of disk definitions |
| `utils/tsh.c` | `tsh_run_io()` — command execution with quote-aware arg splitting |
| `scripts/volmount/crypt/crypt` | Shell script: key mgmt, dm-crypt setup, mount/umount/recovery |

## TODO

- **GC cleanup of orphaned dm-crypt-files**: When a disk is removed from
  `device.json`, its files under `/storage/dm-crypt-files/<disk>/` (image,
  keys, backups) are not cleaned up by `pv_storage_gc_run()`. Adding this
  requires scanning the dm-crypt-files directory and comparing against
  disk paths in the current state. Care needed: misconfigured device.json
  temporarily missing a disk entry could cause irreversible key deletion.
