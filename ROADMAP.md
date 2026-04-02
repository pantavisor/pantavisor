# Pantavisor Disk Roadmap

## 1. Source abstraction

Decouple "where the block device comes from" from "what to do with it."
Replace the overloaded `path` field with a structured `source` object.

```json
{"source": {"type": "image", "path": "/storage/.../data.img", "size": "100M"}}
{"source": {"type": "device", "path": "/dev/nvme0n1p3"}}
{"source": {"type": "partition", "match": {"partlabel": "pv-data"}}}
{"source": {"type": "zram", "disksize": "128M", "comp_algorithm": "lz4"}}
```

The current `path` field maps transparently:
- `-v2 <img>,<size>,<key>` → `{"type": "image", ...}`
- `/dev/mmcblk0p5` → `{"type": "device", ...}`
- `provision: "zram"` → `{"type": "zram", ...}`

Parser handles both old `path` and new `source` formats.

## 2. Software RAID

Add a `"raid"` disk type that combines multiple sub-disks (typically
dm-crypt) into a single mdadm array. Reuses the composite disk
infrastructure from the `dual` type.

### device.json format

```json
{
    "disks_v3": [
        {
            "name": "fast-storage",
            "type": "raid",
            "level": "0",
            "disks": ["_INT-crypt-a", "_INT-crypt-b"],
            "format": "ext4"
        }
    ]
}
```

### RAID levels

| Level | Min disks | Description |
|-------|-----------|-------------|
| 0 | 2 | Stripe — performance, no redundancy |
| 1 | 2 | Mirror — redundancy |
| 5 | 3 | Stripe + parity |
| 6 | 4 | Stripe + double parity |
| 10 | 4 | Mirror + stripe |
| linear | 2 | Concatenation |

### Implementation plan

**1. Crypt script: add `open`/`close` actions**

Sub-disks for RAID need dm-crypt setup without mount. Add two new
actions alongside existing `mount`/`umount`:

- `open`: init key + image, setup loop + dm-crypt mapping. Outputs
  `/dev/mapper/<name>`. No filesystem format, no mount.
- `close`: tear down dm-crypt mapping + loop device.

~20 lines — reuse existing init/dm-setup code, skip mount step.

**2. Disk impl interface: add open/close callbacks**

```c
struct pv_disk_impl {
    int (*init)(struct pv_disk *disk);
    pv_disk_status_t (*status)(struct pv_disk *disk);
    int (*format)(struct pv_disk *disk);
    int (*mount)(struct pv_disk *disk);
    int (*umount)(struct pv_disk *disk);
    int (*open)(struct pv_disk *disk);   /* new: setup without mount */
    int (*close)(struct pv_disk *disk);  /* new: teardown without umount */
};
```

Optional callbacks — NULL means not supported. The crypt impl
provides them; swap/volume/dual do not.

**3. Add `DISK_RAID` type**

- Add `DISK_RAID` to `pv_disk_t` enum, string converters
- Add `level` field to `struct pv_disk` (parsed from JSON)
- Add `raid_impl` extern declaration

**4. Create `disk/disk_raid.c`**

~150 lines, similar skeleton to `disk_dual.c`:

```
raid_init:
    validate sub-disks exist
    validate min disk count for level

raid_mount:
    for each sub-disk: pv_disk_open(sub)  → /dev/mapper/<name>
    mdadm --create /dev/md/<raid-name> --level=<N>
           --raid-devices=<count> /dev/mapper/<d1> /dev/mapper/<d2> ...
    if no init_done: mkfs.ext4 /dev/md/<raid-name>
    mount /dev/md/<raid-name> <mntpath>
    touch init_done

raid_umount:
    umount <mntpath>
    mdadm --stop /dev/md/<raid-name>
    for each sub-disk: pv_disk_close(sub)
```

**5. Parser**

The `disks` array and `level` field are parsed in `parse_disks_ex`
for `DISK_RAID` type, same pattern as `DISK_DUAL` dual array parsing.

### Dependencies

- `mdadm` must be available in the initramfs (RDEPENDS in recipe)
- Sub-disks must support `open`/`close` (currently only crypt)
- Existing dual infrastructure: `disk_list`, `pv_disk_find()`,
  `pv_disk_is_internal()`, `disks` array parsing

## 3. Hotplug slots

### Concept

For hot-pluggable and external storage, device.json defines **slots**
(abstract storage endpoints), not disks. Physical devices get **bound**
to slots at runtime — either automatically via policy or manually via
the ctrl API.

```
Slot (OTA-managed)          Binding (local state)         Physical device
┌──────────────────┐        ┌─────────────────┐          ┌──────────────┐
│ media-storage    │◄──────►│ UUID: 1234-5678 │◄────────►│ /dev/sda1    │
│ strategy: auto   │        │ serial: WD-ABC  │          │ 32GB USB     │
│ accept: usb,ext4 │        │ bound_at: ...   │          └──────────────┘
└──────────────────┘        └─────────────────┘
```

Slot definitions are OTA-managed (platform decides what slots exist).
Bindings are local persistent state (survive reboots, not part of OTA).

### device.json format

```json
{
    "disks_v3": [
        {
            "name": "media-rw",
            "type": "hotplug-slot",
            "strategy": "partlabel",
            "multi": false,
            "accept": {
                "bus": ["usb"],
                "partlabel": "PV-MEDIA-RW",
                "min_size": "1G"
            },
            "format_policy": "preserve",
            "mount_target": "/media/rw"
        },
        {
            "name": "media-ro",
            "type": "hotplug-slot",
            "strategy": "first-fit",
            "multi": true,
            "merge": "overlay-ro",
            "accept": {
                "bus": ["usb"],
                "fstype": ["vfat", "ext4", "ntfs"]
            },
            "mount_target": "/media/content"
        },
        {
            "name": "backup",
            "type": "hotplug-slot",
            "strategy": "partlabel",
            "multi": false,
            "accept": {
                "bus": ["usb"],
                "partlabel": "PV-BACKUP",
                "min_size": "4G"
            },
            "format_policy": "format-if-empty",
            "mount_target": "/backup"
        }
    ]
}
```

### Auto-assign strategies

Strategies determine how devices are assigned to slots without
platform/user intervention. The right defaults mean headless products
work out of the box.

| Strategy | Behavior | Use case |
|----------|----------|----------|
| `first-fit` | First matching unbound device wins. If slot occupied (and `multi: false`), ignore new devices. | Headless single-drive: plug in a stick, it works |
| `replace` | New matching device replaces current binding. Old device safely ejected. | Kiosk: swap content stick, new one takes over |
| `partlabel` | Only bind if partition label matches. The stick declares what it's for. | Factory-provisioned devices: label the stick during production |
| `priority` | Prefer by criteria (largest, specific serial). Replace if better match arrives. | Always use the biggest available drive |
| `manual` | Never auto-bind. Only via ctrl API. | UI-driven products where user/platform decides |

**`partlabel` is the killer default for headless products.** The USB
stick itself declares its purpose via partition label. No UI, no API,
no runtime config. Factory or field technician partitions the stick
with `PV-MEDIA` or `PV-BACKUP` label, pantavisor does the rest.

**`first-fit` with `multi: true` is the zero-config catch-all.** One
slot that accepts everything — each stick gets a subdirectory. Platform
containers read from `/media/usb/`. Done.

### Slot evaluation order

When a device is plugged in, slots are evaluated in definition order.
First slot that accepts the device wins. Platform builders control
priority by ordering slots from most specific to least specific:

```json
"disks_v3": [
    {"name": "backup",    "accept": {"partlabel": "PV-BACKUP"}, ...},
    {"name": "media-rw",  "accept": {"partlabel": "PV-MEDIA"}, ...},
    {"name": "media-ro",  "strategy": "first-fit", "multi": true, ...}
]
```

Stick labeled `PV-BACKUP` → backup slot. Labeled `PV-MEDIA` →
media-rw. Unlabeled → falls through to media-ro catch-all.

### Merge strategies (multi-device slots)

When `multi: true`, multiple devices can be bound to one slot. The
`merge` field controls how they appear to containers:

| Merge | Behavior | Reformats? |
|-------|----------|------------|
| `subdirs` | Each device gets a subdirectory: `/media/content/<uuid>/` | No |
| `overlay-ro` | overlayfs merges all devices into flat read-only view | No |
| `overlay-rw` | overlayfs with write layer on designated device or main storage | No |
| `linear` | dm linear concatenation into one big block device | Yes |

**`subdirs` is the safe universal default.** Works with any filesystem,
read-write per device, trivial to implement. Containers see all
content organized by source.

**`overlay-ro` is ideal for media/content.** Flat merged namespace,
all files appear together. Read-only. Remounted when sticks are
added/removed.

### Format policies

| Policy | Behavior |
|--------|----------|
| `preserve` | Use existing filesystem as-is, fail if incompatible |
| `format-if-empty` | Format only if no filesystem detected |
| `always-format` | Format on every bind (for dedicated devices) |
| `ask` | Notify platform via ctrl API, wait for decision |

### Accept criteria

The `accept` object filters which devices can bind to a slot:

| Field | Match against |
|-------|---------------|
| `bus` | `["usb", "sdcard", "nvme", "sata"]` |
| `bus_path_prefix` | sysfs path like `"usb1-1"` (specific USB port) |
| `fstype` | `["ext4", "vfat", "ntfs"]` |
| `partlabel` | GPT partition label |
| `min_size` | Minimum device size (`"1G"`, `"500M"`) |
| `max_size` | Maximum device size |
| `vendor` | USB vendor ID |
| `model` | USB model ID |

### Binding persistence

Bindings are stored in `/storage/pantavisor/slot-bindings.json`,
outside the OTA state:

```json
{
    "backup": {
        "device_serial": "WD-WXK1A234567",
        "partition_uuid": "1234-5678",
        "bound_at": "2026-04-02T10:00:00Z"
    }
}
```

Identity is multi-factor: partition UUID (stable across reboots) +
device serial (survives reformat). For `strategy: "auto"` / `"first-fit"`
slots, bindings are transient (not persisted).

### Hotplug lifecycle

```
Device plugged in
    │
    ├─► Match saved bindings (by serial+UUID)
    │       └── found → mount to slot → notify containers
    │
    ├─► Evaluate slot strategies in order
    │       ├── partlabel match → bind + mount → notify
    │       ├── first-fit match → bind + mount → notify
    │       └── no match → report as unbound
    │
    └─► Unbound device available via ctrl API
            └── Platform/user binds via API → mount → persist → notify
```

```
Device removed
    │
    ├─► sync filesystem
    ├─► unmount (lazy if busy)
    ├─► update slot status
    └─► notify containers
```

### Ctrl API

```
GET  /slots                     — list all slots + binding state
GET  /slots/{name}              — slot details, current binding, mount status
POST /slots/{name}/bind         — bind a specific device to this slot
POST /slots/{name}/unbind       — eject / unbind (specific device for multi)
GET  /devices/unbound           — detected devices not bound to any slot
```

### Container notification

Status file per slot, watchable via inotify:

```json
// /run/pantavisor/slots/media-ro/status.json
{
    "state": "mounted",
    "devices": [
        {"uuid": "A1B2-C3D4", "serial": "...", "size": "32G", "fstype": "vfat"},
        {"uuid": "E5F6-G7H8", "serial": "...", "size": "16G", "fstype": "ext4"}
    ],
    "mount_target": "/media/content",
    "merge": "overlay-ro"
}
```

### Showcase: media appliance

Platform defines two slots — writable media and read-only content
library. Frontend container presents UI on USB plug:

| Slot state | UI choices |
|-----------|------------|
| rw empty, ro empty | [Writable Media] [Read-Only Content] [Both] |
| rw empty, ro has devices | [Writable Media] [Add to Library] [Both] |
| rw occupied | [Replace Writable] [Add to Library] |

"Both" = bind to media-rw (writable mount) AND add to media-ro
(read-only overlay). Same physical device, two slot bindings.

**Headless variant** with no UI — pure policy:

```json
{
    "name": "usb-storage",
    "type": "hotplug-slot",
    "strategy": "first-fit",
    "multi": true,
    "merge": "subdirs",
    "accept": {"bus": ["usb"]},
    "format_policy": "preserve",
    "mount_target": "/media/usb"
}
```

One slot, catches everything, each stick gets a subdirectory. Zero
config, zero API, zero UI. Containers read from `/media/usb/`.

### Design principles

- **Slots are OTA-managed, bindings are local state.** Platform defines
  what's possible, users/runtime decide what's connected.
- **Strategies are the headless-first default.** Every slot works
  without UI. The API/UI path is an optional enhancement.
- **Same device, multiple slots.** A device can be bound to N slots
  simultaneously (the "Both" case).
- **Containers don't restart on hotplug.** Mount points appear/disappear
  at runtime. Containers handle this via inotify on status files.
- **Pantavisor provides building blocks.** Source resolution, encryption,
  compositing, hotplug lifecycle. Platform builders compose them.

### Implementation priority

1. Device discovery module (uevent netlink monitor, /sys/block scan)
2. Slot matching engine (accept criteria, strategy evaluation)
3. Single-device slot lifecycle (bind/mount/unbind/unmount)
4. Ctrl API endpoints
5. Multi-device merge (subdirs first, then overlay-ro)
6. Status file notifications
7. Binding persistence

### What NOT to build

- No LVM/ZFS/btrfs — delegate to containers via passthrough
- No partition table management — use `partition` source matcher
- No filesystem diversity beyond ext4/swap — containers handle the rest
- No complex scheduling — first-match-wins is enough
