# Raspberry Pi A/B Boot (rpiab)

The `rpiab` bootloader backend implements A/B boot partition switching for
Raspberry Pi devices using the Pi's native `tryboot` mechanism.

## Partition Layout

The disk layout uses four partitions:

| Partition | Type  | Contents |
|-----------|-------|----------|
| 1 (bootsel) | FAT32 | `autoboot.txt`, `bootcode.bin` (A/B selector) |
| 2 (boot_a) | FAT32 | Kernels, DTBs, `config.txt`, initramfs, `pv_rev.txt` |
| 3 (boot_b) | FAT32 | Same as boot_a (mirror for A/B switching) |
| 4 (root) | ext4 | Rootfs with `/trails/` state |

## Key Files

### autoboot.txt (partition 1)

Controls which partition the Pi boots from. Contains:

```ini
[all]
tryboot_a_b=1
boot_partition=2        # default boot partition
[tryboot]
boot_partition=3        # partition used during tryboot
```

When a tryboot is triggered (via the `SET_REBOOT_FLAGS` mailbox call),
the Pi boots from the `[tryboot]` partition. On a normal boot it uses
`[all]` `boot_partition`.

### pv_rev.txt (partitions 2 and 3)

Stores the revision(s) associated with a boot partition. This file lives
on the FAT32 boot partition alongside the kernel and DTBs.

For a simple reboot update, `pv_rev.txt` contains a single revision:

```
35
```

For stacked no-reboot updates, it contains a comma-separated list of all
revisions installed since the last reboot:

```
35,36,37
```

See [No-Reboot Updates](#no-reboot-updates) for details.

### rpiab.txt (rootfs)

Persistent key-value store on the ext4 rootfs. Holds:

- `pv_rev` — the last committed (done) revision
- `pv_try` — the revision being tried (set during install, cleared on commit)
- `pv_done` — alias for pv_rev in the bootloader abstraction

## Update Flow

### Reboot Update

1. **Install** (`rpiab_install_update`):
   - DD the boot image (`.img.gz`) to the try partition
   - Write `pv_rev.txt` with the new revision
   - Store `pv_try=<rev>` in `rpiab.txt`
   - Arm the tryboot flag via mailbox `SET_REBOOT_FLAGS`

2. **Reboot**: Pi boots from the `[tryboot]` partition

3. **Validate** (`rpiab_validate_state`):
   - Read `is_tryboot` from `/proc/device-tree/chosen/bootloader/tryboot`
   - Read `pv_rev.txt` from the booted partition
   - Verify the expected revision is present in `pv_rev.txt`
   - If valid, return the revision to use

4. **Commit** (`rpiab_commit_update`):
   - Swap `autoboot.txt` so the try partition becomes the new default
   - Swap internal partition globals (`autoboot_boot_partition` /
     `autoboot_try_partition`) so subsequent installs target the
     correct partition
   - Clean `pv_rev.txt` on the now-committed partition to a single revision
   - Clear `pv_try` from `rpiab.txt`

5. **Fail** (`rpiab_fail_update`):
   - Clear `pv_try` from `rpiab.txt`
   - On next normal boot, Pi boots from the unchanged default partition

### No-Reboot Update

When the BSP (boot image) has not changed, pantavisor performs a
no-reboot update. The containers are swapped live without rebooting.

The problem: after a no-reboot update, `pv_rev.txt` on the try partition
must still be valid if a crash forces a reboot. Without tracking, the
partition would contain a stale revision that doesn't match `pv_done`.

Solution: `pv_rev.txt` accumulates a comma-separated list of revisions
across no-reboot updates on the same partition:

```
Install reboot rev 35:        pv_rev.txt = "35"
Install no-reboot rev 36:     pv_rev.txt = "35,36"
Install no-reboot rev 37:     pv_rev.txt = "35,36,37"
Crash + reboot:               validate checks pv_done ∈ {35,36,37} → OK
Commit (on next reboot):      pv_rev.txt = "37" (cleaned to single value)
```

**Overflow protection**: If the comma-separated list would exceed 511
bytes (FAT filename safe limit), the bootloader signals a forced reboot
instead of appending. This converts the no-reboot update into a reboot
update, resetting `pv_rev.txt` to a single fresh revision.

### Partition Globals Swap

After `rpiab_commit_update()` swaps `autoboot.txt`, it also swaps the
internal C globals `autoboot_boot_partition` and `autoboot_try_partition`.
This ensures that any subsequent install (e.g. a no-reboot update
immediately after a commit) targets the correct try partition.

Without this swap, the next install after a commit would DD the boot
image to the wrong partition (the one just committed to, rather than the
free one).

## Boot Validation

`rpiab_validate_state()` handles three scenarios:

### 1. Tryboot Active (`is_tryboot=1`)

The Pi booted from the try partition after an update:

- Read `pv_rev.txt` from the booted partition
- Verify `pv_try` appears in the comma-separated list
- If valid: use `pv_try` as the running revision
- If mismatch: boot failure (return -1)

### 2. Normal Boot with `pv_try` Set

A previous tryboot failed and the Pi fell back to the default partition:

- The try partition's update failed; rolled back to the committed revision
- Use `pv_done` as the running revision
- Log a warning if `pv_rev.txt` doesn't match (expected during rollback)

### 3. Normal Boot, No `pv_try`

Clean boot with no pending update:

- Read `pv_rev.txt` from the booted partition
- Verify it matches `pv_done`
- If mismatch: boot failure

## EEPROM Version Requirements

The `tryboot_a_b` mode requires EEPROM firmware from 2022-11-25 or later
on Pi 4. All Pi 5 EEPROMs support it. The minimum version is checked
at init time (`RPIAB_MIN_TRYBOOT_VERSION = 1669334400`).

During updates, `rpiab` stages EEPROM firmware (`pieeprom.upd`,
`pieeprom.sig`, `recovery.bin`) to the bootsel partition for automatic
EEPROM updates on next boot.

## Configuration

The rpiab bootloader is selected by setting:

```
PV_BOOTLOADER_TYPE=rpiab
```

This is passed via the kernel command line and detected during early init.
