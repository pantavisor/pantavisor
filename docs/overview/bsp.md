---
title: "BSP"
sidebar_position: 3
description: "Board Support Package: kernel, modules, firmware, and the supported bootloaders."
---
# BSP

In addition to [containers](containers.md), Pantavisor is in charge of the life-cycle of the Linux kernel, modules and firmware. To allow upgrading all this plus Pantavisor itself, all these binaries have been included under the BSP denomination in the [state JSON](../reference/pantavisor-state-format-v2.md#2-bsp-bsprunjson). 

## Pantavisor

The Pantavisor binary and dependency tree are part of the revision BSP in the state JSON.

### Addons

Additional files can be [added](../reference/pantavisor-state-format-v2.md#2-bsp-bsprunjson) to Pantavisor initrd rootfs without having to do it during compile time.

It is important to remark that the binary file has to be under cpio.xz4 compression. That is, cpio.xz with 4 Byte alignment. You can take a look at how we do the cpio.xz4 compression at [this example](https://gitlab.com/pantacor/pantavisor-addons/gdbserver). For the rest of gdbserver installation and use, go [here](../../meta-pantavisor/getting-started/troubleshooting/index.md).

## Linux Kernel

The Linux Kernel, modules and firmware are also part of the revision BSP of the state JSON.

### Kernel requirements

Porting to a board with an existing, booting kernel doesn't guarantee it can
run Pantavisor's [container](containers.md) and
[storage](storage.md) layers. At minimum the kernel config needs:

- **Namespaces and cgroups** (`CONFIG_NAMESPACES`, `CONFIG_CGROUPS`, plus the
  `CONFIG_CGROUP_*`/`CONFIG_MEMCG`/`CONFIG_CPUSETS` subsystems) — required by
  [LXC](../../meta-pantavisor/overview/glossary.md#lxc) for container
  isolation.
- **`CONFIG_OVERLAY_FS`** — used for the container config-overlay mechanism
  (see [Containers](containers.md)).
- **`CONFIG_SQUASHFS`** (plus `CONFIG_SQUASHFS_LZ4`/`CONFIG_SQUASHFS_ZSTD` if
  using those compressors) — every container rootfs is a squashfs image.
- **Device-mapper** (`CONFIG_DM_CRYPT`, `CONFIG_DM_VERITY`) — only if you use
  the `dm-crypt`/`dm-verity`
  [`PANTAVISOR_FEATURES`](../../meta-pantavisor/overview/meta-pantavisor.md#pantavisor_features),
  which are on by default in `meta-pantavisor`'s standard configuration.

Check what your kernel already has with `zcat /proc/config.gz | grep -E
'NAMESPACES|CGROUP|OVERLAY_FS|SQUASHFS|DM_CRYPT|DM_VERITY'` on a board
that's already booting a similar kernel version, since exact defaults vary
by kernel version and vendor BSP.

### Managed Drivers

Pantavisor offers a [declarative way](../reference/pantavisor-state-format-v2.md#3-drivers-bspdriversjson) to define a list of drivers at BSP level, each driver being just a set of Kernel modules. Parameters for Kernel loading are supported too by mapping drivers to [device or user metadata](storage.md#metadata).

The modules that are part of a driver will only be loaded if referenced from a [container](containers.md#drivers). Therefore, the loading order of the drivers will depend on their [start up order](containers.md#groups).

## Bootloader

To natively run Pantavisor on a device, it is necessary to have some on-disk artifacts that fall out of the umbrella of Pantavisor [revisions](revisions.md). This is the case of the bootloader, which will load the Linux kernel and directly execute the initrd (Pantavisor) after that. Pantavisor and the bootloader communicate through [storage](storage.md): Pantavisor is solely responsible for writing the target revision into the bootloader environment; the bootloader only reads from it at boot time to locate the kernel and initrd to load.

We support a number of boards, using both U-Boot and GRUB bootloaders. These include all the bring up mechanisms that is necessary to run Pantavisor in its minimal form. You can take a look at the supported boards [here](../../meta-pantavisor/overview/supported-device.md). [Contact us](https://community.pantavisor.io) if you need support for your board!

In regards of how the interaction with the bootloader is done, Pantavisor can be set up to different modes using the `PV_BOOTLOADER_TYPE` [config key](../reference/pantavisor-configuration.md):

* [uboot](#uboot)
* [uboot-ab](#uboot-ab)
* [rpiab](#rpiab)
* [grub](#grub)

### uboot

In this mode, both Pantavisor and U-Boot will write and read to and from a file in [storage](storage.md) that contains the revision information that U-Boot needs so it can boot up at any time. With that information, Kernel and initrd will be loaded from that same [storage](storage.md) by U-Boot.

#### Where `pv_trying` is stored

While a new revision is being tried, U-Boot keeps a `pv_trying` marker so it can tell "already tried" from "first try" and fall back to `pv_rev` if the try never reached Pantavisor. Pantavisor clears it only when [devmode](devmode.md) re-arms a try; normal updates and rollbacks leave it to U-Boot. Where the marker lives depends on the board; `PV_BOOTLOADER_TRYING_ENV` tells Pantavisor which one:

| Setup | `PV_BOOTLOADER_TRYING_ENV` | Pantavisor clears `pv_trying` by |
|-------|----------------------------|----------------------------------|
| `pv.env` file on the boot partition (generic boot script on eMMC/SD) | `part:<n>:/pv.env`, set by the boot script | rewriting the file |
| U-Boot environment in flash, written by `saveenv` (generic boot script on UBI) | `mtd:<name>`, set by the BSP, for example `mtd:u-boot-env` | editing that key in the environment in place |
| `pv-env` MTD partition (legacy, raw `key=value` list) | not used | removing only `pv_trying` from the partition |
| `PV_BOOTLOADER_MTD_ONLY=1` (legacy, `PV_BOOTLOADER_MTD_ENV` partition holds all keys) | not used | removing only `pv_trying`; `pv_rev` and `pv_try` stay |

With `mtd:<name>` Pantavisor reads the first good erase block of the partition, finds the environment size by checking the CRC32 for each power-of-two size from 4 KiB up to the erase size, removes the exact key `pv_trying`, recomputes the CRC, erases and writes the block, and reads it back to verify. Every other key keeps its value and order. Pantavisor never wipes a partition that holds a U-Boot environment.

If the partition has no environment Pantavisor can edit, it logs at `INFO` and writes nothing, and the boot, update, rollback or re-arm carries on. This is the case for an erased partition, garbage, a CRC that matches no size, a read error and a missing partition: U-Boot has simply never run `saveenv` there. A redundant environment (two copies, flags byte) is detected and left alone with a warning.

To see what Pantavisor did with the environment, on the device:

```
grep uboot-mtd-env /storage/logs/0/pantavisor/pantavisor.log
```

### uboot-ab

This mode keeps the kernel as a [FIT image](https://github.com/devicetree-org/devicetree-specification) in two raw MTD partitions, `fitA` and `fitB` (NAND), so U-Boot can load it straight from flash. Pantavisor writes the FIT of an incoming revision into the partition that does not hold `pv_rev`, so the committed revision is never overwritten and a failed try falls back to it. U-Boot picks the partition to boot.

#### What U-Boot must do

The boot script reads the 4 KiB header of both partitions, boots the one whose `fit_rev` equals the revision it wants (`pv_try`, else `pv_rev`; no `pv_rev` means `0`), and falls back to `pv_rev` for a try it already attempted (`pv_trying`). When no partition matches, it boots `fitA`.

| Item | Value |
|------|-------|
| Header | at offset 0 of the partition, `fit_rev=<rev>\nfit_size=<bytes>\n`, NUL padded to 4096 bytes; `env import -t <addr> 0x1000` reads it |
| FIT | `fit_size` bytes at offset `0x1000` |
| Bad blocks | the partition is the sequence of its good erase blocks, as `nand read` sees it; the header sits at the start of the first good block |
| Revision match | exact: `fit_rev=1` does not match revision `10` |
| Headers without `fit_size` | written by older Pantavisor versions, still readable |

Inspect a partition on the device:

```
dd if=/dev/mtd4 bs=4096 count=1 2>/dev/null | strings
```

#### Updates

An update always writes the FIT of the new revision into the partition that does not hold `pv_rev`, even when the FIT did not change, and then sets `pv_try`. The write erases and programs only good blocks and fails, leaving the flash untouched, when header plus FIT do not fit in them. A failed write fails the update. Partitions are found by their exact name in `/proc/mtd`; `CONFIG_MTD_BLOCK` is not needed.

#### Configuration

This mode can be tuned up with the following [config keys](../reference/pantavisor-configuration.md); the `ENV` keys only matter for the `fw_setenv` path:

* `PV_BOOTLOADER_UBOOTAB_A_NAME`
* `PV_BOOTLOADER_UBOOTAB_B_NAME`
* `PV_BOOTLOADER_UBOOTAB_ENV_NAME`
* `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME`
* `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET`
* `PV_BOOTLOADER_UBOOTAB_ENV_SIZE`

### rpiab

This mode sets Pantavisor up to work with [tryboot_a-b for Raspberry Pi](https://www.raspberrypi.com/documentation/computers/config_txt.html#tryboot_a_b).

### grub

In this mode, both Pantavisor and GRUB will write and read to and from a file in [storage](storage.md) that contains the revision information that GRUB needs to boot up at any moment. With that information, Kernel and initrd will be loaded from that same [storage](storage.md) by GRUB.

## Reference

- [State Format → BSP](../reference/pantavisor-state-format-v2.md#2-bsp-bsprunjson) — every `bsp/run.json` field
- [State Format → Drivers](../reference/pantavisor-state-format-v2.md#3-drivers-bspdriversjson) — the `bsp/drivers.json` alias map
- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_BOOTLOADER_*` and `PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO`
