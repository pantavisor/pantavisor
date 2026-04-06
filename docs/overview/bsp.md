---
nav_order: 3
---
# BSP

In addition to [containers](containers.md), Pantavisor is in charge of the life-cycle of the Linux kernel, modules and firmware. To allow upgrading all this plus Pantavisor itself, all these binaries have been included under the BSP denomination in the [state JSON](../../../reference/legacy/pantavisor-state-format-v2.md#bsprunjson). 

## Pantavisor

The Pantavisor binary and dependency tree are part of the revision BSP in the state JSON.

### Addons

Additional files can be [added](../../../reference/legacy/pantavisor-state-format-v2.md#bsprunjson) to Pantavisor initrd rootfs without having to do it during compile time.

It is important to remark that the binary file has to be under cpio.xz4 compression. That is, cpio.xz with 4 Byte alignment. You can take a look at how we do the cpio.xz4 compression at [this example](https://gitlab.com/pantacor/pantavisor-addons/gdbserver). For the rest of gdbserver installation and use, go [here](../../../debug-pantavisor.md).

## Linux Kernel

The Linux Kernel, modules and firmware are also part of the revision BSP of the state JSON.

### Managed Drivers

Pantavisor offers a [declarative way](../../../reference/legacy/pantavisor-state-format-v2.md#bspdriversjson) to define a list of drivers at BSP level, each driver being just a set of Kernel modules. Parameters for Kernel loading are supported too by mapping drivers to [device or user metadata](storage.md#metadata).

The modules that are part of a driver will only be loaded if referenced from a [container](containers.md#drivers). Therefore, the loading order of the drivers will depend on their [start up order](containers.md#groups).

## Bootloader

To natively run Pantavisor on a device, it is necessary to have some on-disk artifacts that fall out of the umbrella of Pantavisor [revisions](revisions.md). This is the case of the bootloader, which will load the Linux kernel and directly execute the initrd (Pantavisor) after that. Both the bootloader and Pantavisor will interact with [Pantavisor storage](storage.md) to communicate with each other so the bootloader kwnows where to find the artifacts to boot.

We support a number of boards, using both U-Boot and GRUB bootloaders. These include all the bring up mechanisms that is necessary to run Pantavisor in its minimal form. You can take a look at the supported boards [here](../../../initial-devices.md). [Contact us](https://community.pantavisor.io) if you need support for your board!

In regards of how the interaction with the bootloader is done, Pantavisor can be set up to different modes using the `PV_BOOTLOADER_TYPE` [config key](../../../reference/legacy/pantavisor-configuration.md):

* [uboot](#uboot)
* [uboot-ab](#uboot-ab)
* [rpiab](#rpiab)
* [grub](#grub)

### uboot

In this mode, both Pantavisor and U-Boot will write and read to and from a file in [storage](storage.md) that contains the revision information that U-Boot needs so it can boot up at any time. With that information, Kernel and initrd will be loaded from that same [storage](storage.md) by U-Boot.

### uboot-ab

This mode is similar to [uboot](#uboot) but it will use [fit images](https://github.com/devicetree-org/devicetree-specification) stored in two mtd partitions so the Kernel can be loaded in a faster manner by the bootloader. The selection of the partition to be booted is done by Pantavisor using U-Boot env variables, as well as the writing of the Kernel images in each partition.

This mode can be tuned up with the following [config keys](../../../reference/legacy/pantavisor-configuration.md):

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
