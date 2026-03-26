---
nav_order: 11
---
# Init Mode

Pantavisor offers several [configurable](pantavisor-configuration.md#summary) init modes for convenience: embedded, standalone and appengine.

## Embedded Mode

This is the way Pantavisor was meant to be run. In this case, the bootloader will directly start up Pantavisor, which will run alongside a minimal rootfs with all its dependencies.

## Standalone Mode

This mode was created for debugging Pantavisor. It works the same way as _embedded_, with the bootloader starting Pantavisor up. The difference is Pantavisor will not launch any container or perform any of its regular [operations](pantavisor-architecture.md). To do so, Pantavisor has to be manually run from console inside of the device.

## App Engine mode

App Engine mode is meant for prototyping on already setup devices running any Linux distro. In this case, Pantavisor will run as a daemon that can be started from your init system or directly from console.

!!! Note
	You can get more information about how to run Pantavisor in our [how-to guides](choose-device.md).
