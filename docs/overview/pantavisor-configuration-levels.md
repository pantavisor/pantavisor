---
nav_order: 10
nav_title: Configuration
---
# Pantavisor Configuration

!!! Note
    The configuration syntax is common for all levels, but not all levels support the same keys. Our [reference](../../../reference/legacy/pantavisor-configuration.md) contains the list of keys and the allowed levels for each one.

There are several ways to set Pantavisor configuration, depending on when it can be modified in the [Pantavisor life cycle](pantavisor-architecture.md#state-machine). Bear in mind that not all configuration parameters will be available for all levels. Furthermore, each level will overwrite whatever is configured in the previous ones, following this order:

1. [pantavisor.config](#pantavisorconfig)
1. [pantahub.config](#pantahubconfig)
1. [Policies](#policies)
1. [OEM](#oem)
1. [cmdline](#cmdline)
1. [Environment Variables](#environment-variables)
1. [User Metadata](#user-metadata)
1. [Commands](#commands)

## pantavisor.config

Configuration file for [Pantavisor](pantavisor-architecture.md). It can only be changed at [build time](../../../reference/legacy/customize-build-pantavisor.md#config).

## pantahub.config

[Build time](../../../reference/legacy/customize-build-pantavisor.md#config) configuration file for Pantavisor built-in [Pantacor Hub client](remote-control.md#pantacor-hub).

## Policies

Policies are added at build time from the [vendor skel directory](../../../reference/legacy/customize-build-pantavisor.md#vendor), but loaded during boot up time.

To select a policy among the installed ones, we need to set its name to the `PV_POLICY` key either from [pantavisor.config](#pantavisorconfig) or [environment variables](#environment-variables).

## OEM

For setups where we want to modify the configuration based on device [updates](updates.md), we offer the possibility to attach a configuration file to a [revision](revisions.md).

Its location [inside the revision](../../../reference/legacy/pantavisor-state-format-v2.md#oem-configuration) will be defined by the [configuration](../../../reference/legacy/pantavisor-configuration.md) values of the keys `PV_OEM_NAME` and `PV_POLICY` from [pantavisor.config](#pantavisorconfig), [environment variables](#environment-variables) or [policies](#policies) levels.

## cmdline

!!! Warning
    This method is _DEPRECATED_ but still supported for backwards compatibility reasons. It is recommended to use [env variables](#environment-variables) instead.

Right after loading the [configuration files](#compile-time), Pantavisor reads `/proc/cmdline` in search for `key=value` pairs that use the prefix `ph_` or `pv_`. This can be done from the [bootloader console](../../../navigating-console.md#bootloader-console).

## Environment Variables

Linux environment variables can be used to configure Pantavisor. To do that, the rules to set env variables have to be followed:

* Use `key=value` format
* Do not use `.`
* If ` ` characted is needed, you can escape them by using `"` between the config item. For example: `"PV_SYSCTL_KERNEL_CORE_PATTERN=|/lib/pv/pvcrash --skip"`.

These variables need to be set during boot time, and setting them after that will have no effect on Pantavisor. This can be achieved from the [bootloader console](../../../navigating-console.md#bootloader-console).

## User Metadata

!!! Note
    If the [user metadata volume](../../../reference/legacy/pantavisor-state-format-v2.md#devicejson) is assigned to a permanent volume, as it is by default, these changes will persist over device reboots.

[User metadata](storage.md#user-metadata) can be used to override any of the previously presented configuration mechanisms.

There is a number of ways of setting user metadata, depending on the device management method choice. Go to our [how-to use Pantavisor guide](../../../choose-way.md) for more information.

## Commands

!!! Note
    It is important to notice that these changes will not persist after a device reboot in any case.

The [Pantavisor control socket](local-control.md#local-control), or consequently the [PVControl tool](local-control.md#pvcontrol), offers another way to change a very limited subset of configuration values. Specifically, using the [command](../../../reference/legacy/pantavisor-commands.md#commands) endpoint.
