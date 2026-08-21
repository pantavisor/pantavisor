---
title: "Configuration Levels"
sidebar_position: 12
---
# Configuration Levels

:::note
The configuration syntax is common for all levels, but not all levels support the same keys. Our [reference](../reference/pantavisor-configuration.md) contains the list of keys and the allowed levels for each one.
:::

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

Configuration file for [Pantavisor](pantavisor-architecture.md). It can only be changed at [build time](../../meta-pantavisor/overview/get-started.md).

## pantahub.config

[Build time](../../meta-pantavisor/overview/get-started.md) configuration file for Pantavisor built-in [Pantacor Hub client](remote-control.md#pantacor-hub).

## Policies

Policies are added at build time from the [vendor skel directory](../../meta-pantavisor/overview/get-started.md), but loaded during boot up time.

To select a policy among the installed ones, we need to set its name to the `PV_POLICY` key either from [pantavisor.config](#pantavisorconfig) or [environment variables](#environment-variables).

## OEM

For setups where we want to modify the configuration based on device [updates](updates.md), we offer the possibility to attach a configuration file to a [revision](revisions.md). This way, the configuration values travel with the revision like any other artifact: they can be changed with a regular update, are covered by the same rollback guarantees, and do not require rebuilding the Pantavisor image.

### How it works

Every time a revision is started (after boot up or a device [update](updates.md)), Pantavisor searches [inside the revision](../reference/pantavisor-state-format-v2.md#1-root-level-statejson) for a configuration file at:

```
<PV_OEM_NAME>/<PV_POLICY>.config
```

The two keys that define this location are set at the [pantavisor.config](#pantavisorconfig), [environment variables](#environment-variables) or [policies](#policies) levels:

| Key | Default | Effect on the OEM level |
|-----|---------|-------------------------|
| `PV_OEM_NAME` | empty | Name of the directory that contains the file. If not set, the OEM level is disabled and no file is loaded |
| `PV_POLICY` | empty | Name of the file. If not set, the file name falls back to `default.config` |

For example, with `PV_OEM_NAME=myoem` and `PV_POLICY` unset, Pantavisor will load `myoem/default.config` from the revision. With `PV_POLICY=production`, it will load `myoem/production.config` instead. This means a single revision can ship one configuration file per [policy](#policies), and each device will pick the one matching its installed policy.

If `PV_OEM_NAME` is set but the revision does not contain the file, an informative message is printed in the logs and startup continues normally.

The file uses the same `key=value` syntax as [pantavisor.config](#pantavisorconfig). Its values are applied at the OEM level, so they overwrite [pantavisor.config](#pantavisorconfig), [pantahub.config](#pantahubconfig) and [policies](#policies), but can still be overwritten by [cmdline](#cmdline), [environment variables](#environment-variables), [user metadata](#user-metadata) and [commands](#commands). Only the keys allowed at the OEM level will be accepted, while the rest will be ignored with a warning in the logs. Our [reference](../reference/pantavisor-configuration.md#levels) contains the list of keys that can be set at this level.

### How to set it up

First, set the OEM name in one of its allowed levels. The typical choice is [pantavisor.config](#pantavisorconfig) at [build time](../../meta-pantavisor/overview/get-started.md):

```
PV_OEM_NAME=myoem
```

Then, attach the configuration file to the revision from a [pvr](https://docs.pantahub.com/pvr/) checkout of your device:

```bash
mkdir myoem
cat > myoem/default.config << EOF
PH_METADATA_DEVMETA_INTERVAL=30
PH_METADATA_USRMETA_INTERVAL=30
EOF
pvr add .
pvr commit
pvr post
```

After the device runs the new revision, the overridden values can be verified with [pvcontrol](local-control.md#pvcontrol), which reports the level each key was last modified at:

```bash
$ pvcontrol conf ls
...
{
  "key": "PH_METADATA_USRMETA_INTERVAL",
  "value": "30",
  "modified": "oem config"
}
...
```

:::note
If [state signature](storage.md#state-signature) validation is enabled, the OEM configuration directory, like the BSP one, can only be secured by a certificate that is validated against the default root certificate. Signatures whose certificate subject CN matches `PV_OEM_NAME` are validated against the OEM root certificate instead, and cannot include any artifact from those two directories. See the [certificate chain of trust](storage.md#certificate-chain-of-trust) for more information.
:::

## cmdline

:::warning
This method is _DEPRECATED_ but still supported for backwards compatibility reasons. It is recommended to use [env variables](#environment-variables) instead.
:::

Right after loading the [configuration files](#pantavisorconfig), Pantavisor reads `/proc/cmdline` in search for `key=value` pairs that use the prefix `ph_` or `pv_`. This can be done from the [bootloader console](../../meta-pantavisor/getting-started/operate/device-access/serial-port.md).

## Environment Variables

Linux environment variables can be used to configure Pantavisor. To do that, the rules to set env variables have to be followed:

* Use `key=value` format
* Do not use `.`
* If ` ` characted is needed, you can escape them by using `"` between the config item. For example: `"PV_SYSCTL_KERNEL_CORE_PATTERN=|/lib/pv/pvcrash --skip"`.

These variables need to be set during boot time, and setting them after that will have no effect on Pantavisor. This can be achieved from the [bootloader console](../../meta-pantavisor/getting-started/operate/device-access/serial-port.md).

## User Metadata

:::note
If the [user metadata volume](../reference/pantavisor-state-format-v2.md#4-infrastructure-devicejson) is assigned to a permanent volume, as it is by default, these changes will persist over device reboots.
:::

[User metadata](storage.md#user-metadata) can be used to override any of the previously presented configuration mechanisms.

There is a number of ways of setting user metadata, depending on the device management method choice. Go to our [how-to use Pantavisor guide](../../meta-pantavisor/getting-started/operate/device-access/index.md) for more information.

## Commands

:::note
It is important to notice that these changes will not persist after a device reboot in any case.
:::

The [Pantavisor control socket](local-control.md), or consequently the [PVControl tool](local-control.md#pvcontrol), offers another way to change a very limited subset of configuration values. Specifically, using the [command](../reference/pantavisor-commands.md#commands) endpoint.
