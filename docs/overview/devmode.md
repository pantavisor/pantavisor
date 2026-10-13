---
title: "Devmode"
sidebar_position: 17
description: "A fast edit loop on a device: write files into a running container without building a new revision."
---
# Devmode

Devmode lets a developer change the files of a container on a running device and see the result after a container restart, without building and installing a new revision for every edit. The container still runs as deployed: same root filesystem, same configuration, same group and restart policy.

## Enable devmode

Devmode is off by default. Turn it on with [`PV_DEVMODE_ALLOWED`](../reference/pantavisor-configuration.md#summary), for example through [user metadata](../reference/pantavisor-metadata.md#user-metadata) (the key is the variable name, as for any [configuration level](pantavisor-configuration-levels.md#user-metadata)):

```bash
pvcontrol usrmeta save PV_DEVMODE_ALLOWED true
```

With `PV_DEVMODE_ALLOWED=false`, a devmode revision is refused: `PUT /steps/devmode/...` and the `run` command for a devmode revision both return an error.

## Reference

- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_DEVMODE_ALLOWED`
