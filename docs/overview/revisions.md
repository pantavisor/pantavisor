---
title: "Revisions"
sidebar_position: 2
description: "The revision as Pantavisor's unit of state, and the state JSON that makes it reproducible."
---
# Revisions

A revision is composed by a [BSP](bsp.md) (Pantavisor binary, Linux kernel, modules and firmware)
plus a number of [containers](containers.md).

In order to make revisions reproducible, they are defined in a state JSON. This JSON is a flat
representation of a set of either binary objects or other inline JSON documents: every key is a
path, and every value is either the SHA256 of a binary artifact or an inline JSON manifest.

```json
{
  "#spec": "pantavisor-service-system@1",
  "bsp/run.json": { "linux": "kernel.img", "initrd": "pantavisor", "modules": "modules.squashfs" },
  "bsp/kernel.img": "990f8b0fcab8b99f631497753cc55b70f6f522a1d91cd4ae0777a7747b98509e",
  "awconnect/run.json": { "#spec": "service-manifest-run@1", "name": "awconnect", "type": "lxc" },
  "awconnect/root.squashfs": "e1ddabe573021b48dd5d66d59593d94fbc57b7a2f85dac59628959ae6955d2e2"
}
```

The binary artifacts referenced by hash are the [objects](storage.md#trails-and-objects); because
they are content-addressed they can be shared between revisions, so an [update](updates.md) only
downloads what actually changed.

Installed revisions form a trail, which is what makes [rollback](updates.md#error) possible: the
previous revision's state JSON and objects are still on disk, so returning to it is a bootloader
decision rather than a download.

```bash
pvcontrol steps ls                 # every revision installed on the device
pvcontrol steps get current        # the running revision's state.json
```

## Reference

- [State Format](../reference/pantavisor-state-format-v2.md) — every root key and manifest, with a [complete example](../reference/pantavisor-state-format-v2.md#10-complete-example)
- [Control Socket → /steps](../reference/pantavisor-commands.md#steps) — installing and querying revisions
