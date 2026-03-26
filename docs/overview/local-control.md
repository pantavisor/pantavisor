---
nav_order: 8
---
# Local Control

With local control, we mean the control that is performed from one of the [containers](containers.md) running in the [revision](revisions.md) using the [control socket](pantavisor-commands.md), which offers an HTTP REST API to control and monitor Pantavisor.

This kind of control can be performed even if the device is already [claimed in Pantacor Hub](remote-control.md#pantacor-hub). It can also be the only option if you [disable remote control](pantavisor-configuration.md#summary) or if you install a [local revision](pantavisor-commands.md#steps) at any given time, which will interrupt Pantacor Hub remote control unless a [go remote command](pantavisor-commands.md#commands) is issued. This behavior can be avoided with the [remote always configuration](pantavisor-configuration.md#summary).

## Pantabox

[Pantabox](pvr-sdk/reference/pantabox.md) is the top level control tool that can be run inside of a [container](containers.md). It offers a [ncurses](https://invisible-island.net/ncurses/) user interface that lets you interact with Pantavisor (install new [revisions](revisions.md), exchange [metadata](storage.md#metadata), reboot or shutdown your device...).

It is included in [pvr-sdk](https://gitlab.com/pantacor/pv-platforms/pvr-sdk), our development platform that is included with the [initial devices](initial-devices.md). To get more info or try it out, [ssh your pvr-sdk container](inspect-device.md) and just type the command:

```
pantabox
```

Pantabox is built on top of [pvcontrol](#pvcontrol).

## pvcontrol

[pvcontrol](pvr-sdk/reference/pvcontrol.md) is the CLI control tool that communicates with [Pantavisor control socket](pantavisor-commands.md) using [cURL](https://curl.se/). As it is a [Pantabox](#pantabox) dependency, it generally gets advantage of the latest features of the control socket first.

It is also included in [pvr-sdk](https://gitlab.com/pantacor/pv-platforms/pvr-sdk), included with the [initial devices](initial-devices.md). To try it out, [ssh to your pvr-sdk container](inspect-device.md) and just type the command:

```
pvcontrol
```

## Other Local Controllers

In the end, [Pantabox](#pantabox) and [pvcontrol](#pvcontrol) are just HTTP clients that are making use of [Pantavisor control socket](pantavisor-commands.md).

If you want to take advantage of the local control in your own container, first make sure [mgmt role](containers.md#roles) is selected in your container. Then, consider importing Pantabox and/or pvcontrol into your container. Besides this option, you can always directly use [cURL](https://curl.se/) or any other HTTP client to attack the [control socket endpoints](pantavisor-commands.md).
