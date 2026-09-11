---
title: "Testing"
sidebar_position: 0
description: "The pvtest integration suite: architecture, running it against containers or real hardware, and authoring new tests."
---

# Testing

pvtest is Pantavisor's integration test framework. One suite that runs against two kinds of
targets, a pool of **appengine** containers on the host, or a **real device** over the network.

1. [The pvtest Harness](pvtest-harness.md): test architecture, execution models, flow and where
   the code lives.
2. [Running Against Appengine and Authoring pvtests](appengine.md): running tests against a
   pool of appengine instances, debugging tests that fail, adding new tests and containers
   along authoring rules.
3. [Running Against a Real Device](device.md): running tests against real devices with the help
   of the device manifest, hook scripts, architecture specific test containers and pvs signing.
4. [Running Without a Container Runtime](native.md): natively running tests for driving tests
   from a host without Docker.
5. [pvtest List](pvtest-list.md): test to do list.

## Getting a distro to run

Building the appengine distro tarball is a Yocto build and stays in meta-pantavisor:
[Building the pvtest distro](../../meta-pantavisor/overview/testing/automated/index.md). Every page
here starts from an already-built distro.
