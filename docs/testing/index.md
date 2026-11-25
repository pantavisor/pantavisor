---
title: "Prototyping & Testing"
sidebar_position: 0
description: "Running Pantavisor on a host with the appengine distro: standalone appengine instances to prototype by hand, and the pvtest integration suite against appengine or real hardware."
---

# Prototyping & Testing

The appengine distro runs Pantavisor from a host, by hand or under the pvtest integration
suite. It covers four setups, from the simplest to the most complex:

| Setup | Pantavisor runs on | Driven by | Script | Tarball |
|---|---|---|---|---|
| Standalone appengine | one appengine container | you, by hand | `run.docker.sh` | appengine distro |
| pvtest + appengine | a pool of appengine containers | the tester, in a container | `test.docker.sh` | appengine distro |
| pvtest + device | a real device | the tester, in a container | `test.docker.sh --device` | appengine distro |
| native pvtest + device | a real device | the tester, on the host | `test.native.sh` | pvtest scripts |

1. [Installing the Appengine Distro](install.md): extracting the tarball, host dependencies
   and Docker images.
2. [The Standalone Appengine](appengine-standalone.md): how appengine is built, its
   lifecycle, workdir and where the code lives.
3. [Running a Standalone Appengine Instance](standalone.md): prototyping by hand on an
   appengine booted from a setup json, outside of any test run.
4. [The pvtest Harness](pvtest-harness.md): test architecture, execution models, flow,
   where the code lives and [what CI runs for each change](pvtest-harness.md#ci-coverage).
5. [Running Against Appengine](appengine.md): running tests against a pool of appengine
   instances and debugging tests that fail.
6. [Authoring pvtests](authoring.md): adding new tests and containers along authoring
   rules, and regenerating expected output.
7. [Running Against a Real Device](device.md): running tests against real devices with the
   help of the device manifest, hook scripts, architecture specific test containers and
   pvs signing.
8. [Running Without a Container Runtime](native.md): natively running tests for driving
   tests from a host without Docker.
9. [pvtest List](pvtest-list.md): test to do list.

## Getting a distro to run

Building the appengine distro tarball is a Yocto build and stays in meta-pantavisor:
[Building the appengine distro](../../meta-pantavisor/overview/testing/automated/index.md).
Every page here starts from an already-built distro, installed as in [install.md](install.md).
