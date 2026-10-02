---
title: "Running Against a Real Device Without a Containerized Tester"
sidebar_position: 4
description: "Natively running tests for driving tests from a host without Docker."
---
# Running pvtests Without a Container Runtime

`test.native.sh` is the native counterpart of `test.docker.sh`. It runs the
[pvtest](pvtest-harness.md) tester directly on the host instead of in a
[container](device.md). Use it to run the tests against a **real device** from a
workstation, lab runner or CI box that has no Docker runtime.

## Getting it

The [meta-pantavisor build](../../meta-pantavisor/overview/testing/automated/index.md)
deploys a slim companion to the [appengine](appengine.md) distro tarball, holding the
scripts and suites without the container images, named
`pantavisor-pvtest-scripts-<machine>.tar.gz`.

Its `README.md` covers host setup and running.

## Setup

### The device manifest

`device.txt` documents every key. Copy it, fill it in, uncomment.

You can find more details [here](device.md#the-device-manifest).

### The hook Scripts

A [`setbootconfig=`](device.md#the-setbootconfig-script) or a
[`flash=`](device.md#the-flash-script) script can be set in the manifest to adapt pvtest
framework to your device-specific needs.

### Building and Installing Target Tarballs

`targets/` starts empty, so you will need to
[build](device.md#building-target-tarballs) and
[install](device.md#installing-target-tarballs) them for your specific board.

### Host dependencies

`./test.native.sh check` and the package lists are in the `README.md`.

## Running

See the `README.md` included in the pvtest tarball install to learn how to run.

## Expected outcomes

The triage procedure in [device.md](device.md#expected-outcomes) applies unchanged.
