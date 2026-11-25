---
title: "Running Against Appengine"
sidebar_position: 5
description: "Running tests against a pool of appengine instances and debugging tests that fail."
---
# Running Against Appengine

This page covers running the suite against the pool and debugging a failure. To learn
how the framework itself works, see [this](pvtest-harness.md). To write tests, see
[authoring.md](authoring.md). To run
the tests against real hardware, go [here](device.md) if you can use a containerized
runtime or [here](native.md) if that is not the case.

## Running tests

From an [installed distro](install.md), the tarball-included `README.md` has ready-made
examples for running the tests. `./test.docker.sh -h` lists every command, flag, path
selector and environment override.

## Debugging a failing test

Every run creates a workspace with a `README.md` inside that documents the full layout,
the log format and its sources, the useful greps, and how to read valgrind output.
Besides that, pvtest provides interactive and manual modes for the appengine target.

Interactive mode (`-i`) opens a console in the tester container and, in parallel, starts
an appengine container instance. From that console, the device is reachable and the full
test script can be run by hand.

Manual mode (`-m`) opens a console in the appengine container itself without starting
Pantavisor, which is handy to start Pantavisor by hand when it crashes or fails to reach
READY.
