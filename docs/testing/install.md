---
title: "Installing the Appengine Distro"
sidebar_position: 1
description: "Extracting the appengine distro tarball, installing host dependencies and loading the Docker images."
---
# Installing the Appengine Distro

Everything on the following pages runs from an extracted
`pantavisor-appengine-distro-<machine>.tar.gz`: the pvtest suite against appengine or a
real device, and standalone appengine instances. This page sets up a host to run it.

## Getting the tarball

The [meta-pantavisor build](../../meta-pantavisor/overview/testing/automated/index.md)
deploys the tarball. Pick the `<machine>` that matches the host architecture: x86_64 or
arm64.

On the build machine, the deploy directory also holds an unpacked copy, named like the
tarball without `.tar.gz`. Run from there and skip the extraction.

## Extracting

The tarball has no top-level directory, so extract it into a fresh one:

```sh
mkdir pvtest && cd pvtest
tar -xzf /path/to/pantavisor-appengine-distro-<machine>.tar.gz
```

```
README.md           <- quick reference for running the suite
workspace-README.md <- layout of a finished run output
device.txt          <- device manifest template
test.docker.sh      <- the test runner
test.native.sh      <- the test runner without container runtime
run.docker.sh       <- standalone appengine instances
templates/          <- setup templates for run.docker.sh
images/             <- the docker images install-docker loads
local/  remote/     <- the suites
targets/<type>/     <- per target container tarballs
pvtest/             <- tester scripts, shared with the tester container
```

Every command on these pages runs from this directory.

## Host dependencies

On a fresh host (we only support Debian or Ubuntu, but other distros should be compatible
with changes):

```sh
./test.docker.sh install-deps
```

It installs Docker (keeping one already installed), `git`, `jq`, `iw`, `bc` and the
kernel extra modules, adds `$USER` to the `docker` group and loads the bundled images. On
x86_64 hosts it also sets up qemu binfmt. Log out and back in for the group change to
apply.

The runner calls `sudo -n` for a few commands while tests run. Allow them without a
password, once, with `sudo visudo`:

```
<user> ALL=(ALL) NOPASSWD: /sbin/losetup, /sbin/modprobe, /usr/sbin/iw, /bin/chmod
```

## Loading the images

After every new tarball, load its images:

```sh
./test.docker.sh install-docker
```

This loads the appengine, tester and netsim images tagged `latest`. For standalone
instances only, `./run.docker.sh install-deps` installs the same dependencies and
`./run.docker.sh install-docker` loads just the appengine image. To keep several
installs side by side on one Docker daemon, see
[image tags](../../meta-pantavisor/overview/testing/automated/index.md#install).

## Hub credentials

Remote tests and instances pointed at a Hub read the credentials from the environment:

```sh
export PH_USER=... PH_TOKEN=...
```

## Without Docker

For a host with no container runtime, the build also deploys
`pantavisor-pvtest-scripts-<machine>.tar.gz`, which only runs against real devices. See
[Running Without a Container Runtime](native.md).
:qa
