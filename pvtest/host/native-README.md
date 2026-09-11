# pvtest — native runner

The pvtest suites plus the tester scripts, with no container images. Use this
when you want to run the suites against a **real device** from a host that has
no container runtime.

The tester always runs on the host and reaches the board over SSH (`exec=`) and
its pvr HTTP endpoint (`ip=`), so nothing here is architecture-bound. Only the
example container tarballs the tests deploy are, and those are not shipped in
this tarball — you install your board's own.

For the appengine pool (the `local/` suites against throwaway containers) use
`test.docker.sh` from the full distro tarball instead. Its targets *are*
containers, so it needs a container runtime.

## Layout

```
pvtest/             pvtest-run, utils, common   the tester half
                    host-common                 shared with test.docker.sh
                    bin/pvr                     static pvr for this arch
local/  remote/     the suites
targets/            per-target container tarballs (starts empty)
test.native.sh      the runner
device.txt          device manifest template
```

## Host dependencies

`./test.native.sh check` verifies all of this and prints what is missing.

Nothing from pantavisor is needed on the host: with a device manifest every
target command is forwarded through `exec=`, so `pvcontrol`, `pventer`,
`pvcurl` and `pvtx` run **on the board**, not here.

### Alpine

```sh
apk add bash jq curl openssh-client coreutils sed util-linux-misc flock tar \
        findutils grep gawk diffutils
```

(no `pvr` — it ships in this tarball, see below)

Busybox applets are not enough for four of these, which is why the list is
explicit:

| Needed | Why busybox will not do |
|---|---|
| `coreutils` | `timeout --foreground`, used for every forwarded command and to bound each test |
| `sed` | `sed -u`, used to stream the serial console into `<device>.log` |
| `util-linux-misc` | provides `script`, which wraps every test script (and `unshare`, for the legacy fallback below) |
| `flock` | separate package on Alpine; guards the device lock and the run queue |

`findutils`, `grep`, `gawk` and `diffutils` are listed because the summary and
the golden diffing are only exercised against the GNU versions; the busybox
applets may well work.

### Debian / Ubuntu

```sh
apt install bash jq curl openssh-client coreutils sed util-linux tar \
            findutils grep gawk diffutils
```

All present on a default install; `jq` and `curl` are the usual gaps.

### pvr

The one dependency no distro packages. **It ships in this tarball** as
`pvtest/bin/pvr`, built static with CGO off: no ELF interpreter, so the same
binary runs on glibc and musl hosts alike.

It is built for **this tarball's architecture**, so use the tarball matching the
host that runs the tester — `pantavisor-pvtest-scripts-docker-x86_64.tar.gz` on
an x86_64 runner, `-docker-armv8` on an arm64 one. A `pvr` on `PATH` always
wins; the bundled one is used only if it actually executes here, and `check`
says which is in play:

```
INFO -- pvr: /usr/bin/pvr (host)
INFO -- pvr: /path/pvtest/bin/pvr (bundled, static)
ERROR -- bundled pvr at ... does not run here (wrong architecture?)
```

### Tests' own tools

The suites themselves shell out to `jq`, `curl`, `sed`, `grep`, `awk`,
`sha256sum`, `date` and `nc`. All but `nc` are covered above; add
`netcat-openbsd` (Debian) or busybox's applet (Alpine) if a test needs it.

### Namespaces (legacy runners only)

`pvtest-run` locates `utils`/`common` through `PVTEST_LIBDIR` and derives test
ids by stripping `PVTEST_ROOT`. When the shipped runner has both — anything
built from a pantavisor that carries them — the run is plain native, no
namespaces involved.

Against an older runner that hardcodes `/usr/share/pantavisor/pvtest` and
`/work`, `test.native.sh` falls back to a private user+mount namespace: it
overlays `/usr/share`, binds the scripts into place and binds the suites at
`/work`, leaving no trace on the host. That needs unprivileged user namespaces
enabled and an existing `/work` directory (`sudo mkdir /work` once).

## Setup

Copy the device manifest template, fill it in, and drop it in the host's pvtest
config dir — a manifest describes a workstation's board, not a workspace:

```sh
mkdir -p ~/.config/pvtest/devices
cp device.txt ~/.config/pvtest/devices/rock5a.txt
$EDITOR ~/.config/pvtest/devices/rock5a.txt
```

`device.txt` documents every key. `name=`, `ip=`, `exec=` and `tty=` are
required. Without a `setbootconfig=` the board is bound as it is and any test whose
`config.env` it does not already satisfy is SKIPPED — that is by design, so run
without `--fail-on-skip` until each test's `"devices"` array is triaged.

Then install container tarballs built for the board's MACHINE. The target name
is the manifest's `type=`:

```sh
./test.native.sh install-tarballs radxa-rock5a <dir-or-tarball>...
```

## Running

```sh
./test.native.sh check                          # host readiness
./test.native.sh ls                             # list tests
./test.native.sh run local --device rock5a      # run a scope
./test.native.sh run local/lifecycle/foo --device rock5a
./test.native.sh run local/lifecycle/foo --device rock5a -o   # regenerate golden
./test.native.sh run local/lifecycle/foo --device rock5a -i   # tester shell
./test.native.sh run --device rock5a -m                       # shell on the board
./test.native.sh run remote --device rock5a --hub https://api.stage.pantahub.com
```

`--hub URL` (or `PVTEST_HUB_URL`, default `https://api.pantahub.com`) selects the
Hub; `PH_USER`/`PH_PASS` must be an account on it.

Results land in the workspace printed at the start of the run (`-w` to choose
it): `run.log`, `results/<test>/test.log`, `results/<test>/diff`, and the serial
capture in `<device>.log`. `workspace-README.md` in this tarball documents the
layout and the log format.

`install-scripts [prefix]` is available if you want `pvtest-run` on `PATH`
system-wide (default prefix `/usr/local`); `run` does not need it — it uses the
copies in `pvtest/`.
