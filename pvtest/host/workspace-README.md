# Test Run Results

## Workspace Layout

```
<workspace>/
  run.log        <- aggregate output (host + tester) + SUMMARY
  <name>.log     <- console capture for <name> device
  README.md
  results/
    <tag>/<scope>/<category>/<name>/
      test.log   <- aggregate output per test (host + tester + worker)
      diff       <- golden output diff (expected vs actual). Only present when test fail
  storage/       <- appengine mode only (a real device keeps its own on-device storage)
    <tag>/<key>/ <- only in persistent model with appengine
      trails/ objects/ logs/ ...
    <tag>/<scope>/<category>/<name>/ <- only in volatile model with appengine
      trails/ objects/ logs/ ...
  valgrind/      <- only with appengine and -V
    <container>/ <-
      valgrind.log.<pid>
```

## Log Format

All structured log lines follow the pantavisor log convention:

```
[hostname] <epoch> LEVEL -- [source]: message
```

Sources: `test.docker.sh`, `pvtest-run`, `pv-appengine` and Pantavisor specific
sources.

To filter by source:

    grep '\[pvtest-run\]'   test.log    # pvtest-run messages only
    grep '\[pv-appengine\]' test.log    # pv-appengine messages only
    grep '\[ctrl\]'         test.log    # pantavisor ctrl module messages only
    grep 'WARN\|ERROR'      test.log    # all warnings and errors

### test.docker.sh

Host-side orchestrator. With `-v`, it  produces `set -x` traces, covering
container startup and network setup.

### pvtest-run

Inner test runner inside the tester container. Parses `test.json`, connects to
the worker via PVTEST_EXEC (SSH), then runs the test script. The test script
output is captured and diffed against the stored `output` file.

### pv-appengine

Pantavisor runtime launcher inside the appengine container. Sets up cgroups and
storage mounts, then runs the `pantavisor` binary in a restart loop (simulating
device reboots).

### Pantavisor specific sources

Enabled by default at appengine workers, needs to be set in the device manifest
for real devices `setbootconfig_base=PV_LOG_SERVER_OUTPUTS=filetree,stdout_direct`.

Some relevant Pantavisor modules: `core`, `ctrl`.

## run.log

General test.docker.sh run aggregate log (host + tester) plus a structured
result SUMMARY section at the end.

Log levels used in `run.log`:

| Level | When |
|-------|------|
| `DEBUG` | Test launch and workspace setup diagnostics |
| `INFO` | PASSED, ABORTED, SKIPPED |
| `ERROR` | FAILED |

One result line per test, with the diff inlined right after a failure:

```
[pvtest] 1748000000 INFO -- launching 'local/core/legacy-config-overload'
[pvtest] 1748000023 INFO -- 'local/core/legacy-config-overload' PASSED (23 s)
[pvtest] 1748000110 ERROR -- 'local/lifecycle/reboot-nonreboot-rollback' FAILED (110 s)
--- diff: local/lifecycle/reboot-nonreboot-rollback ---
-expected line
+actual line
--- end diff ---
[pvtest] 1748000110 INFO -- 'local/runtime/remount-policies' SKIPPED
```

A failure means the test output diverged from the golden output. Lines prefixed
with `-` are expected, lines prefixed with `+` are what the test produced. The
same diff is saved to `results/.../diff`. The launch line is printed before the
test starts, so parallel test timelines can be correlated by timestamp.

Quick scan for failures:

    grep ERROR run.log

## test.log

Per test aggregate log (host + tester + worker) interleaved stream.

## Valgrind Logs (appengine mode, -V)

Valgrind output is under `valgrind/<N>/valgrind.log.<pid>`. The main worker is typically
the largest file. Check with:

    grep -E "definitely lost|possibly lost|ERROR SUMMARY" valgrind/<N>/valgrind.log.<largest-pid>

- `definitely lost` — real leaks, investigate.
- `possibly lost` — typically PV buffer pools; consistent at ~3.7 MB, not a regression.
- `ERROR SUMMARY` — mostly `Syscall param` warnings from liblxc, not pantavisor code.
- No summary at the end of a file — the process was killed before valgrind could flush.
