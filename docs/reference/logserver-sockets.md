---
title: "Log Sockets"
sidebar_position: 6
description: "Logserver Unix socket paths and message formats."
---

# Pantavisor Log Sockets

**Overview:** [Storage → Logs](../overview/storage.md#logs) explains how the log server fits together,
how containers are expected to log, and what each sink is for.

| Socket | Path | Type | Created | Removed |
|--------|------|------|---------|---------|
| [`pv-ctrl-log`](#pv-ctrl-log) | `<PV_SYSTEM_RUNDIR>/pv-ctrl-log` | `SOCK_STREAM` | Log server start | Log server stop |
| [`pv-fd-log`](#pv-fd-log) | `<PV_SYSTEM_RUNDIR>/pv-fd-log` | `SOCK_STREAM` | Log server start | Log server stop |
| [`log.sock`](#devlog) | `<PV_SYSTEM_RUNDIR>/pv-plat-log/<container>/log.sock`, bind-mounted at `/dev/log` in the container | `SOCK_DGRAM`, mode `0666` | Container start, when [`dev-log`](#per-container-control) allows it | Container stop, or a failed start |
| [`/dev/log`](#devlog) | `/dev/log` (Pantavisor's own) | `SOCK_DGRAM`, mode `0666` | Log server start, when [`PV_LOG_AUTO_DEVLOG`](pantavisor-configuration.md#summary) is enabled | Closed at log server stop; the socket file is left in place |

`<PV_SYSTEM_RUNDIR>` is set by [`PV_SYSTEM_RUNDIR`](pantavisor-configuration.md#summary) (default `/pv`).

## Protocol detection

`pv-ctrl-log` and every `/dev/log` socket accept the same protocols. The parser is picked per message,
trying each row in order:

| First bytes | Protocol |
|-------------|----------|
| `<NNN>1 …` (digit `1` right after the closing `>`) | [RFC 5424](#rfc-5424) |
| `<NNN>…` (any other character after the closing `>`) | [RFC 3164](#rfc-3164) |
| Valid JSON object | [JSON](#json-protocol) |
| Only `level=`/`src=`/`message=` pairs, all three present | [Key-Value](#key-value-protocol) |
| Binary `struct pv_ls_msg` | [Legacy binary](#legacy-protocol-code--0) |

A message that matches a protocol but fails to parse is dropped with a `WARN`.

## Platform attribution

The platform is the folder name under the log directory.

| Protocol | Received on | Platform |
|----------|-------------|----------|
| Legacy binary | any | The `platform` field of the message |
| RFC 3164, RFC 5424, JSON, Key-Value | a container's `log.sock` | The container owning the socket |
| RFC 3164, RFC 5424, JSON, Key-Value | Pantavisor's `/dev/log` | `pantavisor` |
| RFC 3164, RFC 5424, JSON, Key-Value | `pv-ctrl-log` | The sender's cgroup; `unknown-platform` if it cannot be resolved |

## Log levels

| Level | Legacy value | JSON / Key-Value `level` |
|-------|--------------|--------------------------|
| FATAL | `0` | `FATAL` |
| ERROR | `1` | `ERROR` |
| WARN | `2` | `WARN` |
| [WALL](#console-alerts) | `3` | `WALL` |
| INFO | `4` | `INFO` |
| DEBUG | `5` | `DEBUG` |
| TRACE | `6` | `TRACE` |

:::note
`WALL` was added at `3`, so `INFO`/`DEBUG`/`TRACE` moved up by one (previously `3`/`4`/`5`).
Senders that hardcode the old numeric levels must update.
:::

JSON and Key-Value level names are case-insensitive. `ALL` is valid for
[`PV_LOG_LEVEL`](pantavisor-configuration.md#summary) but not as a message level: such a message is
dropped.

## pv-ctrl-log

Stream socket for sending log messages. Accepts every protocol in
[Protocol detection](#protocol-detection).

### Legacy Protocol (code = 0)

```C
struct pv_ls_msg {
    int code;
    int len;
    char buf[0];
};
```

| Field | Value |
|-------|-------|
| `code` | `0` LEGACY; `256` CMD, internal, rejected unless sent by Pantavisor's PID |
| `len` | Length of `buf` |
| `buf` | `level\0platform\0source\0data` |

| `buf` part | Content |
|------------|---------|
| `level` | Legacy value from [Log levels](#log-levels), as a string (`"4"` for INFO) |
| `platform` | Container name or `pantavisor` |
| `source` | Log source, e.g. a process or module name |
| `data` | Message text |

### JSON Protocol

Sent as-is, not wrapped in `pv_ls_msg`.

```json
{ "version": "0", "level": "INFO", "src": "myapp", "message": "Connection established" }
```

| Field | Required | Value |
|-------|----------|-------|
| `version` | Yes | `"0"`; any other value is rejected |
| `level` | Yes | A name from [Log levels](#log-levels) |
| `src` | Yes | Log source |
| `message` | Yes | Message text |

### Key-Value Protocol

Sent as-is, not wrapped in `pv_ls_msg`.

```
level=INFO src=myapp message="hello world"
```

| Key | Required | Value |
|-----|----------|-------|
| `level` | Yes | A name from [Log levels](#log-levels) |
| `src` | Yes | Log source |
| `message` | Yes | Message text |

Keys can come in any order. There is no `version` key. An unquoted value ends at the first whitespace,
so quote any value containing spaces; `\"` escapes a quote inside a quoted value.

## pv-fd-log

Hands a file descriptor to Pantavisor, which then polls it and logs what it reads.

### Subscription Protocol

Send with `sendmsg`, passing the file descriptor as `SCM_RIGHTS` and a 4-element `iovec`:

| iov Index | Type | Max Length | Description |
|-----------|------|------------|-------------|
| `iov[0]` | string | 50 bytes | Platform name (container name) |
| `iov[1]` | string | 50 bytes | Source name (e.g. `stdout`) |
| `iov[2]` | int | 4 bytes | Log level for messages from this FD |
| `iov[3]` | int | 4 bytes | Action: `1` subscribe, `0` unsubscribe |

| Action | `SCM_RIGHTS` fd | Effect |
|--------|-----------------|--------|
| Subscribe (`1`) | The fd to poll | Polled into `<PV_LOG_DIR>/<revision>/<platform>/`, path per [Filetree paths](#filetree-paths). Replaces any fd already subscribed for the same platform/source pair |
| Unsubscribe (`0`) | Can be `-1` | Stops polling and closes Pantavisor's copy of the fd for that platform/source pair |

## /dev/log

Per-container datagram socket, listed in the table at the top of this page. Accepts every
protocol in [Protocol detection](#protocol-detection); RFC 3164 and RFC 5424 need no configuration.

| Condition | Result |
|-----------|--------|
| Container name empty, `.`, `..`, or containing `/`, `\` or `"` | No socket; Pantavisor logs a `WARN` |

### Per-container control

Set `dev-log` in `<container>/run.json` to override
[`PV_LOG_AUTO_DEVLOG`](pantavisor-configuration.md#summary) for that container:

```json
{
  "#spec": "service-manifest-run@1",
  "dev-log": true
}
```

| `PV_LOG_AUTO_DEVLOG` | `dev-log` | Container gets `log.sock` and `/dev/log` |
|----------------------|-----------|------------------------------------------|
| `1` (default) | not set | Yes |
| `1` | `true` | Yes |
| `1` | `false` | No |
| `0` | not set | No |
| `0` | `true` | Yes |
| `0` | `false` | No |

### RFC 3164

```
<PRI>Mmm dd HH:MM:SS HOSTNAME APP[PID]: message
<34>May 15 16:48:18 mydevice myapp[1234]: Connection established
```

| RFC 3164 field | Pantavisor attribute | Notes |
|----------------|----------------------|-------|
| `PRI` severity bits | `lvl` | See [Priority and Facility](#priority-and-facility) |
| Timestamp | `time` | `strptime("%b %d %H:%M:%S")` |
| `HOSTNAME` | — | Discarded |
| `APP` | `src` | `[PID]` suffix stripped; `unknown-app` if missing |
| Message text | log data | Everything after `APP[PID]: ` |
| — | `plat` | See [Platform attribution](#platform-attribution) |

### RFC 5424

```
<PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED-DATA MSG
<34>1 2026-05-15T16:48:18Z mydevice myapp 1234 - - Connection established
```

| RFC 5424 field | Pantavisor attribute | Notes |
|----------------|----------------------|-------|
| `PRI` severity bits | `lvl` | See [Priority and Facility](#priority-and-facility) |
| `TIMESTAMP` | `time` | `strptime("%Y-%m-%dT%H:%M:%S")`; fractional seconds dropped; nil (`-`) → current time |
| `HOSTNAME` | — | Discarded |
| `APP` | `src` | `unknown-app` if missing |
| `PROCID`, `MSGID`, `STRUCTURED-DATA` | — | Accepted, not stored |
| `MSG` | log data | Everything after `STRUCTURED-DATA` |
| — | `plat` | See [Platform attribution](#platform-attribution) |

### Priority and Facility

`PRI = facility × 8 + severity`

| Severity | syslog name | Pantavisor level |
|----------|-------------|------------------|
| 0 | EMERG | FATAL |
| 1 | ALERT | FATAL |
| 2 | CRIT | ERROR |
| 3 | ERR | ERROR |
| 4 | WARNING | WARN |
| 5 | NOTICE | INFO |
| 6 | INFO | INFO |
| 7 | DEBUG | DEBUG |

| Facility code | Name | Description |
|---------------|------|-------------|
| 0 | `kern` | Kernel messages |
| 1 | `user` | User-level messages |
| 3 | `daemon` | System daemons |
| 16 | `LOCAL0` | Recommended for container applications |

## Log server outputs

Set with [`PV_LOG_SERVER_OUTPUTS`](pantavisor-configuration.md#summary), a comma-separated list; sinks
combine freely and unknown tokens are dropped with a warning. See
[Output types](../overview/storage.md#output-types) for when to use each.

| Value | Destination |
|-------|-------------|
| `filetree` | One file per source under `<PV_LOG_DIR>/<revision>/<container>/`. Default |
| `singlefile` | All logs as JSON lines in `<PV_LOG_DIR>/<revision>/pv.log` |
| `stdout` | Standard output, processed by the log server |
| `stdout.pantavisor` | Standard output, Pantavisor's own messages only |
| `stdout.containers` | Standard output, container messages only |
| `stdout_direct` | Standard output, bypassing the log server. Also auto-enabled before the server starts and after it stops, and always passes FATAL through |
| `nullsink` | `/dev/null` |

### Filetree paths

How `filetree` turns a message's `src` into a path under `<PV_LOG_DIR>/<revision>/<container>/`,
for any protocol. Leading and trailing `/` are stripped first.

| `src` after stripping | Stored at |
|-----------------------|-----------|
| No `/` (e.g. `myapp`, from `/myapp/`) | `<container>/syslog/<src>` |
| Contains `/` (e.g. `lxc/console.log`) | `<container>/<src>` |
| Empty, `..`, or containing `../` or `/..` | `<container>/syslog/unknown-src` |
| Any, when the [platform](#platform-attribution) is `pantavisor` | `pantavisor/pantavisor.log`; `src` is not used |

Only `filetree` builds paths from `src`; `singlefile` and the `stdout*` sinks store it as a field.

## Console alerts

Pantavisor's own messages mirrored to `/dev/console`, one line each; enabled by default.
Overview: [Storage → Console alerts](../overview/storage.md#console-alerts).

| Action | Setting |
|--------|---------|
| Disable at boot | [`PV_LOG_CONSOLE_ALERTS`](pantavisor-configuration.md#summary)`=0` |
| Disable at runtime | `pvcontrol usrmeta save PV_LOG_CONSOLE_ALERTS 0` — applies from the next message |
| Revert to the boot value | `pvcontrol usrmeta delete PV_LOG_CONSOLE_ALERTS` |

### Line format

```
[    6.217276] [PANTAVISOR] [platforms] WALL: platform 'awconnect' status is now STARTING
```

| Field | Content |
|-------|---------|
| `[    6.217276]` | Seconds since boot (`CLOCK_MONOTONIC`), `dmesg`-style: 5 digits, 6 decimals |
| `[PANTAVISOR]` | Fixed tag |
| `[platforms]` | The emitting Pantavisor module |
| `WALL` | Level name: `WALL`, `ERROR` or `FATAL` |
| `platform 'awconnect' …` | The message, without the `(function:line)` prefix of the log files. Whole line capped at 1024 bytes; truncated lines end in `...` |

### Alert sources

| Source | Emitted when | Level |
|--------|--------------|-------|
| `platforms` | A container changes [status](../overview/containers.md#status), one line per transition | `WALL` |
| any Pantavisor module | It logs an error | `ERROR` or `FATAL` |
| container logs | Never mirrored, whatever their level | — |

### Relation to logging

| Condition | Console alert | Log outputs |
|-----------|---------------|-------------|
| Level allowed by [`PV_LOG_LEVEL`](pantavisor-configuration.md#summary), no stdout output shows it | printed | logged |
| Level allowed by `PV_LOG_LEVEL`, a stdout output shows it | skipped | logged |
| Level filtered out by `PV_LOG_LEVEL` | printed | not logged |
| `PV_LOG_CONSOLE_ALERTS=0` | never printed | follows `PV_LOG_LEVEL` |

| Level | Value | Logged when `PV_LOG_LEVEL` ≥ |
|-------|-------|------------------------------|
| `FATAL` | `0` | always |
| `ERROR` | `1` | `1` |
| `WALL` | `3` | `3`, one step before `INFO` (`4`) |

Default `PV_LOG_LEVEL` is `0`: only `FATAL` is logged, all three still reach the console.

Outputs that count as "a stdout output shows it" (second row of the first table):

| Output | Log server running | Not running (before start, after stop) |
|--------|--------------------|----------------------------------------|
| `stdout` | skips the alert | skips the alert |
| `stdout.pantavisor` | skips the alert | — |
| `stdout_direct` | skips the alert | skips the alert |
| `stdout.containers` | — | — |

## Timestamp formats

Every sink except `nullsink` prefixes each line with a timestamp.

| Key | Sink |
|-----|------|
| [`PV_LOG_FILETREE_TIMESTAMP_FORMAT`](pantavisor-configuration.md#summary) | `filetree` |
| [`PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT`](pantavisor-configuration.md#summary) | `singlefile` |
| [`PV_LOG_STDOUT_TIMESTAMP_FORMAT`](pantavisor-configuration.md#summary) | `stdout*` |

| Prefix | Meaning |
|--------|---------|
| `golang:<constant>` | One of the [Go time layout constants](https://pkg.go.dev/time#pkg-constants) below |
| `strftime:<format>` | Any [strftime(3)](https://man7.org/linux/man-pages/man3/strftime.3.html) format, e.g. `strftime:%d, %T %Y` |

| `golang:` constant | Example |
|--------------------|---------|
| `golang:Layout` | `01/02 03:04:05PM '06 -0700` |
| `golang:RubyDate` | `Mon Jan 02 15:04:05 -0700 2006` |
| `golang:ANSIC` | `Mon Jan _2 15:04:05 2006` |
| `golang:RFC822Z` | `02 Jan 06 15:04 -0700` |
| `golang:RFC1123Z` | `Mon, 02 Jan 2006 15:04:05 -0700` |

[`PV_LOG_TIMESTAMP`](pantavisor-configuration.md#summary) selects the clock behind the `tsec` field:

| Value | `tsec` |
|-------|--------|
| `relative` (default) | Seconds since boot |
| `absolute` | Unix epoch |
