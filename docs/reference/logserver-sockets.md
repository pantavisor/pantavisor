---
title: "Log Sockets"
sidebar_position: 6
description: "Logserver Unix socket paths and message formats."
---

# Pantavisor Log Sockets

**Overview:** [Storage → Logs](../overview/storage.md#logs) explains how the log server fits together and
what each sink is for.

The Pantavisor logging system uses two Unix sockets for inter-process log management: `pv-ctrl-log` for receiving direct log messages and `pv-fd-log` for subscribing file descriptors to be polled by Pantavisor.

## pv-ctrl-log

This socket is used by applications and containers to send log messages directly to the Pantavisor Log Server. The wire format is auto-detected per message: the binary `logserver_msg` structure below, RFC 3164/RFC 5424 syslog text (also reachable via [`/dev/log`](#devlog)), [JSON](#json-protocol), or [Key-Value](#key-value-protocol).

Messages using the binary structure must follow the `logserver_msg` structure:

```C
struct logserver_msg {
    int code; // Protocol code: 0 for LEGACY, 256 for CMD (internal)
    int len;  // Length of the following buffer
    char buf[0]; // Log data buffer
};
```

Code `256` (CMD) is reserved for Pantavisor's own internal use. The log server rejects any CMD
message whose sender PID is not Pantavisor's, so containers cannot use it.

### Legacy Protocol (code = 0)

The `buf` contains the log metadata and message, separated by null terminators (`\0`):

```
level\0platform\0source\0data
```

* **level**: Log level as a string (e.g., "3" for INFO).
* **platform**: Name of the container or "pantavisor".
* **source**: The specific source of the log (e.g., a process name or module).
* **data**: The actual log message content.

The supported log levels are:
* `0`: FATAL
* `1`: ERROR
* `2`: WARN
* `3`: INFO
* `4`: DEBUG
* `5`: TRACE

### JSON Protocol

`pv-ctrl-log` also accepts log messages formatted as a single JSON object. Unlike the Legacy Protocol, JSON messages are sent as-is on the wire — they are not wrapped in the `logserver_msg` structure. Any datagram that parses as a valid JSON object is auto-detected as JSON (see the [protocol detection table](#devlog) for how this fits together with the binary and syslog formats).

**Message format:**

```json
{
  "version": "0",
  "level": "INFO",
  "src": "myapp",
  "message": "Connection established"
}
```

* **version**: Protocol version. Must be `"0"` — the only version currently supported. Messages with any other value, or missing the field, are rejected.
* **level**: Log level name, case-insensitive. See the level table below.
* **src**: The specific source of the log (e.g., a process name or module) — equivalent to `source` in the [Legacy Protocol](#legacy-protocol-code--0).
* **message**: The actual log message content.

:::note
There is no `platform` field. The platform (the folder name under the log directory) is always derived automatically from the cgroup of the process that sent the message, the same way it is for the [Legacy](#legacy-protocol-code--0), [RFC 3164](#rfc-3164), and [RFC 5424](#rfc-5424) protocols.
:::

The supported log levels are:
* `FATAL`
* `ERROR`
* `WARN`
* `INFO`
* `DEBUG`
* `TRACE`

:::note
`ALL` is a valid threshold for [`PV_LOG_LEVEL`](pantavisor-configuration.md#summary), but it is not accepted as a per-message `level` here — a JSON message with `"level": "ALL"` is silently dropped.
:::

A message that fails to parse (invalid JSON, wrong `version`, unrecognized `level`, or missing `src`/`message`) is dropped; Pantavisor logs a `WARN` and continues.

### Key-Value Protocol

`pv-ctrl-log` also accepts log messages formatted as `key=value` pairs. Like JSON messages, key-value messages are sent as-is on the wire — they are not wrapped in the `logserver_msg` structure. A datagram is auto-detected as key-value formatted when it is made up entirely of `level=`, `src=`, and `message=` pairs and all three are present (see the [protocol detection table](#devlog) for how this fits together with the binary, syslog, and JSON formats).

**Message format:**

```
level=INFO src=myapp message=hello
```

Values containing spaces must be quoted:

```
level="INFO" src="my-component" message="hello world"
```

* **level**: Log level name, case-insensitive. See the level table below.
* **src**: The specific source of the log (e.g., a process name or module) — equivalent to `source` in the [Legacy Protocol](#legacy-protocol-code--0).
* **message**: The actual log message content.

All three keys are required and may appear in any order. Unlike the [JSON Protocol](#json-protocol), there is no `version` field.

:::note
Unquoted values end at the first whitespace character. `message=hello world` without quotes is parsed as `message=hello`, with `world` left dangling and the message rejected — quote any value that contains spaces, as shown above. Quoted values support escaped quotes (`\"`).
:::

:::note
There is no `platform` field. The platform (the folder name under the log directory) is always derived automatically from the cgroup of the process that sent the message, the same way it is for the [Legacy](#legacy-protocol-code--0), [RFC 3164](#rfc-3164), [RFC 5424](#rfc-5424), and [JSON](#json-protocol) protocols.
:::

The supported log levels are:
* `FATAL`
* `ERROR`
* `WARN`
* `INFO`
* `DEBUG`
* `TRACE`

:::note
`ALL` is a valid threshold for [`PV_LOG_LEVEL`](pantavisor-configuration.md#summary), but it is not accepted as a per-message `level` here — a message with `level=ALL` is silently dropped, the same as for the [JSON Protocol](#json-protocol).
:::

A message that fails to parse (missing one of the three keys, or an unrecognized `level`) is dropped; Pantavisor logs a `WARN` and continues.

## pv-fd-log

This socket allows containers to delegate the polling of their file descriptors (e.g., pipes, sockets, or open files) to Pantavisor.

### Subscription Protocol

To subscribe or unsubscribe a file descriptor, you must use the `sendmsg` system call with `SCM_RIGHTS` to pass the file descriptor.

The `msghdr` must contain an `iovec` array with 4 elements:

| iov Index | Type | Max Length | Description |
|-----------|------|------------|-------------|
| `iov[0]` | string | 50 bytes | Platform name (container name) |
| `iov[1]` | string | 50 bytes | Source name (e.g., "stdout", "syslog") |
| `iov[2]` | int | 4 bytes | Log level for the messages from this FD |
| `iov[3]` | int | 4 bytes | Action: `1` to subscribe, `0` to unsubscribe |

#### Subscribe
- Send the file descriptor using `SCM_RIGHTS`.
- Set `iov[3]` to `1`.
- Pantavisor will poll this FD and create a corresponding log file at `/storage/logs/current/<platform>/<source>`.

#### Unsubscribe
- Set `iov[3]` to `0`.
- The file descriptor passed in `SCM_RIGHTS` can be `-1`.
- Pantavisor will stop polling and close its internal reference to the FD for that platform/source pair.

:::note
Only one file descriptor can be subscribed per platform-source pair. Subscribing a new FD for an existing pair will replace the previous one.
:::

## /dev/log

Pantavisor's Log Server creates a symbolic link to the pv-ctrl-log socket at `/dev/log` — the standard syslog socket path used by most operating systems and logging libraries. Applications that write standard syslog messages will have their logs captured automatically with no additional configuration.

RFC 3164 and RFC 5424 protocol support is always active. The `/dev/log` bind-mount into containers is controlled globally by [`PV_LOG_AUTO_DEVLOG`](pantavisor-configuration.md#summary) (default: enabled).

### Per-container control

Each container inherits the global [`PV_LOG_AUTO_DEVLOG`](pantavisor-configuration.md#summary) setting by default. You can override this per-container with the `dev-log` key in `<container>/run.json`:

```json
{
  "#spec": "service-manifest-run@1",
  "dev-log": false
}
```

| Value | Effect |
|-------|--------|
| `true` (default) | `/dev/log` is bind-mounted into the container |
| `false` | `/dev/log` is never mounted in this container, regardless of the global setting |

The parser is selected at runtime based on the first bytes of each datagram:

| First bytes | Protocol detected |
|-------------|-------------------|
| `<NNN>1 …` (digit `1` immediately after the closing `>`) | RFC 5424 |
| `<NNN>…` (any other character after the closing `>`) | RFC 3164 |
| Valid JSON object (e.g. `{ "version": ...`) | [JSON](#json-protocol) |
| `level=`/`src=`/`message=` pairs, all three present | [Key-Value](#key-value-protocol) |
| Binary `struct logserver_msg` with `code` header | [Legacy binary](#pv-ctrl-log) |

### RFC 3164

RFC 3164 is the original BSD syslog wire format. It is the default output of `openlog`/`syslog` on most Linux systems.

**Message format:**

```
<PRI>Mmm dd HH:MM:SS HOSTNAME APP[PID]: message
```

Annotated example:

```
<34>May 15 16:48:18 mydevice myapp[1234]: Connection established
 ^^  ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^ ^^^^  ^^^^^^^^^^^^^^^^^^^^^^
 |   timestamp             hostname app   message text
 priority (facility=4, severity=2 → ERROR)
```

**Field mapping:**

| RFC 3164 field | Pantavisor attribute | Notes |
|----------------|----------------------|-------|
| `HOSTNAME` | — | Parsed to advance the cursor, then discarded |
| `APP` | `src` (source) | Process name; `[PID]` suffix is stripped. Falls back to `unknown-app` |
| `PRI` severity bits | `lvl` (level) | See [priority table](#priority-and-facility) |
| Timestamp | `time` | Parsed with `strptime("%b %d %H:%M:%S")` |
| Message text | log data | Everything after `APP[PID]: ` |
| — | `plat` (platform) | Not taken from the message: resolved from the sender's cgroup, falling back to `unknown-platform` |

The `HOSTNAME` a client sends is never trusted or stored. Like every other protocol on this socket,
the platform is resolved by Pantavisor from the sending process' cgroup.

### RFC 5424

RFC 5424 is the structured syslog format. It adds a version field, ISO 8601 timestamps, and optional structured data elements.

**Message format:**

```
<PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED-DATA MSG
```

Annotated example:

```
<34>1 2026-05-15T16:48:18Z mydevice myapp 1234 - - Connection established
 ^^  ^ ^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^ ^^^^^ ^^^^ ^ ^ ^^^^^^^^^^^^^^^^^^^^^^
 |   | timestamp            hostname app   pid  | | message text
 |   version = 1 (RFC 5424 marker)             | structured-data (nil)
 priority                                 msgid (nil)
```

Nil fields are represented by a single `-` character. Pantavisor accepts `PROCID`, `MSGID`, and `STRUCTURED-DATA` but does not store or forward them.

**Field mapping:**

| RFC 5424 field | Pantavisor attribute | Notes |
|----------------|----------------------|-------|
| `HOSTNAME` | — | Ignored entirely; `plat` is resolved from the sender's cgroup |
| `APP` | `src` (source) | Application name. Falls back to `unknown-app` |
| `PRI` severity bits | `lvl` (level) | See [priority table](#priority-and-facility) |
| `TIMESTAMP` | `time` | Parsed with `strptime("%Y-%m-%dT%H:%M:%S")`; nil (`-`) → current time |
| `MSG` | log data | Everything after the structured-data field |
| `PROCID`, `MSGID`, `STRUCTURED-DATA` | — | Accepted but ignored |

:::note
Fractional seconds in RFC 5424 timestamps are silently dropped. Use UTC (`Z` suffix) for best fidelity.
:::

### Priority and Facility

Both RFC 3164 and RFC 5424 encode priority as a single integer:

```
PRI = facility × 8 + severity
```

**Severity → Pantavisor level mapping:**

| Severity | syslog name | Pantavisor level |
|----------|-------------|-----------------|
| 0 | EMERG | FATAL |
| 1 | ALERT | FATAL |
| 2 | CRIT | ERROR |
| 3 | ERR | ERROR |
| 4 | WARNING | WARN |
| 5 | NOTICE | INFO |
| 6 | INFO | INFO |
| 7 | DEBUG | DEBUG |

**Common facility codes:**

| Code | Name | Description |
|------|------|-------------|
| 0 | `kern` | Kernel messages |
| 1 | `user` | User-level messages |
| 3 | `daemon` | System daemons |
| 16 | `LOCAL0` | Recommended for Pantavisor containers |

`LOCAL0` (facility 16) is the recommended facility for container applications.

### Library support

Any standard syslog library that writes to `/dev/log` works without modification. The examples below show the minimal setup for common languages.

**C / C++ (`syslog.h`)**

```c
#include <syslog.h>

int main(void) {
    openlog("myapp", LOG_PID, LOG_LOCAL0);
    syslog(LOG_INFO, "Container started");
    closelog();
    return 0;
}
```

`openlog` targets `/dev/log` by default on Linux. `LOG_LOCAL0` maps to facility 16.

```

**Python (`logging.handlers.SysLogHandler`)**

```python
import logging
import logging.handlers

handler = logging.handlers.SysLogHandler(address="/dev/log")
logger = logging.getLogger("myapp")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
logger.info("Container started")
```

**Go (`log/syslog`)**

```go
package main

import "log/syslog"

func main() {
    w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_LOCAL0, "myapp")
    if err != nil {
        panic(err)
    }
    defer w.Close()
    w.Info("Container started")
}
```

## Log server outputs

Where the log server writes what it receives is set with
[`PV_LOG_SERVER_OUTPUTS`](pantavisor-configuration.md#summary), a comma-separated list. The sinks
are not mutually exclusive and can be combined in any fashion; unknown tokens are dropped with a
warning.

| Value | Destination |
|-------|-------------|
| `filetree` | One file per container under `<PV_LOG_DIR>/<revision>/<container>/`. Default |
| `singlefile` | All logs as JSON lines in a single `<PV_LOG_DIR>/<revision>/pv.log` |
| `stdout` | Standard output, processed by the log server |
| `stdout.pantavisor` | Standard output, Pantavisor's own messages only |
| `stdout.containers` | Standard output, container messages only |
| `stdout_direct` | Standard output, bypassing the log server. Also auto-enabled before the server starts and after it stops, and always passes FATAL through |
| `nullsink` | `/dev/null` |

See [Output types](../overview/storage.md#output-types) for what each sink is useful for.

## Timestamp formats

Every sink except `nullsink` prefixes each line with a timestamp. The format is set per sink with
[`PV_LOG_FILETREE_TIMESTAMP_FORMAT`](pantavisor-configuration.md#summary),
`PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT` and `PV_LOG_STDOUT_TIMESTAMP_FORMAT`.

Two prefixes are accepted:

| Prefix | Meaning |
|--------|---------|
| `golang:<constant>` | One of the [Go time layout constants](https://pkg.go.dev/time#pkg-constants) below |
| `strftime:<format>` | Any [strftime(3)](https://man7.org/linux/man-pages/man3/strftime.3.html) format string, e.g. `strftime:%d, %T %Y` |

| `golang:` constant | Example |
|--------------------|---------|
| `golang:Layout` | `01/02 03:04:05PM '06 -0700` |
| `golang:RubyDate` | `Mon Jan 02 15:04:05 -0700 2006` |
| `golang:ANSIC` | `Mon Jan _2 15:04:05 2006` |
| `golang:RFC822Z` | `02 Jan 06 15:04 -0700` |
| `golang:RFC1123Z` | `Mon, 02 Jan 2006 15:04:05 -0700` |

Separately, [`PV_LOG_TIMESTAMP`](pantavisor-configuration.md#summary) selects the clock behind the
`tsec` field of every log line: `relative` (seconds since boot, the default) or `absolute`
(Unix epoch).
