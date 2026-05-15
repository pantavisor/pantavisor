# Pantavisor Log Sockets

The Pantavisor logging system uses two Unix sockets for inter-process log management: `pv-ctrl-log` for receiving direct log messages and `pv-fd-log` for subscribing file descriptors to be polled by Pantavisor.

## pv-ctrl-log

This socket is used by applications and containers to send log messages directly to the Pantavisor Log Server. All messages must follow the `logserver_msg` structure:

```C
struct logserver_msg {
    int code; // Protocol code: 0 for LEGACY, 256 for CMD
    int len;  // Length of the following buffer
    char buf[0]; // Log data buffer
};
```

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
* `5`: ALL

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

!!! Note
    Only one file descriptor can be subscribed per platform-source pair. Subscribing a new FD for an existing pair will replace the previous one.

## /dev/log

Pantavisor's Log Server creates a symbolic link to the pv-ctrl-log socket at `/dev/log` — the standard syslog socket path used by most operating systems and logging libraries. Applications that write standard syslog messages will have their logs captured automatically with no additional configuration. 

The parser is selected at runtime based on the first bytes of each datagram:

| First bytes | Protocol detected |
|-------------|-------------------|
| `<NNN>1 …` (digit `1` immediately after the closing `>`) | RFC 5424 |
| `<NNN>…` (any other character after the closing `>`) | RFC 3164 |
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
| `HOSTNAME` | `platform` | Container name or source identifier |
| `APP` | `src` (source) | Process name; `[PID]` suffix is stripped |
| `PRI` severity bits | `lvl` (level) | See [priority table](#priority-and-facility) |
| Timestamp | `time` | Parsed with `strptime("%b %d %H:%M:%S")` |
| Message text | log data | Everything after `APP[PID]: ` |

Missing or unparseable fields fall back to `"unknown-host"` and `"unknown-app"`.

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
| `HOSTNAME` | `platform` | Container name or source identifier |
| `APP` | `src` (source) | Application name |
| `PRI` severity bits | `lvl` (level) | See [priority table](#priority-and-facility) |
| `TIMESTAMP` | `time` | Parsed with `strptime("%Y-%m-%dT%H:%M:%S")`; nil (`-`) → current time |
| `MSG` | log data | Everything after the structured-data field |
| `PROCID`, `MSGID`, `STRUCTURED-DATA` | — | Accepted but ignored |

!!! Note
    Fractional seconds in RFC 5424 timestamps are silently dropped. Use UTC (`Z` suffix) for best fidelity.

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
