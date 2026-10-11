# PVCM Shell Reference

Interactive shell for Pantavisor MCU containers. Access via the shell
RPMsg channel (ttyRPMSG0 on hardware, uart PTY on native_sim).

## Connecting

```bash
# From Linux host (interactive session):
cat /dev/ttyRPMSG0 & cat > /dev/ttyRPMSG0

# Via SSH:
ssh -p 8222 _pv_@<device-ip> 'cat /dev/ttyRPMSG0 & cat > /dev/ttyRPMSG0'
```

Press Enter to get the `mcu:~$` prompt.

## Commands

### pv status

Show PVCM connection info.

```
mcu:~$ pv status
PVCM protocol v1
Transport: RPMsg
Heartbeat: 5000 ms
```

### pv heartbeat

Show MCU uptime.

```
mcu:~$ pv heartbeat
Uptime: 142 s
```

### pv http

Make HTTP requests to Linux services. Supports GET, POST, PUT, DELETE.

**Syntax:**
```
pv http [METHOD] <url> [body]
pv http [METHOD] <service> <path> [body]
pv http <path>
```

**URL format:** `http://servicename.pvlocal/path` — the `.pvlocal` hostname
maps to a backend configured via `--route` on pvcm-run.

**Examples:**
```
# GET — query containers from pv-ctrl
mcu:~$ pv http http://pv-ctrl.pvlocal/containers
GET http://pv-ctrl.pvlocal/containers ...
HTTP 200 (752 bytes)

# GET — shortform (auto-appends .pvlocal)
mcu:~$ pv http pv-ctrl /buildinfo
GET http://pv-ctrl.pvlocal/buildinfo ...
HTTP 200 (2337 bytes)

# GET — default route (no host header)
mcu:~$ pv http /cgi-bin/logs
GET /cgi-bin/logs ...
HTTP 200 (...)

# POST with JSON body
mcu:~$ pv http POST http://pv-ctrl.pvlocal/user-meta {"key":"value"}
POST http://pv-ctrl.pvlocal/user-meta (with body) ...
HTTP 200 (...)

# PUT
mcu:~$ pv http PUT pv-ctrl /config {"mode":"auto"}
PUT http://pv-ctrl.pvlocal/config (with body) ...
HTTP 200 (...)

# DELETE
mcu:~$ pv http DELETE http://pv-ctrl.pvlocal/resource/1
DELETE http://pv-ctrl.pvlocal/resource/1 ...
HTTP 200 (...)
```

**Route configuration** (on pvcm-run):
```
pvcm-run --route pv-ctrl=unix:/pv/pv-ctrl \
         --route pvr-sdk=tcp:127.0.0.1:12368
```

### pv dbus

D-Bus gateway — call methods, subscribe to signals on the Linux system bus.

#### pv dbus list

List all names on the system bus.

```
mcu:~$ pv dbus list
D-Bus ListNames ...
["org.freedesktop.DBus","net.connman","org.pantacor.PvWificonnect",...]
```

#### pv dbus call

Call a D-Bus method.

**Syntax:** `pv dbus call <dest> <path> <interface> <method> [args]`

Arguments are JSON: `["string",42,true]`. Bare words are treated as
strings (Zephyr shell strips quotes): `[net.connman]` works for
`["net.connman"]`.

```
# Get owner of a bus name
mcu:~$ pv dbus call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner [net.connman]
":1.0"

# List network technologies
mcu:~$ pv dbus call net.connman / net.connman.Manager GetTechnologies
[["/net/connman/technology/ethernet",{"Name":"Wired","Type":"ethernet",...}]]

# List network services (full config with IP, DNS, proxy)
mcu:~$ pv dbus call net.connman / net.connman.Manager GetServices
[["/net/connman/service/ethernet_...",{"Type":"ethernet","State":"online","IPv4":{"Address":"192.168.2.77",...},...}]]
```

#### pv dbus subscribe

Subscribe to D-Bus signals.

**Syntax:** `pv dbus subscribe <sender> <path> <interface> <signal>`

```
mcu:~$ pv dbus subscribe org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameOwnerChanged
subscribed: sub_id=1

# Signals appear asynchronously:
[signal] org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.NameOwnerChanged: [...]
```

#### pv dbus unsubscribe

```
mcu:~$ pv dbus unsubscribe 1
unsubscribed: sub_id=1
```

### pv ping

Transport round-trip test. The proxy echoes back the requested
number of bytes, split across 400-byte frames.

```
mcu:~$ pv ping 100
ping 100 bytes (expect 1 frames)...
PASS: 1 frames, 100 bytes received

mcu:~$ pv ping 10000
ping 10000 bytes (expect 25 frames)...
PASS: 25 frames, 10000 bytes received
```

### pv hdrtest

Send a request with a large synthetic header to test streaming.

```
mcu:~$ pv hdrtest 3000
GET /x with 3000-byte header (7 frames)...
HTTP 400 (32 bytes)
```

## Architecture

All commands are async internally. The shell uses semaphores to
block until the response arrives (convenience for interactive use).
The SDK API (`pvcm_get`, `pvcm_dbus_call`, etc.) is fully non-blocking.

```
Shell thread:  pv http ...  → pvcm_http() → send frames → k_sem_take
Server thread: recv frames  → callback    → k_sem_give
Shell thread:  ← wakes up, prints result
```

No size limits on path, headers, body, or D-Bus results. All buffers
are dynamically allocated. Responses stream through DATA frames —
any size works.
