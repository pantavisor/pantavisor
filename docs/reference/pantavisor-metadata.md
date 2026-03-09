# Pantavisor Metadata

This page contains reference information about [Pantavisor metadata](storage.md#metadata).

## Device metadata

This is the device metadata created by Pantavisor that will give you useful information about your device:

| Key | Value | Description |
| --- | ----- | ----------- |
| `interfaces` | json | network interfaces of the device |
| `pantahub.address` | IP:port | Pantacor Hub address the client is communicating with |
| `pantahub.claimed` | 0 or 1 | 1 if claimed in Pantacor Hub |
| `pantahub.online` | 0 or 1 | 1 if connection to Pantacor Hub was established |
| `pantahub.state` | string | [see Pantacor Hub states](remote-control.md#pantacor-hub-client) (init, register, claim, sync, login, wait hub, report, idle, prep download or download) |
| `pantavisor.arch` | string | CPU architecture |
| `pantavisor.claimed` | 0 or 1 | 1 if device has ever been claimed (local or remote) |
| `pantavisor.cpumodel` | string | CPU model name |
| `pantavisor.dtmodel` | string | Device Tree model name |
| `pantavisor.mode` | local or remote | [see operation modes](pantavisor-architecture.md#communication-with-the-outside-world) |
| `pantavisor.revision` | string | [revision number](make-a-new-revision.md) |
| `pantavisor.status` | string | [revision status](containers.md#status) |
| `pantavisor.uname` | json | [uname](https://man7.org/linux/man-pages/man1/uname.1.html) output |
| `pantavisor.version` | string | Pantavisor build version |
| `storage` | json | disk usage of the device |
| `sysinfo` | json | [sysinfo](https://man7.org/linux/man-pages/man2/sysinfo.2.html) |
| `time` | json | time information |

# User metadata

This is the user metadata that can be set by the user which is parsed and have some actions on Pantavisor:

| Key | Value | Description |
| --- | ----- | ----------- |
| `pvr-sdk.authorized_keys` | SSH pub key | set [public key](inspect-device.md) to get SSH access |
| `pvr-auto-follow.url` | URL | device will automatically pull every change in the device associated to that [clone URL](clone-your-system.md) |
| `pantahub.log.push` | 0 or 1 | disable/enable log pushing to Pantacor Hub. Overrides [PV_LOG_PUSH](pantavisor-configuration.md#summary) |
| `<config-key>` | config-value | override any [configuration](pantavisor-configuration.md#summary) keys that allow RUN level |
| `<container>/<key>` | value | send user metadata that can be consumed by one of the containers |
