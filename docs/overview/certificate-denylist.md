---
title: "Certificate Denylist"
sidebar_position: 18
description: "Block individual certificates by public key for HTTPS connections, on devices without a reliable clock."
---

# Certificate Denylist

Devices often have no reliable clock, so certificate expiry and revocation dates cannot be trusted. A denylist lets you stop trusting a certificate anyway. Pantavisor refuses an HTTPS connection to Pantacor Hub when the certificate chain contains a listed certificate, whether it is the server certificate, an intermediate or a root.

## Write the list

The file has one entry per line: the lowercase hex SHA-256 of a certificate's public key. Because the key is listed, a re-issued certificate with the same key is blocked too. Empty lines and `#` comments are ignored. Lines that are not a SHA-256 are logged and skipped.

Get the entry for a certificate with:

```bash
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1
```

```text
# GlobalSign Root E46, shown as an example only
e04a022ce32f4ccf2c7f6046287b828a32a909f5e751447f83fd2c71f6fd8173
```

Pantavisor reads the file from `/etc/thttp/denylist` unless you point `PV_TLS_DENYLIST` at another path. A missing file means no denylist. Keep the file outside the certificates directory (`PV_TLS_CERTSDIR`).

## Set the path

`PV_TLS_DENYLIST` can be set at these [levels](pantavisor-configuration-levels.md): `pantavisor.config`, policy, OEM config, `pv_` kernel command line and environment variable. It cannot be set from `pantahub.config`, which holds only the credentials and Hub settings the device negotiates at run time.

For example, in `pantavisor.config`:

```text
PV_TLS_DENYLIST=/storage/my-denylist
```

Or in the [OEM config](pantavisor-configuration-levels.md#oem) file of a revision, so an update can move the path:

```bash
mkdir -p myoem
echo 'PV_TLS_DENYLIST=/storage/my-denylist' >> myoem/default.config
pvr add . && pvr commit && pvr post
```

On the kernel command line the `pv_` prefix is stripped before the key is looked up, so the full key follows it: `pv_PV_TLS_DENYLIST=/storage/my-denylist`. Prefer an [environment variable](pantavisor-configuration-levels.md#environment-variables).

## When a change takes effect

Pantavisor reads the file once at start-up, so a changed list or path takes effect after a reboot. A revision that changes the OEM config file is applied with a reboot, so the new path is used when the device comes back. Editing the list file itself, for example on `/storage`, needs a manual reboot:

```bash
pvcontrol commands reboot "new denylist"
```

## Check it

At start-up, Pantavisor logs one of these lines:

```text
loaded 2 certificate denylist entries from /etc/thttp/denylist
no certificate denylist at /etc/thttp/denylist
```

Find them in the Pantavisor log:

```bash
grep denylist /storage/logs/current/pantavisor/pantavisor.log
```

When a listed certificate is in the chain, requests to the Hub fail without an answer and the device stays offline. The [`remote/core/hub-certificate-denylist`](../testing/pvtest-list.md) test exercises this against a Hub.

## Reference

- [Configuration](../reference/pantavisor-configuration.md#summary) — `PV_TLS_DENYLIST`, with its levels
