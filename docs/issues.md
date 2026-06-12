---
title: "Known Documentation Issues"
draft: true
---

# Known Documentation Issues

Open issues that require content or infrastructure work before they can be fixed.

There are currently no open issues.

## Resolved

### Issue 4 — Missing `docs/legacy/` folder (resolved 2026-06)

Reference files used to link to a `docs/legacy/` folder that does not exist in
this repository. All `../legacy/...` links have been retargeted to the current
equivalents in `docs/reference/` (the legacy reference content was superseded
by the current pages). The deprecated configuration format is linked to its
archived copy in the
[docs.pantavisor archive](https://github.com/pantavisor/docs.pantavisor/tree/master/archive/legacy).

### Issue 5 — Cross-repo links that only resolve in the docs site build (resolved 2026-06)

Links using the MkDocs-era `../../pantavisor-src/docs/overview/...`,
`../../../reference/legacy/...`, and `../../../reference/027/...` prefixes have
been replaced with direct relative links (`../overview/...`, `../reference/...`)
that resolve both in this repository and in the Docusaurus reference instance on
docs.pantavisor.io. Links to MkDocs-era how-to pages (`inspect-device.md`,
`claim-device.md`, `make-a-new-revision.md`, …) now point to the equivalent
curated pages on https://docs.pantavisor.io.
