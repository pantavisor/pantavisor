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

### Issue 6 — Overview and reference had drifted into each other (resolved 2026-09)

Reference tables (log sinks, timestamp formats, hook points, hook environment, wakelock scopes,
`PV_POWER_*` keys, disk field requirements, container status values) had accumulated in
`docs/overview/`, while narrative had accumulated in `docs/reference/`. Content was moved to the
side that owns it, two reference pages were added (`pantavisor-hooks.md`, `pantavisor-power.md`),
every page was cross-linked in both directions, and the rules were written down in
[CONTRIBUTING.md](CONTRIBUTING.md) and enforced by `scripts/check-docs.sh` in CI.
