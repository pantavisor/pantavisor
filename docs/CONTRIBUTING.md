---
title: "Documentation Contract"
draft: true
---

# Documentation Contract

How to decide where a documentation change goes. This page is the single source of truth for the
rules; [AGENTS.md](../AGENTS.md) points here rather than restating them.

It is `draft: true`, so it never publishes to docs.pantavisor.io — it is for people and agents
working in this repository.

## The three folders

| Folder | Answers | Contains | Never contains |
|--------|---------|----------|----------------|
| [`docs/overview/`](overview/index.md) | *How does this work, and why is it built this way?* | Prose, rationale, diagrams, worked examples, algorithm walk-throughs | Exhaustive key / field / endpoint tables — link to reference instead |
| [`docs/reference/`](reference/index.md) | *What exactly are the valid values?* | Tables: every key, every accepted value, every default, every field, every status code | Multi-paragraph explanation — link to overview instead |
| [`docs/tools/`](tools/index.md) | *How do I invoke it?* | CLI synopsis, flags, exit codes, worked invocations | Subsystem theory |

Reference is **authoritative and complete**. Overview is **readable top-to-bottom and never
complete** — it is allowed to skip cases, and it must say where the complete list lives.

## Deciding where a change goes

Ask, in order:

1. **Is it enumerable from the code?** A config key, an accepted value, an endpoint, a JSON field,
   an environment variable, a status code, an exit code. → **reference**. If the set is finite,
   list every member; never write `string` where the parser accepts seven specific tokens.
2. **Does it explain a mechanism, a trade-off, or a "why"?** → **overview**.
3. **Is it how to run a command-line tool?** → **tools**.
4. **Both?** Write both, and link them to each other. The overview names the feature and explains
   it; the reference table is the complete list. Neither duplicates the other's job.

A new subsystem needs all three of: an overview page, an entry in
[`overview/index.md`](overview/index.md), and a reference page for its tables. A feature that is
purely a set of config keys may skip the overview page, but its keys still go in the
[configuration reference](reference/pantavisor-configuration.md).

## Every change gets a documentation pass

After any change (a new feature, a change to an existing one, a fix that alters behaviour) stop
and ask whether the **overview** and the **reference** still describe reality. Usually one of them
needs an edit and often both do: the reference because a value, field or endpoint moved, and the
overview because the explanation around it no longer matches. Answering "no change needed" is a
fine outcome, but it should be an answer, not an omission.

The map below is a lookup aid for the reference half — where each subsystem's tables live. It is
not a list of the only changes that need documenting.

| Subsystem | Reference page |
|-----------|----------------|
| Configuration keys (`config.c` `entries[]`, `config.h` `config_index_t`) | [`reference/pantavisor-configuration.md`](reference/pantavisor-configuration.md) — **both** the Summary and the Levels table |
| Control socket routes and status codes (`ctrl/*_ep.c`) | [`reference/pantavisor-commands.md`](reference/pantavisor-commands.md) |
| Commands (`ctrl/ctrl_cmd.h`) | [`reference/pantavisor-commands.md`](reference/pantavisor-commands.md) `/commands` section |
| Device metadata (`metadata.h` `DEVMETA_KEY_*`) | [`reference/pantavisor-metadata.md`](reference/pantavisor-metadata.md) |
| Log server and its protocols (`logserver/`) | [`reference/logserver-sockets.md`](reference/logserver-sockets.md) |
| Manifest parsing for `run.json`, `device.json`, `groups.json`, `disks.json` | [`reference/pantavisor-state-format-v2.md`](reference/pantavisor-state-format-v2.md) |
| Hooks (`hooks.c`) | [`reference/pantavisor-hooks.md`](reference/pantavisor-hooks.md) |
| Power and wakelocks (`power/`) | [`reference/pantavisor-power.md`](reference/pantavisor-power.md) |
| IPAM (`ipam/`) | [`reference/pantavisor-ipam.md`](reference/pantavisor-ipam.md) |
| xconnect manifests (`xconnect/`) | [`reference/pantavisor-xconnect.md`](reference/pantavisor-xconnect.md) |
| `tools/pvcontrol` | [`tools/pvcontrol.md`](tools/pvcontrol.md) |
| `tools/pventer`, `tools/pvcurl` | [`tools/pantavisor-tools.md`](tools/pantavisor-tools.md) |

`scripts/check-docs.sh` mechanically verifies the first four rows against the code. Everything else,
including whether the overview still reads true, is on you.

## Table conventions

- **Enumerate.** If the parser accepts a fixed set of strings, the Value column lists all of them.
  `string` is only correct for genuinely free-form values.
- **Default means the built-in default** — the value in `config.c`'s `entries[]` table, *not* what
  `embedded/pantavisor.config.in` or `appengine/pantavisor.config.in` ships.
- **One row, one line.** No paragraphs inside a cell. If a value needs explanation, put a sentence
  under the table or link to the overview page.
- **Sorted.** Key tables are alphabetical.
- **Verified.** Every command, key, path and filename is checked against the source before it is
  written down. Do not invent plausible-looking examples.

## Actionability

Every feature described in `docs/` gives the reader a direct path to *do* something with it:

- Alongside the concept, show the concrete command, config key, or endpoint that exercises it — a
  [`pvcontrol`](tools/pvcontrol.md) invocation, a raw [`pv-ctrl`](reference/pantavisor-commands.md)
  call, a [configuration key](reference/pantavisor-configuration.md), or an on-disk path to inspect.
- Prefer a short fenced code block over prose describing what a command does.
- If a feature genuinely has no user-facing action, say so — a one-line "this is managed
  automatically; no action needed" is enough.

## Frontmatter

Every page under `docs/` carries:

```yaml
---
title: "Short Page Name"
sidebar_position: <n>
description: "One sentence, used as the search and card summary."
---
```

`sidebar_position` is unique within its folder and follows the order of that folder's `index.md`.
Meta pages that must not publish (this page, [`issues.md`](issues.md)) use `draft: true` instead of
`sidebar_position`.

## Link conventions

- **Within the same folder**: plain relative links, e.g. `containers.md#restart-policy`.
- **Between `overview/`, `reference/` and `tools/`**: relative sibling links, e.g.
  `../reference/pantavisor-commands.md#steps`, `../overview/containers.md#status`. These resolve
  both on GitHub and on the published site.
- **To meta-pantavisor docs**: `../../meta-pantavisor/<section>/<page>.md` — resolves only on the
  published site, where both repos' docs are siblings.
- **To curated site pages**: full URLs, e.g.
  `https://docs.pantavisor.io/operate/device-access/serial-port`.
- **Do not** use the retired MkDocs-era prefixes (`../../../reference/legacy/`,
  `../../../reference/027/`, `../../pantavisor-src/docs/...`) — they dangle on the site.
- **Syntax**: the site renders MDX. Use Docusaurus admonitions (`:::note` … `:::`), not MkDocs
  `!!! Note`; avoid MkDocs Material icon codes like `:material-check:`.

## Cross-linking

Navigation must work in both directions:

- Every overview page ends with a **Reference** line pointing at the reference pages that carry its
  tables.
- Every reference page opens with an **Overview** line pointing at the page that explains it.

## Page URLs are permanent

A page's path under `docs/` *is* its published URL: `docs/overview/bsp.md` is served as
`https://docs.pantavisor.io/pantavisor/overview/bsp/`. The retired MkDocs site,
`docs.pantahub.com`, still 301-redirects into those URLs, so renaming, moving or deleting one of
the pages below does not just move a page — it turns a live redirect into a 404.

| Page | Redirected from |
|------|-----------------|
| [`overview/bsp.md`](overview/bsp.md) | `docs.pantahub.com/bsp/` |
| [`overview/containers.md`](overview/containers.md) | `docs.pantahub.com/containers/` |
| [`overview/init-mode.md`](overview/init-mode.md) | `docs.pantahub.com/init-mode/` |
| [`overview/local-control.md`](overview/local-control.md) | `docs.pantahub.com/local-control/` |
| [`overview/pantavisor-architecture.md`](overview/pantavisor-architecture.md) | `docs.pantahub.com/pantavisor-architecture/` |
| [`overview/pantavisor-configuration-levels.md`](overview/pantavisor-configuration-levels.md) | `docs.pantahub.com/pantavisor-configuration-levels/` |
| [`overview/remote-control.md`](overview/remote-control.md) | `docs.pantahub.com/remote-control/` |
| [`overview/revisions.md`](overview/revisions.md) | `docs.pantahub.com/revisions/` |
| [`overview/storage.md`](overview/storage.md) | `docs.pantahub.com/storage/` |
| [`overview/updates.md`](overview/updates.md) | `docs.pantahub.com/updates/` |
| [`overview/watchdog.md`](overview/watchdog.md) | `docs.pantahub.com/watchdog/` |
| [`reference/logserver-sockets.md`](reference/logserver-sockets.md) | `docs.pantahub.com/logserver-sockets/` |
| [`reference/pantavisor-commands.md`](reference/pantavisor-commands.md) | `docs.pantahub.com/pantavisor-commands/` |
| [`reference/pantavisor-configuration.md`](reference/pantavisor-configuration.md) | `docs.pantahub.com/pantavisor-configuration/` |
| [`reference/pantavisor-metadata.md`](reference/pantavisor-metadata.md) | `docs.pantahub.com/pantavisor-metadata/` |
| [`reference/pantavisor-state-format-v2.md`](reference/pantavisor-state-format-v2.md) | `docs.pantahub.com/pantavisor-state-format-v2/` |

Rules for those pages:

- **Do not rename, move or delete them**, and do not mark them `draft: true` — that unpublishes the
  page and breaks the redirect just as effectively. `scripts/check-docs.sh` reads the table above
  and fails if a listed page is gone or drafted.
- **Split, do not move.** When a page grows too big, leave it in place and move the *content* into
  a new page it links to.
- If a rename is genuinely unavoidable, it is a two-repo change: the replacement redirect goes into
  [`docs.pantavisor`](https://github.com/pantavisor/docs.pantavisor)
  (`docusaurus.config.ts`, `plugin-client-redirects`) **before** this side merges, and the row above
  is updated in the same PR.

Everything else in `docs/` is free to move; only the redirect targets are frozen. Adding pages is
always safe.

## Before you commit

```bash
scripts/check-docs.sh
```

It is also run in CI by `.github/workflows/docs.yaml` on any PR touching `docs/` or the sources
listed in the table above.
