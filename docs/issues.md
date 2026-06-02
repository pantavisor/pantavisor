---
title: "Known Documentation Issues"
---

# Known Documentation Issues

Open issues that require content or infrastructure work before they can be fixed.

---

## Issue 4 — Missing `docs/legacy/` folder

Several reference files link to a `docs/legacy/` folder that does not exist in this repository. These links are expected to resolve once legacy reference content is migrated or the folder is created.

**Broken links:**

| File | Link target |
|------|-------------|
| `reference/pantavisor-commands.md` | `../legacy/pantavisor-metadata.md` |
| `reference/pantavisor-commands.md` | `../legacy/pantavisor-xconnect.md` |
| `reference/pantavisor-configuration.md` | `../legacy/pantavisor-configuration-legacy.md` |
| `reference/pantavisor-configuration.md` | `../legacy/pantavisor-metadata.md` |
| `reference/pantavisor-metadata.md` | `../legacy/pantavisor-configuration.md` |
| `reference/pantavisor-xconnect.md` | `../legacy/pantavisor-commands.md` |

**Resolution:** Create `docs/legacy/` and populate it with the legacy reference files, or update each link to point to the current equivalent in `docs/reference/` if the legacy content has been superseded.

---

## Issue 5 — Cross-repo links that only resolve in the docs site build

Reference files in `docs/reference/` contain links using `../../pantavisor-src/docs/overview/...` path prefixes. These paths are relative to the docs site build context, where `pantavisor-src` is a submodule mounted alongside the pantavisor repository. They do not resolve within this repository alone.

Similarly, several overview files contain links to how-to guide pages (`../../make-a-new-revision.md`, `../../inspect-device.md`, `../../claim-device.md`, `../../clone-your-system.md`, `../../../choose-device.md`, `../../../choose-way.md`) that live in the docs site but not in this repo.

**Affected files:**

| File | Example broken link |
|------|---------------------|
| `reference/pantavisor-commands.md` | `../../pantavisor-src/docs/overview/containers.md` |
| `reference/pantavisor-commands.md` | `../../make-a-new-revision.md` |
| `reference/pantavisor-commands.md` | `../../claim-device.md` |
| `reference/pantavisor-configuration.md` | `../../pantavisor-src/docs/overview/remote-control.md` |
| `reference/pantavisor-configuration.md` | `../../inspect-device.md` |
| `reference/pantavisor-metadata.md` | `../../pantavisor-src/docs/overview/storage.md` |
| `reference/pantavisor-metadata.md` | `../../make-a-new-revision.md` |
| `reference/pantavisor-metadata.md` | `../../inspect-device.md` |
| `reference/pantavisor-metadata.md` | `../../clone-your-system.md` |
| `overview/local-control.md` | `../../../reference/027/pantavisor-commands.md` |
| `overview/containers.md` | `../../../reference/027/pantavisor-commands.md` |

**Resolution:** As part of the `docs.pantavisor.io` migration (plan.md Phase 2–3), replace `../../pantavisor-src/docs/overview/...` links with direct relative links within `docs/overview/`, and replace how-to guide links with links to the equivalent pages once they exist on the new site. The `../../../reference/027/...` links should point to `../reference/` once versioning is handled by the Docusaurus build.
