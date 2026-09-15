# Per-release CHANGELOG

One file per major stream (`CHANGELOG-NNN.md`). Each section covers one tag in
that stream — release candidates and the final stable — newest first. The
format is modeled on the
[Kubernetes changelog](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.36.md).

| Stream | File |
|---|---|
| 029 | [CHANGELOG-029.md](CHANGELOG-029.md) |
| 030 | [CHANGELOG-030.md](CHANGELOG-030.md) |

Each section captures:

- **Version line** — the tag, its release date, and the commit it points at.
- **Changes** — high-level rollup of conventional-commit subjects since the
  previous tag in the stream, grouped by type (Features / Fixes / CI / Docs /
  Other), no commit hashes.

pantavisor is a single source repo, so — unlike meta-pantavisor's changelog —
there is no Downloads table and no multi-component `SRCREV` diff.

## Where the sections live

Release-candidate sections are **not** committed here. As each RC tag is synced
in from meta-pantavisor, [`tag-changelogs.yaml`](../.github/workflows/tag-changelogs.yaml)
merges its section into a per-major rolling document on S3:

```
https://pantavisor-ci.s3.amazonaws.com/pantavisor/changelog/pantavisor/CHANGELOG-NNN.md
```

This repo file is written exactly once per major — by a maintainer running
`.github/scripts/make-changelog.sh --finalize NNN` just before the stable tag —
and [`changelog-gate.yaml`](../.github/workflows/changelog-gate.yaml) fails the
stable release run if that commit is missing or does not match the S3 document.

## Cutting a stable release

Run this once, after every RC's `tag-changelogs.yaml` run has finished (so the
S3 accumulator is complete):

```sh
git switch master && git pull

# Pull the accumulated changelog into the repo and add the stable "## vNNN"
# section. Commits "changelogs(NNN): finalize NNN changelog". Errors if NNN is
# already tagged.
./.github/scripts/make-changelog.sh --finalize NNN

# Review: the commit should touch only CHANGELOG/CHANGELOG-NNN.md and contain
# every "## vNNN-rcN" section plus a new "## vNNN".
git show HEAD

# Push the finalize commit, THEN tag.
git push origin master
```

The stable tag is then created by meta-pantavisor's tag-sync (as usual). Its
`tag-changelogs.yaml` run refreshes the S3 accumulator and the GitHub Release
for `NNN`; the committed `CHANGELOG/CHANGELOG-NNN.md` is left as finalized.

Point `CHANGELOG_S3_URL_BASE` at a `file://` directory to test `--finalize`
without S3.

## Flag reference

```
make-changelog.sh <TAG>               # write file; auto-commit if pre-tag mode
make-changelog.sh --no-commit <TAG>   # write file but never commit (CI uses this)
make-changelog.sh --stdout <TAG>      # print section to stdout, no file write, no commit
make-changelog.sh --finalize <MAJOR>  # seed the repo file from the S3 accumulator, add the
                                      # "## v<MAJOR>" stable section, commit
                                      # "changelogs(<MAJOR>): finalize <MAJOR> changelog"
```

Re-running on the same tag is safe: the prior `## v<tag>` section is replaced
rather than duplicated, and the file header is preserved. The `changelogs(...)`
commits themselves are filtered out of the Changes section, so re-running
`--finalize` after committing once won't pull the finalize commit back in.
