#!/bin/bash
#
# Generate a Kubernetes-style changelog section for a pantavisor source release
# tag. Output is one Markdown section ("## v<TAG>") containing:
#   - A version line (tag, date, commit the tag points at)
#   - Categorized changes (Conventional Commits, no hashes) since the previous
#     tag in the stream
#
# This is the pantavisor (source repo) counterpart of meta-pantavisor's
# make-changelog.sh. The meta version also renders a Downloads table (from the
# S3 releases.json) and a multi-component SRCREV diff; neither applies here
# because pantavisor is a single C codebase, so those sections are dropped.
#
# Tags are created in this repo by meta-pantavisor's tag-sync workflow
# (sync-pantavisor-tag.sh), so by the time the changelog workflow fires the tag
# already exists -> historical mode.
#
# RC changelog sections are never committed to the repo: they live only on the
# per-major S3 accumulator (CHANGELOG_S3_URL_BASE/CHANGELOG-<MAJOR>.md), merged
# there by tag-changelogs.yaml as each RC is tagged. The repo file is written
# exactly once per major, by --finalize, just before the stable tag is cut.
#
# Modes (auto-detected by whether the tag already exists):
#
#   pre-tag (tag does NOT yet exist)
#     HEAD is treated as the commit that will be tagged; range is <PREV>..HEAD;
#     release date is today. After writing the file the script commits it with
#     "changelogs(<TAG>): autoadd changelog" (or "... finalize <MAJOR>
#     changelog" under --finalize).
#
#   historical (tag already exists)
#     Range is <PREV>..<TAG>; release date is the tag's commit date. No commit
#     is made. This is the mode CI runs (tag-changelogs.yaml); CI uploads the
#     merged file to the per-major S3 accumulator instead of committing it.
#
# Usage:
#   make-changelog.sh <TAG>               # pre-tag: write file + commit; or historical: write file
#   make-changelog.sh --no-commit <TAG>   # write file but never commit
#   make-changelog.sh --stdout <TAG>      # print section to stdout, no file write, no commit
#   make-changelog.sh --finalize <MAJOR>  # seed the repo file from the S3 accumulator, add the
#                                         # stable "## v<MAJOR>" section, commit
#                                         # "changelogs(<MAJOR>): finalize <MAJOR> changelog".
#                                         # <MAJOR> must not be tagged yet.
#
# Requires: git, awk, curl.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

GH_REPO="${GH_REPO:-pantavisor/pantavisor}"
# Base URL of the per-major S3 accumulator (CHANGELOG-<MAJOR>.md lives directly
# under it). Overridable so --finalize can be pointed at a file:// URL in tests.
CHANGELOG_S3_URL_BASE="${CHANGELOG_S3_URL_BASE:-https://pantavisor-ci.s3.amazonaws.com/pantavisor/changelog/pantavisor}"

STDOUT_ONLY=0
NO_COMMIT=0
FINALIZE=0
TAG=""
for arg in "$@"; do
    case "$arg" in
        --stdout)    STDOUT_ONLY=1 ;;
        --no-commit) NO_COMMIT=1 ;;
        --finalize)  FINALIZE=1 ;;
        -h|--help)
            sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*)
            echo "ERROR: unknown flag $arg" >&2
            exit 1
            ;;
        *)
            if [ -z "$TAG" ]; then
                TAG="$arg"
            else
                echo "ERROR: unexpected positional argument $arg" >&2
                exit 1
            fi
            ;;
    esac
done

if [ -z "$TAG" ]; then
    echo "ERROR: TAG is required" >&2
    exit 1
fi

if [[ ! "$TAG" =~ ^0[0-9]+(-rc[0-9]+)?$ ]]; then
    echo "ERROR: '$TAG' is not a release tag (expected 0NN or 0NN-rcN)" >&2
    exit 1
fi

if [ "$FINALIZE" -eq 1 ] && [ "$STDOUT_ONLY" -eq 1 ]; then
    echo "ERROR: --finalize and --stdout are mutually exclusive" >&2
    exit 1
fi

cd "$REPO_ROOT"

# --- --finalize: seed the repo file from the S3 accumulator ---------------
# RC changelog sections are only ever published to the per-major S3
# accumulator. --finalize pulls that rolling document into the working tree
# just before the stable tag is cut, so the tagged commit carries the full
# stream history; the pre-tag path below then adds the stable "## v<MAJOR>"
# section on top and commits.
if [ "$FINALIZE" -eq 1 ]; then
    if [[ "$TAG" == *-rc* ]]; then
        echo "ERROR: --finalize takes a major (0NN), not '$TAG'" >&2
        exit 1
    fi
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
        echo "ERROR: tag '$TAG' already exists — nothing to finalize" >&2
        exit 1
    fi
    mkdir -p "$REPO_ROOT/CHANGELOG"
    accum_url="${CHANGELOG_S3_URL_BASE}/CHANGELOG-${TAG}.md"
    if curl -sfL -o "$REPO_ROOT/CHANGELOG/CHANGELOG-${TAG}.md" "$accum_url"; then
        echo "Seeded CHANGELOG/CHANGELOG-${TAG}.md from ${accum_url}" >&2
    else
        echo "WARN: no S3 accumulator at ${accum_url} — keeping the working-tree copy" >&2
    fi
fi

# --- Mode detection --------------------------------------------------------
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    MODE="historical"
    SOURCE_REV="$TAG"
    RELEASE_DATE="$(git log -1 --format=%cs "$TAG")"
else
    MODE="pre-tag"
    SOURCE_REV="HEAD"
    RELEASE_DATE="$(date -u +%Y-%m-%d)"
fi

MAJOR="${TAG%%-*}"
COMMIT_SHA="$(git rev-parse "$SOURCE_REV")"

echo "Mode:    $MODE" >&2
echo "Tag:     $TAG" >&2
echo "Source:  $SOURCE_REV" >&2
echo "Commit:  $COMMIT_SHA" >&2

determine_previous_tag() {
    local tag="$1"
    local major="${tag%%-*}"
    local candidates=()
    local t

    while IFS= read -r t; do
        [ -z "$t" ] && continue
        [ "$t" = "$tag" ] && continue
        [ "$(printf '%s\n%s\n' "$t" "$tag" | sort -V | head -n 1)" = "$t" ] && candidates+=("$t")
    done < <(git tag -l "${major}-rc*")

    while IFS= read -r t; do
        [ -z "$t" ] && continue
        [ "$t" = "$tag" ] && continue
        [[ "$t" =~ ^[0-9]+$ ]] || continue
        [ "$(printf '%s\n%s\n' "$t" "$tag" | sort -V | head -n 1)" = "$t" ] && candidates+=("$t")
    done < <(git tag -l "0*")

    if [ ${#candidates[@]} -eq 0 ]; then
        return
    fi
    printf '%s\n' "${candidates[@]}" | sort -V | tail -n 1
}

PREV_TAG="$(determine_previous_tag "$TAG")"
echo "Prev:    ${PREV_TAG:-(none)}" >&2

# --- Categorized changes ---------------------------------------------------
emit_changes() {
    if [ -z "$PREV_TAG" ]; then
        echo "_(no previous tag -- initial release)_"
        return
    fi

    local raw
    raw=$(git log --no-merges --format='%s' "${PREV_TAG}..${SOURCE_REV}" 2>/dev/null || true)
    if [ -z "$raw" ]; then
        echo "_(no commits between ${PREV_TAG} and ${SOURCE_REV})_"
        return
    fi

    awk -v raw="$raw" '
        BEGIN {
            n_feat=0; n_fix=0; n_ci=0; n_docs=0; n_other=0
            split(raw, lines, "\n")
            for (i=1; i in lines; i++) {
                line = lines[i]
                if (line == "") continue

                if (match(line, /^([a-z]+)(\(([^)]+)\))?(!)?:[ \t]+(.+)$/, m) == 0) {
                    other[++n_other] = "- **(uncategorized)**: " line
                    continue
                }
                type = m[1]
                scope = m[3]
                subject = m[5]
                prefix = (scope != "") ? ("**" scope "**: ") : ""
                bullet = "- " prefix subject

                # Drop housekeeping types entirely; "changelogs"/"changelog" is the
                # autoadd commit, dropping it prevents the changelog from absorbing
                # itself on re-runs.
                if (type == "chore" || type == "style" ||
                    type == "changelog" || type == "changelogs") continue

                if (type == "feat" || type == "feature")  feat[++n_feat] = bullet
                else if (type == "fix")                   fix[++n_fix]   = bullet
                else if (type == "ci" || type == "build") ci[++n_ci]     = bullet
                else if (type == "docs" || type == "doc") docs[++n_docs] = bullet
                else                                      other[++n_other] = "- (" type ") " prefix subject
            }

            emit("Features", feat, n_feat)
            emit("Fixes", fix, n_fix)
            emit("CI", ci, n_ci)
            emit("Docs", docs, n_docs)
            emit("Other", other, n_other)
        }
        function emit(title, arr, n,    i) {
            if (n == 0) return
            print "#### " title
            for (i = 1; i <= n; i++) print arr[i]
            print ""
        }
    '
}

CHANGES_SECTION="$(emit_changes)"

# --- Render section --------------------------------------------------------
if [ -n "$PREV_TAG" ]; then
    CHANGES_PREAMBLE="Changes since [\`${PREV_TAG}\`](https://github.com/${GH_REPO}/releases/tag/${PREV_TAG}):"$'\n'
else
    CHANGES_PREAMBLE=""
fi

SECTION="$(cat <<EOF
## v${TAG}

Released: ${RELEASE_DATE}
Commit: [\`${COMMIT_SHA:0:12}\`](https://github.com/${GH_REPO}/commit/${COMMIT_SHA})

### Changes

${CHANGES_PREAMBLE}
${CHANGES_SECTION}
EOF
)"

if [ "$STDOUT_ONLY" -eq 1 ]; then
    printf '%s\n' "$SECTION"
    exit 0
fi

# --- Prepend (or replace existing section for this TAG) ---------------------
CHANGELOG_DIR="${REPO_ROOT}/CHANGELOG"
CHANGELOG_FILE="${CHANGELOG_DIR}/CHANGELOG-${MAJOR}.md"
mkdir -p "$CHANGELOG_DIR"

FILE_HEADER="# CHANGELOG-${MAJOR}

This file tracks every release in the \`${MAJOR}\` stream. Each section
covers one tag -- release candidates and the final stable -- newest first.

Generated by [\`make-changelog.sh\`](../.github/scripts/make-changelog.sh).
Release-candidate sections are accumulated on the per-major S3 document by
[\`tag-changelogs.yaml\`](../.github/workflows/tag-changelogs.yaml); this repo
copy is written once per major by \`make-changelog.sh --finalize\` just before
the stable tag. See [\`CHANGELOG/README.md\`](README.md).
"

NEW_FILE="$(mktemp)"
if [ -f "$CHANGELOG_FILE" ]; then
    awk -v top="${NEW_FILE}.top" -v body="${NEW_FILE}.body" '
        BEGIN { mode="top" }
        /^## v/ { mode="body" }
        {
            if (mode == "top") print > top
            else                print > body
        }
    ' "$CHANGELOG_FILE"

    if [ -f "${NEW_FILE}.body" ]; then
        awk -v tag="$TAG" '
            /^## v/ { skip = ($0 == "## v" tag) ? 1 : 0 }
            !skip
        ' "${NEW_FILE}.body" > "${NEW_FILE}.body.clean"
        mv "${NEW_FILE}.body.clean" "${NEW_FILE}.body"
    fi

    {
        if [ -s "${NEW_FILE}.top" ]; then
            cat "${NEW_FILE}.top"
        else
            printf '%s\n' "$FILE_HEADER"
        fi
        printf '%s\n\n' "$SECTION"
        [ -f "${NEW_FILE}.body" ] && cat "${NEW_FILE}.body"
    } > "$NEW_FILE"

    rm -f "${NEW_FILE}.top" "${NEW_FILE}.body"
else
    {
        printf '%s\n' "$FILE_HEADER"
        printf '%s\n\n' "$SECTION"
    } > "$NEW_FILE"
fi

chmod 644 "$NEW_FILE"
mv "$NEW_FILE" "$CHANGELOG_FILE"
echo "Updated $CHANGELOG_FILE" >&2

# --- Auto-commit (pre-tag mode only, unless --no-commit) -------------------
if [ "$NO_COMMIT" -eq 1 ]; then
    exit 0
fi
if [ "$MODE" != "pre-tag" ]; then
    # Historical regeneration: don't auto-commit. User can stage/commit manually.
    exit 0
fi

# Skip the commit only when the file is already tracked AND unchanged. A
# brand-new CHANGELOG-<MAJOR>.md (first tag in a stream, e.g. --finalize of a
# fresh major) is untracked -- `git diff` reports nothing for it, so guard on
# ls-files first and let it fall through to the commit.
if git -C "$REPO_ROOT" ls-files --error-unmatch -- "$CHANGELOG_FILE" >/dev/null 2>&1 \
   && git -C "$REPO_ROOT" diff --quiet -- "$CHANGELOG_FILE" \
   && git -C "$REPO_ROOT" diff --cached --quiet -- "$CHANGELOG_FILE"; then
    echo "No changes to ${CHANGELOG_FILE} -- skipping commit." >&2
    exit 0
fi

if [ "$FINALIZE" -eq 1 ]; then
    COMMIT_MSG="changelogs(${TAG}): finalize ${TAG} changelog"
else
    COMMIT_MSG="changelogs(${TAG}): autoadd changelog"
fi
# `git add` first so a brand-new (untracked) CHANGELOG-<MAJOR>.md can be
# committed; `commit -- <path>` still restricts the commit to this file.
git -C "$REPO_ROOT" add -- "$CHANGELOG_FILE"
git -C "$REPO_ROOT" commit -m "$COMMIT_MSG" -- "$CHANGELOG_FILE"
echo "Committed: $COMMIT_MSG" >&2
