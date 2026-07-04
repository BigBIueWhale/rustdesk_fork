#!/usr/bin/env bash
# scripts/publish-github-release.sh — publish the built dist/ artifacts as a GitHub prerelease,
# self-validating and fail-loud. It does NOT build (run scripts/build-release.sh first) and it REFUSES to
# publish anything stale, tampered, or not traceable to a clean committed+pushed HEAD.
#
# ONE SOURCE OF TRUTH — THE COMMIT. A release IS the commit it was built from. GitHub requires a tag, so
# the tag is the commit itself (`commit-<short-sha>`, a bare pointer — never a maintained "version" that
# could drift from the code), and the notes link that exact commit at the top. The fork version (from the
# FORK_VERSION file + the CHANGELOG.md top entry) is the human-readable TITLE + notes only, not an
# identity that has to be kept in sync. Published as a PRERELEASE by default (the fork's honest maturity —
# pre-1.0, single-reviewer crypto audit). Pass --final only for a matured, externally-audited cut. There
# are no drafts and no manual follow-up: one run produces the finished, marked release.
#
# Usage:  scripts/publish-github-release.sh [--final] [--push]
#   --final   publish a FULL (non-prerelease) release instead of a prerelease. Use only when matured.
#   --push    git push HEAD to origin/master first (the release commit must be on the remote).
#
# Prerequisites (asserted, fail-loud): gh installed + authenticated; origin is a GitHub repo; dist/ holds
# the full artifact set + SHA256SUMS built from the CURRENT clean HEAD; every artifact matches its SHA-256.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/fork-version.sh
source "$SCRIPT_DIR/fork-version.sh"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"

PRERELEASE=1; PUSH=0
for a in "$@"; do
    case "$a" in
        --final)   PRERELEASE=0 ;;
        --push)    PUSH=1 ;;
        -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)         die "unknown argument '$a' — usage: publish-github-release.sh [--final] [--push]" ;;
    esac
done

# 1) Tooling — gh installed + authenticated (with a token that can create releases).
require_cmd git sha256sum awk
command -v gh >/dev/null 2>&1 \
    || die "GitHub CLI 'gh' is not installed — install it (https://cli.github.com), then: gh auth login"
gh auth status >/dev/null 2>&1 \
    || die "gh is not authenticated — run: gh auth login  (the token needs 'repo' scope to create releases)"

# 2) Target repo — origin must be a GitHub repo gh recognizes.
REPO_SLUG="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)" \
    || die "gh does not see a GitHub repo here — origin must point at github.com. Check: git remote -v"
log "target GitHub repo: $REPO_SLUG"

# 3) Artifacts — the full set, non-empty.
ASSETS=(rustdesk-x86_64.deb rustdesk-arm64.apk rustdesk-setup.exe rustdesk.msi SHA256SUMS)
for f in "${ASSETS[@]}"; do
    [ -s "$OUT_DIR/$f" ] || die "$OUT_DIR/$f is missing or empty — build the release first: scripts/build-release.sh"
done

# 4) Coherence — the artifacts trace to the CURRENT clean committed HEAD (never publish stale bytes).
[ -z "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] \
    || die "working tree is DIRTY — a release must correspond to a clean committed HEAD. Commit/stash, then rebuild: scripts/build-release.sh"
HEAD_FULL="$(git -C "$REPO_ROOT" rev-parse HEAD)"
HEAD_SHORT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)"
SUMS_HEAD="$(awk '/^# HEAD /{print $3; exit}' "$OUT_DIR/SHA256SUMS")"
[ -n "$SUMS_HEAD" ] || die "$OUT_DIR/SHA256SUMS has no '# HEAD <sha>' provenance line — rebuild with scripts/build-release.sh"
[ "$SUMS_HEAD" = "$HEAD_FULL" ] \
    || die "dist/ is STALE — SHA256SUMS was built at $SUMS_HEAD but HEAD is $HEAD_FULL. Rebuild: scripts/build-release.sh"

# 5) Integrity — every artifact matches its recorded SHA-256 (catches a stale/partial/tampered dist/).
( cd "$OUT_DIR" && sha256sum -c --strict --status <(grep -vE '^#' SHA256SUMS) ) \
    || die "an artifact in $OUT_DIR does NOT match its SHA-256 in SHA256SUMS — the dist is stale or tampered. Rebuild: scripts/build-release.sh"

# 6) Identity — the release IS the commit. The tag names the commit (`commit-<short-sha>`, not a version),
# and the human-readable name comes from the fork version (FORK_VERSION + the CHANGELOG.md top heading).
FORK_VER="$(fork_version)" || die "FORK_VERSION is missing or malformed (see docs/VERSIONING.md)"
TAG="commit-${HEAD_SHORT}"
COMMIT_URL="https://github.com/${REPO_SLUG}/commit/${HEAD_FULL}"
if gh release view "$TAG" >/dev/null 2>&1; then
    die "commit ${HEAD_SHORT} is already released on $REPO_SLUG (tag $TAG) — a commit is released once; build a new commit"
fi
git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1 \
    && die "git tag '$TAG' already exists locally — remove it before re-releasing this commit: git tag -d $TAG"

# 7) The release commit must be on the remote (GitHub can only reference a commit it has). Push if asked.
if [ "$PUSH" = 1 ]; then
    log "pushing HEAD ($HEAD_SHORT) to origin/master (--push)"
    git -C "$REPO_ROOT" push origin "HEAD:master" || die "git push failed (see above)"
fi
git -C "$REPO_ROOT" branch -r --contains "$HEAD_FULL" 2>/dev/null | grep -q . \
    || die "HEAD $HEAD_FULL is not on any remote branch — GitHub cannot reference a commit it does not have. Push it first: git push origin master   (or re-run with --push)"

# 8) Notes = the commit link (the source of truth) FIRST, then the CHANGELOG.md top section, then a
# verify/SHA footer. The CHANGELOG heading must name the fork version, so the notes always match the build.
CHANGELOG_MD="$REPO_ROOT/CHANGELOG.md"
[ -s "$CHANGELOG_MD" ] || die "CHANGELOG.md is missing — add a '## <version>' top entry (docs/VERSIONING.md)"
NOTES_BODY="$(awk '/^## /{n++} n==1{print} n>=2{exit}' "$CHANGELOG_MD")"
[ -n "$NOTES_BODY" ] \
    || die "no top '## <version>' section found in CHANGELOG.md — add this release's entry (docs/VERSIONING.md)"
printf '%s\n' "$NOTES_BODY" | head -1 | grep -qF "$FORK_VER" \
    || die "CHANGELOG.md's top section heading does not name $FORK_VER — update CHANGELOG.md before releasing (docs/VERSIONING.md)"
BUILT_AT="$(git -C "$REPO_ROOT" show -s --format=%cI "$HEAD_FULL" 2>/dev/null || echo '?')"
NOTES_FILE="$(mktemp)"; trap 'rm -f "$NOTES_FILE"' EXIT
{
printf '**Built from commit [`%s`](%s)** — the single source of truth for this release (%s).\n\n' \
    "$HEAD_FULL" "$COMMIT_URL" "$BUILT_AT"
printf '%s\n\n' "$NOTES_BODY"
cat <<MD
### Verify

Every artifact is byte-identical across independent double-builds (\`SOURCE_DATE_EPOCH\` pinned). Check out
the commit above and rebuild with \`scripts/build-release.sh\` to reproduce them bit-for-bit, or verify the
published checksums:
\`\`\`
sha256sum -c SHA256SUMS
\`\`\`

| Platform | File |
|---|---|
| Debian / Ubuntu x86_64 | \`rustdesk-x86_64.deb\` |
| Android arm64 | \`rustdesk-arm64.apk\` |
| Windows x86_64 (installer) | \`rustdesk-setup.exe\` |
| Windows x86_64 (MSI) | \`rustdesk.msi\` |

#### SHA-256
\`\`\`
MD
grep -vE '^#' "$OUT_DIR/SHA256SUMS"
echo '```'
} > "$NOTES_FILE"

# 9) Publish. Annotate the commit's tag (records the tagger/date + is sign-able), push it, then create the
# release on it — a PRERELEASE by default, --final for a matured cut. Never a draft.
mode="PRERELEASE"; [ "$PRERELEASE" = 1 ] || mode="FINAL release"
TITLE="RustDesk Hardened Fork ${FORK_VER}"
log "publishing $mode '$TITLE' at commit ${HEAD_SHORT} (tag $TAG, 5 assets) on $REPO_SLUG"
git -C "$REPO_ROOT" tag -a "$TAG" -m "$TITLE — commit $HEAD_FULL" "$HEAD_FULL" \
    || die "failed to create the tag $TAG"
git -C "$REPO_ROOT" push origin "refs/tags/$TAG" \
    || die "failed to push the tag $TAG (the LOCAL tag exists — remove it before retrying: git tag -d $TAG)"
create_args=( "$TAG"
    "$OUT_DIR/rustdesk-x86_64.deb" "$OUT_DIR/rustdesk-arm64.apk"
    "$OUT_DIR/rustdesk-setup.exe" "$OUT_DIR/rustdesk.msi" "$OUT_DIR/SHA256SUMS"
    --title "$TITLE" --notes-file "$NOTES_FILE" )
[ "$PRERELEASE" = 1 ] && create_args+=( --prerelease )
gh release create "${create_args[@]}" \
    || die "gh release create failed — the tag $TAG was already pushed; to retry cleanly, first delete it: git push origin :refs/tags/$TAG && git tag -d $TAG"

URL="$(gh release view "$TAG" --json url -q .url 2>/dev/null || echo "$REPO_SLUG releases")"
log "OK — $mode '$TITLE' published: $URL"
[ "$PRERELEASE" = 1 ] && log "  (PRERELEASE — the fork's honest maturity; use --final only for a matured, audited cut)"
