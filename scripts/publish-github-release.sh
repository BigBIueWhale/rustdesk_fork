#!/usr/bin/env bash
# scripts/publish-github-release.sh — publish the built dist/ artifacts as an official GitHub release,
# self-validating and fail-loud. It does NOT build (run scripts/build-release.sh first) and it REFUSES to
# publish anything stale, tampered, or not traceable to a clean committed+pushed HEAD. Opinionated: it
# generates the tag, title, and release notes for you. A DRAFT is created by default so a human reviews
# the assets + notes before it goes public (promote it in the GitHub UI, or re-run with --publish).
#
# Usage:  scripts/publish-github-release.sh [--publish] [--push] [<tag>]
#   <tag>       release tag  (default: v<Cargo-version>-hardened). Must not already exist.
#   --publish   publish immediately instead of creating a draft.
#   --push      git push HEAD to origin/master first (the release commit must be on the remote).
#
# Prerequisites (asserted, fail-loud): gh installed + authenticated; origin is a GitHub repo; dist/ holds
# the full artifact set + SHA256SUMS built from the CURRENT clean HEAD; every artifact matches its SHA-256.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"

DRAFT=1; PUSH=0; TAG=""
for a in "$@"; do
    case "$a" in
        --publish) DRAFT=0 ;;
        --push)    PUSH=1 ;;
        -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
        --*)       die "unknown flag '$a' — usage: publish-github-release.sh [--publish] [--push] [<tag>]" ;;
        *)         [ -z "$TAG" ] || die "more than one tag given ('$TAG' and '$a')"; TAG="$a" ;;
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
SUMS_HEAD="$(awk '/^# HEAD /{print $3; exit}' "$OUT_DIR/SHA256SUMS")"
[ -n "$SUMS_HEAD" ] || die "$OUT_DIR/SHA256SUMS has no '# HEAD <sha>' provenance line — rebuild with scripts/build-release.sh"
[ "$SUMS_HEAD" = "$HEAD_FULL" ] \
    || die "dist/ is STALE — SHA256SUMS was built at $SUMS_HEAD but HEAD is $HEAD_FULL. Rebuild: scripts/build-release.sh"

# 5) Integrity — every artifact matches its recorded SHA-256 (catches a stale/partial/tampered dist/).
( cd "$OUT_DIR" && sha256sum -c --strict --status <(grep -vE '^#' SHA256SUMS) ) \
    || die "an artifact in $OUT_DIR does NOT match its SHA-256 in SHA256SUMS — the dist is stale or tampered. Rebuild: scripts/build-release.sh"

# 6) Tag — opinionated default, never clobber an existing release/tag.
VERSION="$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*=[[:space:]]*"\(.*\)".*/\1/')"
[ -n "$VERSION" ] || die "could not read the fork version from Cargo.toml"
TAG="${TAG:-v${VERSION}-hardened}"
if gh release view "$TAG" >/dev/null 2>&1; then
    die "a GitHub release for tag '$TAG' already EXISTS on $REPO_SLUG — pass a NEW tag: scripts/publish-github-release.sh [--publish] <tag>  (or delete the old release first)"
fi
git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1 \
    && die "git tag '$TAG' already exists locally — choose a different tag"

# 7) The release commit must be on the remote (gh creates the tag there). Push if asked, else fail loud.
if [ "$PUSH" = 1 ]; then
    log "pushing HEAD ($HEAD_FULL) to origin/master (--push)"
    git -C "$REPO_ROOT" push origin "HEAD:master" || die "git push failed (see above)"
fi
git -C "$REPO_ROOT" branch -r --contains "$HEAD_FULL" 2>/dev/null | grep -q . \
    || die "HEAD $HEAD_FULL is not on any remote branch — GitHub cannot tag a commit it does not have. Push it first: git push origin master   (or re-run with --push)"

# 8) Release notes = the human-maintained README section (single source) + an auto verify/SHA footer.
README_MD="$REPO_ROOT/README.md"
NOTES_BODY="$(awk '/<!-- RELEASE_NOTES:START -->/{f=1;next} /<!-- RELEASE_NOTES:END -->/{f=0} f' "$README_MD")"
[ -n "$NOTES_BODY" ] \
    || die "no release notes found in README.md — add a section between the markers <!-- RELEASE_NOTES:START --> and <!-- RELEASE_NOTES:END -->"
BUILT_AT="$(git -C "$REPO_ROOT" show -s --format=%cI "$HEAD_FULL" 2>/dev/null || echo '?')"
NOTES_FILE="$(mktemp)"; trap 'rm -f "$NOTES_FILE"' EXIT
{
printf '%s\n\n' "$NOTES_BODY"
cat <<MD
### Verify

Every artifact is byte-identical across independent double-builds (\`SOURCE_DATE_EPOCH\` pinned) — rebuild
this commit (\`${HEAD_FULL:0:12}\`, $BUILT_AT) yourself to confirm, or check the published checksums:
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

# 9) Create the release (draft by default; assets = the 4 binaries + the checksum manifest).
mode="DRAFT"; [ "$DRAFT" = 1 ] || mode="PUBLISHED"
log "creating $mode GitHub release '$TAG' on $REPO_SLUG (5 assets) at commit ${HEAD_FULL:0:12}"
create_args=( "$TAG"
    "$OUT_DIR/rustdesk-x86_64.deb" "$OUT_DIR/rustdesk-arm64.apk"
    "$OUT_DIR/rustdesk-setup.exe" "$OUT_DIR/rustdesk.msi" "$OUT_DIR/SHA256SUMS"
    --title "RustDesk Hardened Fork $TAG" --notes-file "$NOTES_FILE" --target "$HEAD_FULL" )
[ "$DRAFT" = 1 ] && create_args+=( --draft )
gh release create "${create_args[@]}" || die "gh release create failed (see above)"

URL="$(gh release view "$TAG" --json url -q .url 2>/dev/null || echo "$REPO_SLUG releases")"
log "OK — $mode release '$TAG' created: $URL"
[ "$DRAFT" = 1 ] && log "It is a DRAFT — review the assets + notes there, then click Publish (or re-run with --publish)."
