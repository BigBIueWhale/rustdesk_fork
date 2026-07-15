# Versioning

The hardened fork carries **two** version identities, deliberately kept separate:

| Identity | Value | Lives in | Purpose |
|---|---|---|---|
| **App / wire / package version** | `1.4.7` | `Cargo.toml` `version` (Cargo exposes it as `CARGO_PKG_VERSION`; `build.rs` emits `OUT_DIR/version.rs`; `flutter/pubspec.yaml`; the `.deb`/`.apk`/`.exe`/`.msi` package version) | The upstream RustDesk base the fork derives from. It is the **wire/protocol version** peers exchange for feature-negotiation (`hbb_common::get_version_number`), so it must track the upstream base. The root build script generates `VERSION` and `BUILD_DATE` only under Cargo's target-owned build-script `OUT_DIR`, never as Rust source in the checkout. **Do not** change it to encode fork releases. |
| **Fork release** | `1.4.7-hardened.N` | `FORK_VERSION` (repo root — the single source of truth) | The fork's own release identity, distinguishing successive releases built on the same upstream base. It is the human-readable NAME of a release: the release title, the `CHANGELOG.md` heading, the `dist/SHA256SUMS` header, and `rustdesk --fork-version` (embedded via `build.rs` → `RUSTDESK_FORK_VERSION`). The build script requires one canonical newline-terminated value whose base equals `CARGO_PKG_VERSION`; missing, unreadable, empty, multiline, malformed, or mismatched input aborts every platform build. The canonical GitHub release tag is `fork-version-<version>-commit-<full-sha>`; it binds the fork identity and exact source commit in one ref. `rustdesk --version` prints the **app** version (`1.4.7`) — the machine/tooling contract (e.g. the MSI build). |

## The fork-release string

```
<app-version>-hardened.<N>
   │                    └ a monotonic release counter: 1, 2, 3, …
   └ equals Cargo.toml's version, e.g. 1.4.7
```

- The **base** (`1.4.7`) MUST equal `Cargo.toml`'s `version`. A `verify.sh` gate enforces this — the
  two can never silently drift.
- `N` increments by 1 for every release and never resets while the base is unchanged.
- When the fork rebases onto a newer upstream (say `1.4.8`), bump `Cargo.toml` to `1.4.8`, set
  `FORK_VERSION` to `1.4.8-hardened.1`, and record the rebase in the changelog.
- Every `CHANGELOG.md` release heading is parsed, calendar-validated, and checked newest-first.
  Releases on one app-version base advance by exactly one. A newer app-version base starts at
  `hardened.1`; skipped counters, duplicate versions, invalid dates, and base regressions fail.

Why two identities: the wire version must stay a plain upstream `M.m.p` so peer feature-negotiation
keeps working, while releases of the fork on that same base still need to be told apart. Encoding the
fork release into the wire version would either break negotiation or make two different builds
indistinguishable — so they are separate, and `FORK_VERSION` is the one you bump.

## Cutting a release

1. **Settle source and normative requirements first.** Finish implementation and finalize
   [`requirements.html`](../requirements.html); no release identity changes occur while architecture is moving.
2. **Update the machine inventory expectation.** Re-run the inventory mechanism and settle its expected counts
   against the same source tree that will be released.
3. **Finalize the requirements hash.** Compute the final `requirements.html` SHA-256 and write the identical
   value to the active codec ledger and hardening-status ledger. Run the native-codec watcher against that state.
4. **Bump `FORK_VERSION` last.** Increment `N` only after source, requirements, inventory, and linked hashes
   are settled; update the matching top `CHANGELOG.md` heading/date in the release-preparation change.
5. **Verify the complete tree.** Run `bash scripts/verify-release.sh` and resolve every failure without weakening
   a gate. Any source or requirements change returns the sequence to step 1; any requirements change also
   invalidates the hashes from step 3.
6. **Commit the complete release source.** The commit contains the settled implementation, documentation,
   inventory expectation, linked hash, version, and changelog. The worktree must then be clean.
7. **Push the exact clean `HEAD`.** Use `git push origin HEAD:master`. The build reads live `refs/heads/master` from `origin`
   and requires that full commit ID to equal the pinned local `HEAD` before
   and after verification and target builds.
8. **Run the full cold build.** Execute `./scripts/build-release.sh`. Its entrypoint starts from an empty
   environment, binds Docker to the local Unix socket, and supplies each child through an `env -i`
   allowlist. It creates two independent `--no-hardlinks --reject-shallow`, mode-0700 private repositories, removes their remotes,
   and checks out the exact commit detached. Debian, Android, and Windows each run once in each repository with
   independent target, Flutter, generated, output, and Windows state.
   Each pass owns the `outputs/` parent but leaves its three target leaves absent. Debian and Android create their
   leaves; Windows publishes its complete leaf by a sibling staging rename with no clobber. Its mutable
   `windows-state/` is a pass-private sibling of `outputs/`, never equal to, above, or beneath the Windows output.
   The orchestrator requires byte-identical SHA-256 values for all four artifacts across the two snapshots.
   Direct target scripts retain their own default internal double build; only this structural A/B
   orchestrator passes `DOUBLE_BUILD=0` to a direct target invocation.
9. **Install one immutable local release set.** The exact A/B-equal files and nine-line manifest are copied
   through unnamed synchronized files into a private same-parent payload on the required ext4 publication filesystem.
   A synchronized read-only journal binds the complete descriptor-retrieved ext4 UUID and persistent object identities through
   `initializing`, handle-bound `staging`, manifest-bound `prepared`, and explicit `rollback` or `cleanup`.
   The payload is installed with kernel no-clobber when `dist/` is absent or atomically exchanged with the prior
   set when it exists, then revalidated for exact names, regular-file types, checksums, metadata, and read-only
   modes. Clean source and live `origin/master` equality are proved immediately before installation. Final
   verification rejects any unresolved reserved publication state without repairing it. File edges are acquired with
   `O_PATH|O_NOFOLLOW`, reopened nonblocking through retained descriptors, and re-proved before any read. Recovery requires
   canonical state names to carry the active transaction token. Restart fixtures are logical process-restart proofs, not
   physical power-loss simulation; the invoking UID is cooperative and root, the kernel, ext4, and storage are trusted.
   There is no partial release mode.

The Android signing identity is the public certificate SHA-256 pinned in `scripts/pins.env`. The build
requires the keystore and password to be current-UID, non-symlink, mode-0600 files beneath two mode-0700
current-UID directories. The private key is never an argument or environment value. Both the keystore
certificate and the final APK certificate must match the pin exactly. Artifact authentication and Android
key-loss/compromise handling are normative operational procedures in
[`RELEASE-VERIFICATION.md`](./RELEASE-VERIFICATION.md) and
[`ANDROID-SIGNING-RECOVERY.md`](./ANDROID-SIGNING-RECOVERY.md); neither permits a pin bypass.

Publication is a separate optional action after a verified build:
`./scripts/publish-github-release.sh`. It never builds or pushes source. It independently locks publication,
binds every GitHub CLI command to the owner/repository derived from the exact Git `origin`, snapshots metadata
from the pinned commit and artifacts from the immutable five-file `dist/`, includes drafts in uniqueness checks,
and resolves every existing release tag to a commit. Publication is allowed only when the repository's GitHub
immutable-release policy is enabled. It atomically creates the one canonical
`fork-version-<version>-commit-<full-sha>` tag before creating a draft. All five assets are uploaded to that draft,
queried by numeric release and asset IDs for exact names, nonzero sizes, and server digests, downloaded, and
SHA-256 compared with the private snapshot. The policy, source, origin, tag, manifest, and remote inventory are
reproved immediately before publication. Only then is the draft published; the publisher requires the resulting
release to report immutable and revalidates metadata and downloaded assets. A failure leaves the explicit
tag/draft state for reconciliation; it never deletes uncertain remote state or exposes a partial non-draft release.
Everything downstream derives from `FORK_VERSION` — read it once via `scripts/fork-version.sh`
(`fork_version`), never re-hardcode the string.
