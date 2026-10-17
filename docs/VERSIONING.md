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

## Preparing a release

The [hardening ledger](../HARDENING_STATUS.md#current-verdict) records the current
release blockers. Version preparation does not establish release acceptance.
Build, compiler, scanner and verification commands below run inside the authenticated
no-NIC verifier VM described in the [build guide](../scripts/README.md#execution-boundary).
The host only orchestrates the owned VM launchers.

1. **Settle source and requirements.** Complete the implementation and finalize
   [`requirements.html`](../requirements.html). Review the native, installed-service
   and release gates in `HARDENING_STATUS.md`; keep current evidence and unresolved
   obligations there. Artifact acceptance follows the builds below.
2. **Review the dependency inventory.** `scripts/dependency-inventory.py --text`
   compares the source inventory with its committed expectations. Review each
   dependency or build-surface change before updating those expectations.
3. **Review native-codec advisories.** Refresh
   [`NATIVE-CODEC-WATCH.md`](./NATIVE-CODEC-WATCH.md) against the pinned source set.
   `bash scripts/native-codec-watch.sh` checks package, pin and ledger synchronization;
   the advisory review and any required remediation remain separate obligations.
4. **Bump `FORK_VERSION` last.** Once source, requirements, inventory and advisory
   dispositions are settled, increment the counter and update the matching top
   `CHANGELOG.md` heading and date.
5. **Verify the complete tree.** Run `bash scripts/verify-release.sh` in the verifier
   VM and resolve every failure without weakening a gate. Its source and portable
   checks have the scope described by that script; target artifacts, installed
   privilege boundaries and native acceptance require their own evidence. A source
   or requirements change returns the sequence to step 1.
6. **Commit and push the release source.** Include the settled implementation,
   documentation, reviewed inventory expectations, advisory dispositions, version
   and changelog in signed-off commits. Require a clean worktree and push the exact
   `HEAD` with `git push origin HEAD:master`. The build requires live `origin/master`
   to equal that commit before and after verification and target builds.
7. **Build and verify one complete release set.** Invoke `scripts/build-release.sh`
   only through the completed no-NIC VM orchestration. It coordinates independent
   Debian, Android and Windows builds, requires byte-identical artifacts across both
   snapshots, and installs the immutable four-artifact `dist/` set with its
   commit/version-bound `SHA256SUMS`. R-B2 and R-B10 define the build and input rules;
   partial release sets and unresolved publication state fail closed. The ledger
   tracks the still-open release orchestration and artifact acceptance.

Android's signing certificate must match the pin in
[`scripts/pins.env`](../scripts/pins.env). Supply the keystore and its password as
private, read-only file inputs at signing time; never put the private key or password
in arguments or environment values. Follow
[`ANDROID-SIGNING-RECOVERY.md`](./ANDROID-SIGNING-RECOVERY.md) for key loss or suspected
compromise. Authenticate the complete manifest independently and verify every
artifact under [`RELEASE-VERIFICATION.md`](./RELEASE-VERIFICATION.md) before installation.

GitHub publication is a separate optional action through
[`scripts/publish-github-release.sh`](../scripts/publish-github-release.sh). It requires
the exact verified release set, source and canonical tag, plus GitHub's immutable-release
policy. It verifies all uploaded assets before publishing and revalidates the immutable
result. A failure retains its tag/draft state for reconciliation. Build and verification
do not authorize publication.

Read the fork identity through `scripts/fork-version.sh` (`fork_version`) rather than
hardcoding it in downstream tools.
