# Versioning

The hardened fork carries **two** version identities, deliberately kept separate:

| Identity | Value | Lives in | Purpose |
|---|---|---|---|
| **App / wire / package version** | `1.4.7` | `Cargo.toml` `version` (→ generated `src/version.rs` `VERSION`; `flutter/pubspec.yaml`; the `.deb`/`.apk`/`.exe`/`.msi` package version) | The upstream RustDesk base the fork derives from. It is the **wire/protocol version** peers exchange for feature-negotiation (`hbb_common::get_version_number`), so it must track the upstream base. **Do not** change it to encode fork releases. |
| **Fork release** | `1.4.7-hardened.N` | `FORK_VERSION` (repo root — the single source of truth) | The fork's own release identity, distinguishing successive releases built on the same upstream base. Carried by the git tag, the GitHub release, the `dist/SHA256SUMS` header, and `rustdesk --fork-version` (embedded at build time via `build.rs` → `RUSTDESK_FORK_VERSION`). Note `rustdesk --version` prints the **app** version (`1.4.7`) — the machine/tooling contract (e.g. the MSI build). |

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

Why two identities: the wire version must stay a plain upstream `M.m.p` so peer feature-negotiation
keeps working, while releases of the fork on that same base still need to be told apart. Encoding the
fork release into the wire version would either break negotiation or make two different builds
indistinguishable — so they are separate, and `FORK_VERSION` is the one you bump.

## Cutting a release

1. **Bump** `FORK_VERSION` (increment `N`) and add a top entry to
   [`CHANGELOG.md`](../CHANGELOG.md) whose heading is the new `<app>-hardened.<N>` and the date.
2. `bash scripts/verify.sh` — the versioning gate checks the `FORK_VERSION` format, the
   base-matches-`Cargo.toml` invariant, and that `CHANGELOG.md`'s top heading matches `FORK_VERSION`.
3. `bash scripts/build-release.sh` — builds the reproducible artifact set into `dist/`, stamping the
   fork version into `dist/SHA256SUMS`.
4. `bash scripts/publish-github-release.sh --publish --push` — creates the GitHub release at tag
   `v<FORK_VERSION>`. It **refuses if that tag already exists**, so releases never clobber; prior
   releases stay in place.

Everything downstream derives from `FORK_VERSION` — read it once via `scripts/fork-version.sh`
(`fork_version`), never re-hardcode the string.
