# RustDesk — Hardened Fork

A security-hardened, **direct-IP-only** fork of [RustDesk](https://github.com/rustdesk/rustdesk) `1.4.7`.
You reach a *known* host **by its IP address**, and every connection is mutually password-authenticated by
a mandatory **CPace PAKE** before a single application byte crosses the wire. It is built to be, on the
wire, **as defensible as SSH** — the opposite of zero-config remote access.

> This is **not** upstream RustDesk, and the upstream tagline does not describe it. There is **no
> rendezvous/relay server, no public ID, no LAN discovery, no auto-updater, no plugin loader, no 2FA/OTP,
> and no key or server override** — those paths are **deleted from the source tree** (removed, not merely
> disabled). The binary **refuses to start** unless its sovereign, single-port, zero-egress posture can be
> asserted at runtime.

## Security posture

- **One mandatory balanced PAKE — CPace over ristretto255 + SHA-512** (CFRG draft), enforced at the
  transport choke point before any application message, on every transport, with no legacy fallback. No
  password hash ever touches the wire. **Independently audited — VERDICT: SOUND**
  ([`docs/CRYPTO-AUDIT-2026-07-02.md`](docs/CRYPTO-AUDIT-2026-07-02.md)): a byte-level construction
  reproduction on a separate libsodium stack plus first-principles protocol analysis.
- **Sovereign / dial-nobody.** Rendezvous, relay, KCP, NAT traversal and LAN discovery are compiled out —
  the server binds exactly one v4 TCP port and zero UDP. No cloud, no telemetry, no auto-update.
- **Excise, don't disable.** The auto-update RCE surface, plugin loader, 2FA/OTP cluster, trust-anchor
  overrides and the OS-login second-credential path are removed from the source and CI-grepped absent.
- **Least-privilege capability confinement** (CWE-863 / CVE-2026-58056 fixed): every peer-triggerable
  capability is keyed to the session's authorized connection type by construction.

The full, honest conformance ledger — what is verified, deferred, and the known residuals — is
[`HARDENING_STATUS.md`](HARDENING_STATUS.md); the byte-level specification it is built to is
[`requirements.html`](requirements.html).

## Releases

Official builds are published on the [**Releases page**](https://github.com/BigBIueWhale/rustdesk_fork/releases).
They are **reproducible**: every release ships a `SHA256SUMS` manifest, and because the build is
byte-deterministic you can rebuild any release yourself and confirm the hashes match — **trust by
verification, not by authority.**

Producing a release is entirely **default runs of shell scripts** — no environment variables, no flags.
Each step is self-validating and fail-loud: a wrong, stale, or dirty input stops with an actionable error
rather than silently shipping a bad artifact. Builds are offline and SHA-pinned via
[`scripts/pins.env`](scripts/pins.env), run **on the operator's own host, never in the cloud** (every
GitHub Actions workflow is disabled).

### One-time setup

```sh
scripts/online-fetch.sh            # fetch + SHA-verify the pinned toolchains/caches into ./online
scripts/gen-android-keystore.sh    # mint the permanent RSA-4096 APK signing key (default location)
scripts/provision-windows-vm.sh    # build the throwaway Windows 11 golden VM (needs the ISO below)
```

Windows cannot be cross-built from Linux, so the Windows artifacts are produced inside a throwaway Win11
VM on the build host. You supply the **Windows 11 22H2 x64 English (US)** ISO yourself and prove it by
SHA-256 — the hash, not a URL, is the reproducibility anchor (Microsoft re-issues the media). Place it at
`online/win11.iso`:

| Field | Value |
| --- | --- |
| SHA-256 | `0df2f173d84d00743dc08ed824fbd174d972929bd84b87fe384ed950f5bdab22` |
| Size | `5,557,432,320` bytes (≈ 5.18 GiB) |
| Get it | <https://www.microsoft.com/software-download/windows11> → *Download the Disk Image (ISO)* → English (United States) |

### Each release

```sh
scripts/build-release.sh           # cold, all 3 platforms, each byte-identical double-build (A==B)
scripts/publish-github-release.sh  # upload dist/ as a GitHub release (draft; --publish to go live)
```

`build-release.sh` cleans from scratch, refuses a dirty/stale tree, pins the release commit so the whole
set is **coherent** (it rejects itself if `HEAD` moves mid-build), and writes the authoritative manifest
`dist/SHA256SUMS`. It emits four artifacts:

| Platform | File |
| --- | --- |
| Debian / Ubuntu x86_64 | `rustdesk-x86_64.deb` |
| Android arm64 | `rustdesk-arm64.apk` |
| Windows x86_64 (portable installer) | `rustdesk-setup.exe` |
| Windows x86_64 (MSI) | `rustdesk.msi` |

`publish-github-release.sh` **refuses to publish** anything that is not a clean, committed, pushed `HEAD`
whose artifacts match their recorded SHA-256s. It generates the tag (`v1.4.7-hardened`), title, and
release notes (from the section below), and creates a **draft** you review before it goes public
(`--publish` to publish immediately, `--push` to push `HEAD:master` first). It needs the
[GitHub CLI](https://cli.github.com) authenticated (`gh auth login`).

### Verify a download

```sh
sha256sum -c SHA256SUMS
```

## Release notes

<!-- RELEASE_NOTES:START -->
### v1.4.7-hardened

First hardened-fork release. A sovereign, direct-IP-only RustDesk you connect to by address.

- **Mandatory CPace PAKE** as the sole transport authenticator — independently audited **SOUND**.
- **Sovereign posture**: rendezvous / relay / NAT-traversal / LAN-discovery / auto-update compiled out;
  the server binds one TCP port, zero UDP, and makes zero outbound connections.
- **Attack surface excised** (not disabled): auto-update, plugin loader, 2FA/OTP, trust-anchor overrides,
  OS-login second credential.
- **Capability confinement** by `AuthConnType` (CWE-863 / CVE-2026-58056 closed).
- **Reproducible builds** for Debian (`.deb`), Android (`.apk`), and Windows (`.exe` + `.msi`) —
  byte-identical across independent double-builds; verify with `SHA256SUMS`.
<!-- RELEASE_NOTES:END -->

## Attribution & license

A fork of [RustDesk](https://github.com/rustdesk/rustdesk), licensed under the **GNU AGPL-3.0**
([`LICENCE`](LICENCE)) — the same license as upstream. Not affiliated with or endorsed by the upstream
RustDesk project; the RustDesk name and logo belong to their respective owners.
