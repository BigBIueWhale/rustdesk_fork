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
  password hash ever touches the wire.
  **R-V3 remains outstanding**: the required external expert audit has not happened. The exact-commit
  [external audit handoff and mandatory scope](docs/CRYPTO-AUDIT-SCOPE.md) records that release blocker.
- **Sovereign / dial-nobody.** Rendezvous, relay, KCP, NAT traversal and LAN discovery are compiled out —
  the server binds exactly one v4 TCP port and zero UDP. No cloud, no telemetry, no auto-update.
- **Excise, don't disable.** The auto-update RCE surface, plugin loader, 2FA/OTP cluster, trust-anchor
  overrides and the OS-login second-credential path are removed from the source and CI-grepped absent.
- **Least-privilege capability confinement** (CWE-863 / CVE-2026-58056 fixed): every peer-triggerable
  capability is keyed to the session's authorized connection type by construction.

The full, honest conformance ledger — what is verified, deferred, and the known residuals — is
[`HARDENING_STATUS.md`](HARDENING_STATUS.md); the byte-level specification it is built to is
[`requirements.html`](requirements.html).

## Release acceptance

Release acceptance remains **OPEN / STOP-SHIP**. The current source still requires complete pinned
build inputs, the existing Android signing identity, independent cold-build equality, installed
artifact testing, and external review. The current evidence and remaining work are recorded in
[`HARDENING_STATUS.md`](HARDENING_STATUS.md); the release requirements are in
[`requirements.html`](requirements.html).

Before installing any artifact set, follow the [release verification procedure](docs/RELEASE-VERIFICATION.md).
It requires an independently authenticated manifest digest, full source commit, and fork version.
For the existing Android package identity, follow the [signing-key recovery procedure](docs/ANDROID-SIGNING-RECOVERY.md);
a newly generated key cannot replace the committed signing identity.

## Attribution & license

A fork of [RustDesk](https://github.com/rustdesk/rustdesk), licensed under the **GNU AGPL-3.0**
([`LICENCE`](LICENCE)) — the same license as upstream. Not affiliated with or endorsed by the upstream
RustDesk project; the RustDesk name and logo belong to their respective owners.
