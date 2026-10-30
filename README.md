# RustDesk — Hardened Fork

A security-hardened, **direct-IP-only** fork of [RustDesk](https://github.com/rustdesk/rustdesk) `1.4.7`.
You reach a *known* host **by its IP address**, and every connection is mutually password-authenticated by
a mandatory **CPace PAKE** before application traffic is admitted.

> This is **not** upstream RustDesk, and the upstream tagline does not describe it. There is **no
> rendezvous/relay server, no public ID, no LAN discovery, no auto-updater, no plugin loader, no 2FA/OTP,
> and no key or server override** — those paths are **deleted from the source tree** (removed, not merely
> disabled).

## Security design

- **One mandatory balanced PAKE — CPace over ristretto255 + SHA-512** (CFRG draft), enforced at the
  transport choke point before any application message, on every transport, with no legacy fallback. No
  password hash ever touches the wire.
  **R-V3 remains outstanding**: the required external expert audit has not happened. The exact-commit
  [external audit handoff and mandatory scope](docs/CRYPTO-AUDIT-SCOPE.md) records that release blocker.
- **Direct transport.** The controlled-side listener uses IPv4 TCP port 21118.
  Rendezvous, relay, KCP, NAT traversal and LAN discovery are removed from the source.
- **Excise, don't disable.** The auto-update RCE surface, plugin loader, 2FA/OTP cluster, trust-anchor
  overrides and the OS-login second-credential path are removed from the source.
- **Session-type confinement.** The receiver derives capabilities from the authenticated connection
  type and checks that type at message dispatch and action sinks under R-S19. Current native and
  installed-artifact acceptance remains open in the ledger below.

These describe the source design. Startup checks validate selected policy invariants;
the separate post-bind socket check has platform-specific coverage and failure handling
and does not establish absence of TCP egress. Complete network-surface and local
privilege-escalation acceptance remains tracked in
[`HARDENING_STATUS.md`](HARDENING_STATUS.md). The normative security and product contract is
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

## Host setup

- [Debian/Ubuntu host setup](docs/DEPLOYMENT.md) covers installation, password setup,
  viewer connections and deployment checks.
- [Android host setup](docs/ANDROID-SERVER.md) covers screen sharing, accessibility
  input, capture consent and reconnects.

## Development

Contribution and review instructions are in [the contribution guide](docs/CONTRIBUTING.md).
Build inputs, platform recipes and verification entrypoints are in
[the build guide](scripts/README.md).

## Attribution & license

A fork of [RustDesk](https://github.com/rustdesk/rustdesk), licensed under the **GNU AGPL-3.0**
([`LICENCE`](LICENCE)) — the same license as upstream. Not affiliated with or endorsed by the upstream
RustDesk project; the RustDesk name and logo belong to their respective owners.
