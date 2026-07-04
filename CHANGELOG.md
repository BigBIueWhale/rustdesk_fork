# Changelog — RustDesk Hardened Fork

All notable changes to the hardened fork, newest first. Versions follow
[`docs/VERSIONING.md`](docs/VERSIONING.md): **`<upstream-base>-hardened.<N>`** — the fork's own
release counter (`N`) on top of the upstream RustDesk base version it derives from (currently
`1.4.7`). The upstream base doubles as the wire/protocol version and the package version; the
`-hardened.<N>` part is the fork's release identity. The single source of truth is the repo-root
`FORK_VERSION` file.

## 1.4.7-hardened.1 — 2026-07-04

The first release under the fork's own versioning. It supersedes the earlier **unnumbered**
`v1.4.7-hardened` prereleases (dev iterations that were re-cut in place); from here each release gets
a distinct `-hardened.<N>` and prior releases are never clobbered.

### The fork, in one line
A hardened, **direct-IP-only** RustDesk: no rendezvous/relay/UDP/auto-update; one CPace-PAKE-gated TCP
listener on 21118; a sealed two-key AEAD channel; the shared **permanent password is the sole
authenticator** — there is no host-key/fingerprint pin, because the balanced PAKE defeats an active
MITM by construction (a party that does not know the password cannot key). Reproducible builds (R-B2)
for Debian/Android/Windows, plus Apple source-conformance.

### Fixed — direct-IP listener audit (3-agent adversarial review)
- **Bare-metal deployment no longer self-DoSes (HIGH).** The R-A4 live socket-surface self-check read
  the whole network namespace, so on a host that also runs SSH / `systemd-resolved` it counted those
  foreign sockets and `exit(1)`-looped — refusing to listen despite a password being set. It is now
  scoped to *this process's own* sockets on Linux (matching the existing Android/Windows behaviour),
  so a co-resident service is correctly ignored.
- **Permanent-password set/rotate is now durable across restarts.** The service→user config sync
  rebuilt the stored `password` but left the live CPace PRS stale/empty, so a headless `--server`
  could refuse to listen (or authenticate the *old* password) after a restart. The sync now rebuilds
  the PRS from the stored credential; a matching regression test is gated.
- **Bind failures now retry.** A transient `EADDRINUSE` on restart previously spun forever on a dead
  break-condition and never rebound; it now backs off and re-binds.
- **`listen iff password` holds at runtime.** Clearing the permanent password at runtime now drops the
  listener (previously the socket lingered, though the per-connection gate still refused every peer).

### Changed
- **Versioning.** Introduced this changelog + [`docs/VERSIONING.md`](docs/VERSIONING.md) + the
  `FORK_VERSION` single source of truth. Each release now carries a distinct `-hardened.<N>` identity
  across the git tag, the GitHub release, the `SHA256SUMS` header, and `rustdesk --version`, without
  clobbering prior releases. The wire/protocol version and the `.deb`/`.apk`/`.exe`/`.msi` package
  version stay `1.4.7`.

### Removed
- **Host-key / fingerprint documentation vestiges.** Deleted `docs/HOST-KEY-PIN.md` and every remaining
  reference to the retired host-key/fingerprint pin across the docs and the `pake`/transport-security
  prose, plus ~51 stale translation-table entries (`"Copy Fingerprint"` / `"no fingerprints"`). The
  subsystem itself was excised in the pre-scheme prereleases; this closes the paper trail.
