# Changelog — RustDesk Hardened Fork

All notable changes to the hardened fork, newest first. Each entry's heading is the fork release name
(`<upstream-base>-hardened.<N>` — see [`docs/VERSIONING.md`](docs/VERSIONING.md)). The single source of
truth for the exact code a release contains is the **commit** it was built from, linked in the GitHub
release notes.

## 1.4.7-hardened.1 — 2026-07-07

A hardened, **direct-IP-only** RustDesk, built on upstream RustDesk 1.4.7.

### Connectivity
- **Direct-IP only** — no rendezvous server, relay, UDP, or auto-updater. The box is reachable by one
  deliberate, CPace-PAKE-gated TCP connection on `0.0.0.0:21118`.
- The listener binds **only while a permanent password is set** (fail-closed, R-S9) and re-checks that at
  runtime; a transient bind failure backs off and retries.

### Authentication
- **The permanent password is the sole authenticator.** A balanced CPace PAKE over the password keys a
  sealed two-key AEAD channel and defeats an active MITM by construction. There is no host-key or
  fingerprint to pin — a viewer connects with just an address and the password — and no `rustdesk://` link
  or CLI argument can carry an embedded credential (R-X6).
- The password derives a memory-hard Argon2id PRS; it is machine-bound at rest and durable across restarts.

### Surface & sovereignty
- The box asserts its own reachable surface is **exactly one v4 listener and zero UDP sockets**, scoped to
  its own process — so it coexists with SSH / `systemd-resolved` on the same host (R-A4).
- The rendezvous / relay / KCP / LAN-discovery / auto-updater / plugin-loader / host-key subsystems are
  compiled out — as are the cloud account / address-book / group panels (no OIDC login, no shared address
  book) and the remote-printer capability — and CI greps assert their tokens stay absent (R-A6). Egress is
  silent by construction (§18): the box phones home to nobody.

### Sessions & UI
- **All five session types are preserved for the authenticated owner** — remote desktop, file transfer,
  terminal, TCP tunnel / RDP, and view-camera, plus the clipboard and audio channels — each riding the
  single sealed session stream (R-S5) and confined to the session's authenticated type (R-S19).
- **No GUI footguns (R-G1):** a control whose backend is compiled out or pinned is removed, not greyed; a
  pinned capability that must still be shown is read-only, "set by policy", never a toggle that reverts.
- Settings are usable and honest — the password is settable from the GUI, and services / listeners report
  their **real** reachability (a down or wedged daemon never shows a false "Listening").

### Android (controlled side)
- An Android device can be the controlled host, **owned by the foreground service**: reachable only while
  the service runs and a password is set, and a "Stop" (or an OS kill) genuinely closes the listener by
  construction. Boot starts only the password-gated listener, never an unprompted screen-capture consent.
- **The sideloaded-install flow is spelled out in-app** — on Android 13+ the accessibility toggle is a
  "Restricted setting", and the app walks you through App info → ⋮ → "Allow restricted settings" →
  authenticate → enable.
- Honest scope: screen view is attainable (per-session consent; `FLAG_SECURE` windows capture black);
  remote input is best-effort within Android's limits — the phone is viewer-dominant in practice.

### Build + release
- **Reproducible (R-B2).** Debian, Android, and Windows each cold double-build byte-for-byte identically
  (`SOURCE_DATE_EPOCH` pinned); `dist/SHA256SUMS` records the exact commit. Apple targets are
  source-conformance-checked (not built here).
- **The commit is the source of truth.** A release is identified by its build commit; the fork version is
  the human-readable name. `rustdesk --version` reports the app version (`1.4.7`); `rustdesk --fork-version`
  reports the fork release.
</content>
