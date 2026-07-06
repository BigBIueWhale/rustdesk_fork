# Changelog — RustDesk Hardened Fork

All notable changes to the hardened fork, newest first. Each entry's heading is the fork release name
(`<upstream-base>-hardened.<N>` — see [`docs/VERSIONING.md`](docs/VERSIONING.md)). The single source of
truth for the exact code a release contains is the **commit** it was built from, linked in the GitHub
release notes.

## 1.4.7-hardened.1 — 2026-07-06

A hardened, **direct-IP-only** RustDesk, built on upstream RustDesk 1.4.7.

### Connectivity
- **Direct-IP only** — no rendezvous server, relay, UDP, or auto-updater. The box is reachable by one
  deliberate, CPace-PAKE-gated TCP connection on `0.0.0.0:21118`.
- The listener binds **only while a permanent password is set** (fail-closed, R-S9) and re-checks that at
  runtime, so "listen iff a password is set" holds continuously; a transient bind failure backs off and
  retries.

### Authentication
- **The permanent password is the sole authenticator.** A balanced CPace PAKE over the password keys a
  sealed two-key AEAD channel and defeats an active MITM by construction — a party that does not know the
  password cannot key. There is no host-key or fingerprint to pin: a viewer connects with just an address
  and the password.
- The password derives a memory-hard Argon2id PRS (fixed domain-separation salt); it is machine-bound at
  rest, and setting or rotating it is durable across restarts.

### Surface
- The box asserts its own reachable network surface is **exactly one v4 listener and zero UDP sockets**,
  scoped to its own process — so it runs correctly alongside SSH / `systemd-resolved` on the same host
  (R-A4).
- The rendezvous / relay / KCP / LAN-discovery / auto-updater / plugin-loader / host-key subsystems are
  compiled out, and CI greps assert their tokens stay absent (R-A6). Egress is silent by construction (§18).

### Android (controlled side)
- An Android device can act as the controlled host — its screen is shared and it accepts remote
  keyboard / mouse / touch control.
- The controlled side is **owned by the foreground service**: reachable only while the service runs and a
  permanent password is set, and "Stop service" (or an OS kill) genuinely closes the listener by
  construction — the on/off status can never claim reachable when it is not.
- **The sideloaded-install flow is spelled out in-app.** On Android 13+ the accessibility toggle is a
  "Restricted setting" for sideloaded apps; the app walks you through App info → ⋮ → "Allow restricted
  settings" → authenticate → enable — the step that actually makes remote control work.
- Honest scope: screen view is attainable (per-session consent; `FLAG_SECURE` windows capture black);
  remote input is best-effort within Android's limits — the phone is viewer-dominant in practice.

### Build + release
- **Reproducible (R-B2).** Debian, Android, and Windows each cold double-build byte-for-byte identically
  (`SOURCE_DATE_EPOCH` pinned); `dist/SHA256SUMS` records the exact commit. Apple targets are
  source-conformance-checked (macOS/iOS are not built here).
- **The commit is the source of truth.** A release is identified by the commit it was built from (linked
  in its notes); the fork version is the human-readable name. `rustdesk --version` reports the app version
  (`1.4.7`); `rustdesk --fork-version` reports the fork release.
