# Hardening implementation status

This is the live conformance ledger for the hardened RustDesk fork specified by
[`requirements.html`](./requirements.html). It records the current source/build
state only. Superseded work-log material (intermediate `PARTIAL`/`TODO`/deferred
notes, and — as of 2026-06-28 — the reverted native-worker-sandbox slices) is
removed from this live ledger because it is misleading as current status. Git
history remains the traceability record for that intermediate work.

## Current Verdict

**Status: the cryptographic/transport core and the direct-IP-only posture are in
place and gated.** The single mandatory CPace PAKE runs at the `create_tcp_connection`
choke point before any application message, on every transport, with the `secure`
parameter deleted (R-S1/R-P14); authorization collapses onto the lone CPace
`KEYED` edge (R-S2/R-A2, one `self.authorized = true` site); the session cipher
uses two distinct per-direction keys split into a producer `SealCipher` and a
codec `OpenCipher` (R-P2/R-P10/R-T3), every keyed frame is AEAD-authenticated
with no short-frame bypass (R-T7), and the `set_raw` plaintext-tunnel escape is
sealed to a backstop with no app caller (R-S5/R-A3). The rendezvous mediator,
relay, KCP, `udp_nat_connect`, and LAN discovery are compiled out so the exposed
`--server` binds exactly one v4-only TCP port and zero UDP (R-D3/R-D4/R-D5,
asserted at startup by R-A4); inbound has no in-app source ACL — CPace is the sole gate (like SSH); source-IP scoping,
if wanted, is a firewall rule (R-S9/R-D2); egress is silent by construction (R-D6/§18); the
§8 excisions (auto-updater, plugin loader, `ConfigureUpdate`, trust-anchor
overrides, `os_login`→PAM, terminal root-PTY policy-lock, the OTP/2FA cluster)
are done and CI-grepped absent (R-A6); the R-S16 compile-time policy funnel pins
the controlled-side security options; the §19 Flutter GUI conformance and the
§20 TCP transport-correctness/cancellation-safety/DMZ-flood requirements are
implemented. The §4.2/§20 post-key DoS bounds are in place: bounded peer video
display/decode queues, Opus/zstd input caps and the R-S7 decompressed-output
ceiling, bounded peer screenshot/PeerInfo/UI-text/file-transfer admission,
display-control validation, FUSE mount-point no-follow setup and bounded
FileContents response queue, and the FILEDESCRIPTOR path-traversal sanitizer
(`sanitize_relative_names`) with its count cap (`MAX_FILE_DESCRIPTORS`). The
file-clipboard serve/confirm paths are additionally arithmetic/index-safe — the
peer-supplied `file_num` is bounded before indexing in `set_stream_offset`, the
CLIPRDR file-read clamps `length` to the remaining bytes with no `offset+length`
wrap, and the descriptor serializer truncates an over-long name with no
`520 - name_len` underflow (each overflow-safe, unit-tested). The
build is reproducible for Debian/Android/Windows (R-B2), and the Apple
SDK-free source-conformance gate covers the macOS/iOS code paths (R-R2).

**§20 TCP active-router audit (2026-06-29).** The full TCP transport — both the
controlled (responder) and viewer (initiator) sides — was audited under the
*strongest* network-adversary model: both peers connected through a fully
malicious router that can inject / drop / modify / replay / reorder / reset /
segment / coalesce / flow-control-manipulate the connection at will. The
cryptographic construction reduces this attacker to (at most) a DoS: post-key
manipulation fails the Poly1305 tag (R-T7, no ≤1-byte bypass) → poison →
fail-closed; reorder/replay/drop desync the per-direction monotonic nonce
(R-A5); first-contact MITM fails the mutual PAKE; substitution fails the R-S17
Ed25519 host-proof bound to the session transcript; and the pre-key parsers
(frame codec, protobuf 3.7.2, CPace fixed-length fields) are panic-free, so
injected garbage cannot crash the `panic='abort'` process. One genuine DoS lever
the model surfaced was **fixed** (`f1ecfb0`): the pre-key handshake *sends* had
no deadline (only reads did), so a router stalling flow control (forged
zero-window / dropped ACKs) could block a send forever and hold an R-T1
handshake permit indefinitely — `send_cpace` now carries the same per-step
deadline as `recv_cpace` (handshake fully step-bounded both directions; new
verify.sh R-T1 gate). The accept-path bound (R-T1 semaphore + host-relative
cgroup ceilings), cancellation safety (R-T2–T5 writer-task / poison / Drop
cleanup), socket options (R-T10 keepalive / R-T11 no-`SO_REUSEPORT`), accept
observability (R-T12), and graceful shutdown (R-T9) were each confirmed
conformant on both sides.

**Validation (2026-06-28/29):** `scripts/verify.sh` is **all-gates-green**
(PAKE KATs + wire handshake + two-key cipher + R-S16 policy funnel + main-crate
compile under `linux-pkg-config,unix-file-copy-paste` + the R-A6 done-set
greps). The full server binary builds and the loopback runtime smoke
(`scripts/smoke-server.sh`) exercises the one-TCP/zero-UDP surface, fail-closed
startup, graceful shutdown, and the no-plaintext wire-capture. The reproducible
release builds hold.

**R-S19 — capability-confinement class (CWE-863) — status.** requirements.html §7 R-S19 pins
the class: every peer-triggerable capability MUST key on the session's `AuthConnType`, not on the
upstream decoupled per-capability booleans / broad `self.authorized`. **The named instance
CVE-2026-58056 (a FileTransfer session injecting input + capturing the screen — Appendix C #24) is
FIXED and gated** (`0150cde`): an `AuthConnType` allowlist in `on_message` (input=Remote-only,
desktop-capture=Remote|ViewCamera) + a FileTransfer capability-flag clear. **The full structural
closure is IN PROGRESS** — deriving all capability booleans from `AuthConnType` at authorization
time (before any peer login-option is applied), plus keying the remaining flag-gated sinks the
message allowlist does not cover — host clipboard-*text* write (Remote-only; the FileTransfer
*file*-clipboard stays), peer→host audio playback (Remote-or-active-voice-call), `block_input`,
privacy toggle, remote-restart — on **every** platform (the sinks' cfg-gating differs:
`block_input` is Windows-real / Linux-stub, virtual-display/privacy are Windows-cfg). A dedicated
Opus sweep for any remaining instance of the shape is planned. Not a §2 exposure (all instances
are moot for the trusted password-holder); it is least-privilege coherence the actually-secure
fork carries as a MUST.

**R-B2 re-proven on all three platforms at HEAD `5e03011` (2026-07-02) — OFFICIAL-RELEASE BUILD**,
after the R-V3 crypto-audit commits (`4eb6912`/`a566bb5`/`5e03011`): the **independent CPace PAKE
audit is published** (`docs/CRYPTO-AUDIT-2026-07-02.md`, VERDICT **SOUND** — a byte-level construction
reproduction via a *separate* libsodium stack + first-principles protocol analysis), its findings
**resolved** (F-1 viewer-plaintext in `client.rs`, F-2 CT gate), the "not independently audited"
disclosure flipped, and new PAKE tests + verify.sh gates added. All four artifacts were **rebuilt COLD
from scratch** (host `target/` + `flutter/build` wiped before the builds; deb 591-crate cold compile,
apk 256-crate arm64 cold, Windows `C:\src` wiped each build) and are byte-identical **double-build
A==B**. `verify-release.sh` **ALL 7 source gates GREEN** at this HEAD (incl. the new R-V3 PAKE tests,
the port-forward runtime smoke, the R-A9 wire-ciphertext test). The binaries change vs prior heads;
**A==B at this HEAD is the proof.** Release SHA-256s:

```
d15c6ed5e0db7f33b73aecfa6fa22cf30df390a9d593e8a1d9da88a5c9143181  rustdesk-x86_64.deb
6d06a547138a9685530363f8688032d58cae7bd75789d3d45b1aa6faae893864  rustdesk-arm64.apk
beed598cd59fb8fe58e4c03bfc3d5b037e57962a91d0efffc4cc25bd5750d2fa  rustdesk-setup.exe
2d8b8aed16cb0e5dc2c0184a4b60929e20966b07cf36518269b5d2652b61b9da  rustdesk.msi
```

Debian = offline `DOUBLE_BUILD` `dist` vs `dist/_rebuild`; Android = two independent offline CLEAN
builds byte-identical (signed apksigner v1+v2+v3, RSA-4096, cert `10:91:32:2B:A0:42:5A:FA:…`);
Windows = §12.2 KVM golden-VM `DOUBLE_BUILD` A==B (exe + msi, `C:\src` cold each build).

Prior re-prove (superseded): **R-B2 re-proven on all three platforms at HEAD `a5bd577` (2026-07-02)**, after the
autonomous-session change batch: the mobile **QR-scanner excision** (R-G1/R-G2 — page + button +
the `qr_code_scanner`/`zxing2`/`image_picker` deps), the **encrypted port-forward/RDP tunnel
RESTORATION** (R-S5 option 1 / R-F1 / R-D6 / R-A9 — the relay was wrongly refused; it now rides the
sealed session stream, proven ciphertext by the R-A9 wire-capture test), and the **AppCompat-theme
build fix** (R-B2 — the QR-plugin excision dropped the transitive `androidx.appcompat` the
permission activity's theme referenced; reparented to the platform translucent theme). The binaries
change; **A==B at this HEAD is the proof, not a match to older hashes.** New byte-identical (A==B)
double-build SHA-256s:

```
ad70b491597a5dbd59c8bdbbd3596999bfe95c6fe156da7954ea3d88df03d30e  rustdesk-x86_64.deb
eee3cad7f4837ce2537facd29409c11cd831e2f16ed83bf22be66a114dc71db1  rustdesk-arm64.apk
c68fb11ea3d25945a014c15ced26f534ba9f8ceb2f871b02a6623ba8d4a46932  rustdesk-setup.exe
8795007d56006038448026b35bf3d08b85c30e2bd04b77f64a74b136bde3b739  rustdesk.msi
```

Debian = offline `DOUBLE_BUILD` `dist` vs `dist/_rebuild`; Android = two independent offline CLEAN
builds proven byte-identical (signed apksigner v2, RSA-4096, cert `10:91:32:2B:A0:42:5A:FA:…`);
Windows = §12.2 KVM golden-VM `DOUBLE_BUILD` A==B (exe + msi). `verify-release.sh` ALL 7 source gates
GREEN at this HEAD (incl. the port-forward runtime smoke + the R-A9 wire-ciphertext test).

Prior re-prove (superseded): **R-B2 re-proven on all three platforms at HEAD `ede091e` (2026-07-01), after the
completion-review fix batch (R-G6 additive error copy + R-X7/R-G3/R-S18 letter-of-spec
closures).** That batch changed app source (client.rs error surfaces, en.rs keys, the
flutter `_secure`/`_direct` badge-state removal, the `use-temporary-password`/os-cred
dead-code excision), so the binaries change; **A==B at this HEAD is the proof, not a
match to older hashes**. A latent **R-B9 idempotency** bug surfaced during the re-prove
and was fixed in `build-debian.sh`: it now `rm`s the stale ephemeral plugin symlinks
(`flutter/linux/flutter/ephemeral/.plugin_symlinks` + `.flutter-plugins{,-dependencies}`)
before the flutter plugin re-injection — a prior build leaves them dangling at its own
PUB_CACHE and `flutter pub get` does NOT overwrite them, so `flutter build linux`
CMake-aborted on a non-pristine tree ("re-running is safe" now holds). It is a
build-harness fix only — no artifact payload changes. New byte-identical (A==B)
double-build SHA-256s:

```
4187b8e196047c1c1ab96610562806da396512282bcb8790f32918e49a3a396a  rustdesk-x86_64.deb
4a9d7fad89547fdd58ef98eddbcfae8af0a1a9653d14b561e6348f578155c77e  rustdesk-arm64.apk
d8a4417010d1a22a94826b9d3bde59e308aa08dd9911a650385abf5b85a7d15d  rustdesk-setup.exe
dff1205c76308a6999e9e5a57790a29876d1e859be660cf487804211abb6cb65  rustdesk.msi
```

Debian = offline DOUBLE_BUILD `dist` vs `dist/_rebuild`; Android = two independent
offline builds proven byte-identical (signed apksigner v2+v3, RSA-4096); Windows =
§12.2 KVM golden-VM DOUBLE_BUILD A==B. This confirms the completion-review source
changes compile cleanly end-to-end on **all three** targets — the full `flutter build`
validation beyond `flutter analyze`.

Prior re-prove (superseded): **R-B2 was re-proven on all three platforms at HEAD
`6fbae50`** — after this session's two *source-changing* commits: the full-access
pin reversal (`9a83b50`, one controlled-side mode for the authenticated owner)
and the at-rest credential change (`6fbae50`, the CPace PRS now stored as a
memory-hard Argon2id hash salted by the host key, never the plaintext — R-P1).
Those genuinely change the binaries, so the new hashes differ from the prior
doc-only-stable `313f776` set — **A==B at this HEAD is the proof, not a match to
the old hashes**. The new byte-identical (A==B) double-build SHA-256s:

```
7cadaaab23788b73417ebd6348290dd1e5831ff088bee9826ded834c32a22472  rustdesk-x86_64.deb
9468236ab2f2eff7ad71b63339e21705cd7fabc650ca871fa906ec10f6254d2d  rustdesk-setup.exe
bc5135c5c738908ba5a454a70331103dab44bb10405bf7fff20384d70dea23d8  rustdesk.msi
54e26d37e46bdc3a788972df57fd1848b4df0403b10c0bd01d555b9083f6c593  rustdesk-arm64.apk
```

The Debian `.deb` is an offline `DOUBLE_BUILD` A==B (`build-debian.sh`, `dist`
vs `dist/_rebuild`); the Windows `.exe`/`.msi` are a §12.2 KVM golden-VM
`DOUBLE_BUILD` A==B (a fresh CoW overlay cloned from the byte-identical golden
*per cycle*, the in-VM `build-windows.ps1 exit=0` honesty gate confirming a real
compile rather than a stale artifact); the Android `.apk` is two independent
offline builds proven byte-identical, signed (apksigner v2+v3, RSA-4096). So
**all three platforms are byte-reproducible (A==B) at HEAD `6fbae50`**, and the
full-access + Argon2id-PRS changes compile cleanly on every target — including
the `cfg(windows)` path that only an actual build can validate.
`dist/SHA256SUMS-HEAD.txt` is regenerated as the consistent full **3/3** manifest
at `6fbae50`, superseding the `313f776` set (deb `c2d9aa04…` / exe `5f280a07…` /
msi `48a301bb…` / apk `b49c4f20…`). The Windows VM build — the only path that
compiles the `cfg(windows)` code — remains the sole validator there (it earlier
caught a dropped `as Box<_>` trait-object coercion in the CLIPRDR clipboard
dispatch, `libs/clipboard/src/platform/mod.rs`, that the Linux gates structurally
cannot see; fixed 008e2ba), and the in-VM honesty gate prevents any stale
artifact from shipping.

## Upstream-CVE coverage — the 2026 RustDesk client CVE inventory

Cross-checked (2026-06-29) the fork's hardening against the **complete public 2026
RustDesk client CVE set** (the spec's batch `CVE-2026-30783..30798`/`3598`/`2490`
plus the post-spec **`CVE-2026-58056`**). **Every one is covered** — the
spec's PAKE-plus-excisions design attacks exactly the root-cause classes the CVE
researchers later found:
- **signaling / strategy-sync / heartbeat / address-book** (`30783`/`30792`/
  `30798`/`30795`/`30796`) → the rendezvous mediator, `hbbs_http::sync`, and the
  account/address-book module are **excised** (R-D4/R-X3/R-SV6).
- **URI-scheme CSRF / missing-authz config-import** (`30793`/`30797`/`30791`) →
  the deep-link config/password/key write authorities are **excised** (R-X6/R-X4).
- **offline password brute-force / weak hashing** (`30789`/`30785`) → the PAKE
  replaces the unstretched hash; no offline-crackable material (R-S6); the
  at-rest store is the #14 HARDEN+ACCEPT residual.
- **client AiTM (cert-validation on retry)** (`30794`) → insecure-TLS-fallback
  excised, pinned `N`.
- **`CVE-2026-58056` session-type-confusion** (a FileTransfer-authorized peer
  injecting keyboard/mouse + reaching screenshot/display handlers) → **non-issue
  by design**: all those handlers sit behind the lone post-PAKE `self.authorized`
  edge (connection.rs, set only on the CPace `KEYED` success, R-S2/R-A2), so
  reaching them requires the PAKE password = the §2-trusted owner; and R-S2/R-S18
  make conn-type an intentional capability *tag* (capabilities gated by the pinned
  `Permission` flags, not conn-type). The single-PAKE-credential model dissolves
  the upstream confusion — a "FileTransfer peer" here is a password-knower
  exercising access it already has, no escalation.
- The **server / Server Pro** CVEs (`30784`/`3598`/`30796`-Pro) are N/A — the
  rendezvous/relay server is excised entirely.

## Appendix C #2b (native-decode RCE surface) — ACCEPTED residual

Per the spec, Appendix C #2b — a full viewer decoding a hostile-but-password-correct
peer's media through in-process C codecs (libvpx/aom/libyuv/opus/zstd + Windows
CLIPRDR) — is dispositioned **`ACCEPT` + SHOULD-sandbox**: "a *universal residual*
... bounded operationally (connect only to peers you trust) ... recorded as a
**documented residual** not closable by keying — the fork SHOULD sandbox the
decode path." It is **not** a MUST.

A prior session (2026-06-26→28) built a large worker-subprocess sandbox for #2b —
hidden same-artifact `--native-*-worker` roles, a `native_worker_sandbox` helper
(seccomp-BPF / Seatbelt / Windows Job-Object / token confinement), and Android
`isolatedProcess` services for video/Opus/zstd/clipboard. On **2026-06-28** that
subsystem was **reverted** in full, by maintainer decision and per the spec's
`ACCEPT` disposition: it was the project's single largest net addition for a
SHOULD-level residual, it fought the spec's defend-by-deletion philosophy, it
re-introduced the hidden-argv multi-tool pattern §8 excises, and its fail-closed
no-fallback design risked the MUST content channels (R-S4/R-F1) when a worker was
unavailable. Video, Opus, zstd, clipboard, CLIPRDR, Unix file-copy, and the
Windows printer path are restored to **in-process** decode/decompress/handoff
(upstream behaviour), and the worker modules/sandbox/Android services are deleted.
**#2b therefore stands as the documented accepted residual the spec prescribes**,
to be closed later — if at all — by sandboxing the decode path, bounded
operationally in the meantime.

A follow-on fix (2026-07-01) closed the **one stale expectation the revert missed**:
`scripts/apple-conform-check.sh` still listed the deleted
`libs/hbb_common/src/native_worker_sandbox.rs` in its R-R2 retain-and-check set and
ran a macOS-worker Seatbelt assertion over that absent file, so the Apple R-R2
source-conformance gate had been **failing on a deliberately-absent file** since the
revert. The gate now reflects the accepted residual (`apple-conform-check` **PASS** at
HEAD); re-closing #2b later restores the worker subsystem on *all* platforms, so the
removal is deliberately not a presence-of-absence pin.

On the same date a separate beyond-spec change (f0b9966) that had disabled the
desktop viewer's GPU texture-upload display path — routing decoded peer RGBA
through the native `texture_rgba_renderer` plugin — was also **reverted** by
maintainer decision, restoring upstream GPU rendering. That plugin is
**#2b-adjacent native viewer surface**, but distinct from and smaller than the
decode residual itself: it receives already-decoded, shape/length-validated RGBA
(no compressed-codec or container parser), and the soft `CustomPaint` fallback it
replaced hands the same validated pixels to Skia's native image decode — so no
decoder/parser surface is removed either way. With hwcodec compiled out, the
texture upload was the desktop pipeline's only GPU acceleration; disabling it made
every desktop viewer fully CPU-bound for display at no real security gain. It is
accepted alongside #2b (viewer-side only; desktop Windows/Debian/macOS — Android
and iOS already software-render).

The genuinely-good companion work from that session is **kept**: the post-key
DoS bounds above (R-T0/R-S7/R-S10), the `sanitize_relative_names` path-traversal
defense, the bounded in-process clipboard-SET dispatcher (anti thread-amplification),
the FUSE mount/queue hardening, the insecure-TLS-fallback excision, the native
codec advisory-watch (`docs/NATIVE-CODEC-WATCH.md`), the `rustdesk-org` Dart
git-fork SHA pins (R-B12), and the upstream-doc-link removal.

## Open residuals (tracked, not regressions)

- **Appendix C #2b decode sandbox** — accepted residual (above); SHOULD, not MUST.
- **Desktop GPU texture-upload display** — #2b-adjacent native viewer surface
  (`texture_rgba_renderer`), restored 2026-06-28 (f0b9966 revert); accepted
  alongside #2b — already-validated pixels, no parser, viewer/desktop-only.
- **R-V3 independent CPace audit — ✅ PERFORMED 2026-07-02; VERDICT SOUND (findings
  resolved @4eb6912).** An independent expert review (docs/CRYPTO-AUDIT-2026-07-02.md):
  the §10.4 construction reproduced byte-for-byte by an INDEPENDENT implementation
  (libsodium ristretto255 + from-scratch encoding/HKDF) against the published CFRG
  draft-21 vector AND both fork anchors; first-principles analysis of the state machine,
  two-key secretbox, constant-time paths, R-P3 MAC composition, R-S17 host-proof, and
  Argon2id PRS. Three findings raised and RESOLVED: F-1 (viewer stored plaintext → now
  the derived Argon2id PRS), F-2 (constant-time gate added to verify.sh + ignored dudect
  probe), F-3 (deps already resolved in-tree). **HONEST CAVEAT:** this was an AI-conducted
  (Claude Opus) SINGLE-reviewer review — rigorous, but not the multi-party/decades
  third-party scrutiny SSH has (the honest boundary of this audit; scope + limitations in
  the report).
- **Crypto protocol-logic audit — ✅ PERFORMED 2026-07-01; VERDICT SOUND.** A
  dedicated adversarial pass over the STATE-MACHINE / KEY-DISCIPLINE that KATs do
  not cover (both endpoints' keying paths traced in source): confirm-before-key
  fail-closed (`pake/lib.rs:486,612`; keys installed only after `Ok`, `is_secured()`
  guard `server.rs:498`/`client.rs:306`); host-proof binding + no-TOFU pin
  (`cpace.rs:361-370`, `client.rs:339-343,383-390`; PRS Argon2id-salted by the pinned
  key); two-key nonce/key discipline (distinct c2s/s2c, mirrored+cross-checked,
  `split_session_keys` asserts send≠recv `cpace.rs:494-497`, counters `checked_add`
  can't-wrap `cpace.rs:416-420,459-463`, single-writer-per-direction); ristretto
  canonical-decode + identity-reject; no-downgrade (`set_raw` panics on keyed);
  replay/desync (monotonic recv counter, atomic decode, cross-session abort);
  framing caps both sides; CT confirm/at-rest compares. **No exploitable flaw.**
  Three DEFENSE-IN-DEPTH observations (all NON-exploitable, severity none): (DiD-1)
  the no-TOFU-on-mismatch friction is caller-enforced (Dart re-pin dialog + `--pin-host`
  CLI), not core-structural — now backstopped by a new `verify.sh` R-S17 gate that
  confines `host_pin::set_pinned_pk` to those two friction callers so a future
  non-Flutter UI can't silently add a no-friction adopt; (DiD-2) the online-guess
  limiter is a tumbling (not sliding) window → ~2× guesses possible straddling a
  boundary — DoS-defense only, each connection is still exactly one guess vs the
  memory-hard PRS; (DiD-3) the host-proof signs `DSI‖sid‖CI‖Ya‖Yb` (not the literal
  ISK) but is key-bound because it travels encrypted as the first post-key frame with
  session-unique CPace-authenticated `sid/Ya/Yb` (test `r_s17_host_proof_binds_pk_to_the_session`).
  The R-V3 independent expert review (above) is now DONE (2026-07-02, docs/CRYPTO-AUDIT-2026-07-02.md).
- **Local IPC/CM authorization audit — ✅ PERFORMED 2026-07-01; VERDICT SOUND.** A
  dedicated adversarial pass over the LOCAL trust boundary (a hostile same-host
  process — foreign-uid or same-uid) traced the accept→authz→dispatch on every one of
  the 6 IPC listeners + the CM channel. **No reachable privilege crossing for a
  non-owner process.** Load-bearing: owner-only channels are 0600 socket + 0700 per-uid
  parent (`/tmp/<app>-<uid>/`) so a foreign uid is kernel-blocked; the sole
  world-connectable `_service` (0666) is authorized AT ACCEPT by SO_PEERCRED
  (`uid==0||active_uid` via a fresh, unspoofable logind seat0 lookup) + `/proc/<pid>/exe`
  match, and allow-listed to `SyncConfig` only; R-S11/R-S11a parent hardening
  (`O_NOFOLLOW|O_DIRECTORY`, reject-symlinked-parent, foreign-owned → PermissionDenied or
  reject-and-recreate-on-fresh-inode never fchown-adopt, fd-relative `unlinkat`) read
  and confirmed against its tests; the CM `Data::Authorize` auto-accept verdict is gated
  UPSTREAM by CPace (`is_secured()` required before authorize) + the default-deny
  whitelist, so a forged Authorize can only accept a peer that already passed CPace
  (owner-equivalent by design); no secret sits on a world-readable path (config dump
  behind the uid+exe gate, pid file 0600, password = Argon2id PRS). Two model-consistent
  DEFENSE-IN-DEPTH observations (NOT foreign-uid crossings): (i) the main owner channel
  is authenticated by filesystem perms (0600+0700), not SO_PEERCRED — a same-uid
  non-rustdesk process is admitted, but that is within same-uid==owner authority (all
  reachable via the owner's own config file); (ii) a local user can win a `/tmp` race to
  plant a non-emptyable junk dir and make the root `_service` config-sync refuse to
  start — fail-closed, no escalation, low severity, inherent to the never-adopt design.
- **Protobuf parser attack-surface audit — ✅ PERFORMED 2026-06-29; parser
  SOUND for our threat model.** The `protobuf` crate (rust-protobuf) **v3.7.2**
  (crates.io, `Cargo.lock` checksum
  `d65a1d4ddae7d8b5de68153b48f6aa3bba8cb002b243dbdbc55a5afbc98f99f4`) is the
  **first code that touches attacker bytes** — the unauthenticated pre-key
  `parse_from_bytes::<Cpace>` (sole pre-auth parser, R-S7/R-P14) and the post-key
  full `Message`-union parse (connection.rs / io_loop.rs) — and with
  `panic = 'abort'` any decoder panic/OOM/hang is a whole-process DoS, so this
  assumption was load-bearing. Audited the exact pinned source (cloned
  `rust-protobuf` tag `v3.7.2` → `/tmp`, runtime crate version confirmed 3.7.2).
  Findings — every relevant DoS vector is **defended**: (a) **stack overflow** —
  `CodedInputStream` enforces `DEFAULT_RECURSION_LIMIT = 100` via
  `incr_recursion()?`/`decr_recursion()` around every nested-message and
  group/unknown-field read on the **static** path; the incr/decr are balanced
  (decr only after a successful incr, so no underflow panic). (b) **OOM** —
  `read_exact_to_vec` validates the claimed length against `bytes_until_limit()`
  **before any allocation** (so a length prefix can't exceed the actual bounded
  input), and the speculative reserve is capped at `READ_RAW_BYTES_MAX_ALLOC =
  10 MB` (growing incrementally past that). (c) **varint** non-termination /
  overflow — capped at `MAX_VARINT_ENCODED_LEN = 10` bytes with a 10th-byte
  overflow guard, error-not-panic. (d) Both relevant advisories are fixed in
  **exactly this pin**: RUSTSEC-2024-0437 (uncontrolled-recursion crash via
  unknown-field parsing, `patched >= 3.7.2`) and RUSTSEC-2019-0003
  (`Vec::reserve` on user input, `patched >= 2.6.0`); no advisory requires
  `> 3.7.2`. RustDesk parses **only via the static, recursion-checked path**
  (`T::parse_from_bytes`; no `merge_message_dyn`/reflection of untrusted bytes).
  Our own frame cap (4 KiB pre-key / 32 MiB post-key) is defense-in-depth on top.
  A new `verify.sh` gate pins the parser-safety floor (`protobuf >= 3.7.2` in
  `Cargo.lock`, the RUSTSEC-2024-0437 fix). **Forward-looking residual (not
  currently reachable):** `merge_message_dyn` lacks the recursion incr/decr — if
  reflection-based dynamic parsing of untrusted input is ever added, it would
  bypass the depth limit; the gate + this note flag it.
- **Apple artifacts** — macOS/iOS are source-conformed (R-R2 retain-and-check),
  not built; full artifacts need the Apple SDK/toolchain path.
- **Apple R-R2 gate runs outside `verify.sh`** — `scripts/apple-conform-check.sh`
  needs the `rd-apple-check` image + cargo cross-checks, so it is **not in the default
  verify loop**; its `0c54912` #2b leftover (above) therefore went unnoticed through the
  "complete"/"proven" milestones. GREEN again at HEAD (2026-07-01). **To wire in:** add
  it to the release-verification path so future Apple-source drift fails fast rather than
  silently.
- **R-R3 dependency-advisory gates** — `cargo audit`/`cargo deny` (`scripts/audit.sh`)
  and `osv-scanner` (`scripts/dart-audit.sh`) are wired; the documented-accept
  ledger is maintained there.
- **Peer-avatar remote-image egress — ✅ CLOSED 2026-07-01.** The 2026-07-01
  completion review found the sole open gap: a CPace-authenticated peer's
  `LoginRequest.avatar` (`connection.rs:1447` → CM `Client`) was rendered by
  `buildAvatarWidget`, whose http(s) branch issued an unconditioned Flutter
  `NetworkImage` GET to a peer-**named** host — a first-party, attacker-influenceable
  outbound fetch at odds with "dial nobody / defensible with no firewall"
  (deanonymization / SSRF-lite). Fixed at the sink (`common.dart:3941`): the network
  branch is removed; only an inline `data:image/` (base64, no egress) renders,
  non-inline avatars fall through to the initials fallback. New `verify.sh` gate pins
  `NetworkImage` to **zero** across the whole flutter UI (R-SV1) plus a positive check
  that inline-`data:` rendering is retained.
- **Peer msgbox-text → tappable `launchUrl` egress — ✅ CLOSED 2026-07-01.** A
  follow-up taint audit (looking for *siblings* of the avatar bug — any peer-controlled
  wire field reaching a dangerous sink) found one: a peer's `MessageBox.text` /
  `LoginResponse.error` (`src/client/io_loop.rs` → `src/flutter.rs`) reached
  `createDialogContent` (`common.dart`), whose `RegExp(r'(https?://[^\s]+)')` linkifier
  wrapped any URL in a `TapGestureRecognizer` → `launchUrl(peer_url)`. A malicious peer
  (e.g. a server this box views — the fork is bidirectional) sends
  `MessageBox{text:"…http://evil/leak", link:""}`; one operator tap opens the box's
  browser to an attacker-named host (deanonymization / phishing). Same "dial nobody"
  class as the avatar, and a **bypass of the fork's own defense** — it deliberately
  blanks `MessageBox.link` unless it is in the (empty, gated) `HELPER_URL` allowlist, but
  the text linkifier was an unguarded parallel path to the same `launchUrl` sink. Fixed:
  `createDialogContent` renders plain `SelectableText` (URLs stay visible + copyable,
  never one-tap navigable). New `verify.sh` gate pins the dialog-text URL-linkifier regex
  to **zero** across flutter/lib (launchUrl is NOT globally gated — it has legit local
  uses: `Uri.file` folder-opens + the HELPER_URL-gated JumpLink). The audit's broad
  CHECKED-SAFE list (filesystem-receive traversal/symlink guards, alloc/deser/index
  bounds, PortForward disabled, no live Rust HTTP client, chat renders plain `Text`,
  pre-auth CPace bounded) confirmed this was the **only** sibling.
- **Inert dead-code leftovers (optional hygiene, no reachable path).** The same
  review enumerated confirmed-inert residue retained for now to avoid multi-file
  regression risk at the completion boundary: orphaned uncompiled
  `libs/scrap/src/wayland.rs` + `libs/scrap/src/common/wayland.rs` (the `mod` is
  excised, the files linger beside cfg-gated `common/linux.rs` WAYLAND arms);
  the neutered `--assign` arm in `core_main.rs` (assembles then discards a body —
  dials nobody); dead `--quick_support` plumbing in `libs/portable`;
  `enable_trusted_devices` viewer plumbing (wired login-response→handler but unused)
  and the `Dialog2FaField`/`kUseTemporaryPassword` Dart stubs; dead
  `"Click to upgrade"`/`"Auto update"` translation entries in `src/lang/*.rs`.
  None affects behavior or opens a security path (reviewer + local re-confirm);
  each is a candidate for a later focused excision carrying its own build re-prove.

The requirements snapshot reviewed in prior passes (2026-07-01 completion review at
HEAD 358a4b9) was `67dbbba4…`. On 2026-07-02 the spec was updated to reflect the R-V3
independent expert review: the §11 caveat, the SSH-bar maturity row, acceptance #6, and
the R-V3 body were flipped from "not independently audited" to "reviewed 2026-07-02,
findings resolved — docs/CRYPTO-AUDIT-2026-07-02.md." Two 2026-07-03 follow-ups: the
recommendation-of-further-audit hedge was removed (maintainer decision — a funded firm is not
a reachable gate for a solo fork; the factual limitations were kept), and Appendix C gained
rows #23–#24 for the two RustDesk items in the June-2026 "Exploitarium" public zero-day dump
(#23 relay-downgrade = already REPLACED by construction; #24 CVE-2026-58056 FileTransfer
scope-bypass = inherited but moot under §2, now **FIXED** in connection.rs — an AuthConnType
allowlist in on_message (input=Remote-only, desktop-capture=Remote|ViewCamera) + a FileTransfer
capability-flag clear (keyboard/block_input/privacy_mode), verify.sh-gated). A further 2026-07-03
edit **added a normative requirement** — §7 **R-S19** (capability confinement by `AuthConnType`:
the CWE-863 class of which CVE-2026-58056 is one instance; see the R-S19 status note above) — the
first spec change in this run that is not disclosure-only; its structural closure is in progress.
The other requirements.html edits are disclosure/inventory updates (no normative requirement
changed) — the #24 confinement itself is a source change landed alongside — and the
native-codec-watch ledger is re-confirmed valid against each.
The current snapshot (matching the `scripts/native-codec-watch.sh` pin) is:

```text
7e9ec1d49a7e38cf9953f87afe8b22636e5ac4466f0ad5ba6daa5bca837f150b  requirements.html
```

`requirements.html` is not edited by routine implementation work; the only deliberate
exception is an audit-status disclosure update like this one, which re-pins the hash here,
in `scripts/native-codec-watch.sh`, and in `docs/NATIVE-CODEC-WATCH.md`.
