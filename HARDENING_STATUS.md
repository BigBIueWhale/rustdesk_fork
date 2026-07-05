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

**RESOLVED (2026-07-04) — the GUI/coherence backlog is CLOSED.** The six-audit sweep found the
cryptographic/transport core clean (0 security hazards) and enumerated the surrounding
structural-coherence debt (~80 orphaned-scaffolding sites, 7 user-visible correctness defects, 1 live
latent race). That backlog is now IMPLEMENTED in full (36 files, +441/−1790, reviewed to standard):
the re-key "Password Required" loop is fixed, and the whole dead-scaffolding stratum
(2FA/trusted-devices, the attended-accept + permission-widener IPC pipelines, the rendezvous
online-status cluster, socks/change_id/relay/`IdPk` residue) is excised. **Superseded (host-key
retirement):** the R-S17 fingerprint/first-contact-pin/`--get-fingerprint` GUI items in that sweep
were subsequently RETIRED with the whole host-key subsystem — the CPace PRS is now derived from the
password alone (fixed salt, R-P1) and there is no host identity, host-proof, or local pin (R-P5), so
the fingerprint boards, the pin/known-hosts dialogs, and the `--get-fingerprint`/`--pin-host` CLI are
removed, not fixed. All source gates green (the
`verify-release` bundle + `flutter-verify`), zero dangling references across all five platforms, and
R-B2 reproducibility re-proven per release (build-release.sh → dist/SHA256SUMS, double-build A==B per
target). Detail is retained as the implementation record in the
`## ✅ CLOSED — the excision-vestige backlog` section below.

**§20 TCP active-router audit (2026-06-29).** The full TCP transport — both the
controlled (responder) and viewer (initiator) sides — was audited under the
*strongest* network-adversary model: both peers connected through a fully
malicious router that can inject / drop / modify / replay / reorder / reset /
segment / coalesce / flow-control-manipulate the connection at will. The
cryptographic construction reduces this attacker to (at most) a DoS: post-key
manipulation fails the Poly1305 tag (R-T7, no ≤1-byte bypass) → poison →
fail-closed; reorder/replay/drop desync the per-direction monotonic nonce
(R-A5); first-contact MITM fails the mutual PAKE; a substitute that does not know
the password fails the PAKE (one that does is out of scope per §2 — peer identity
rests on the shared password alone, with no host-key pin, R-P5); and the pre-key parsers
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
closure is DONE and gated** (`3afc51b`, after a four-agent all-platform research pass): a
`confine_capabilities_to_conn_type` derivation keys every capability boolean off the `AuthConnType`
at authorization time — *before* any peer login-option is applied, closing a real login-time ordering
window (a FileTransfer peer's `LoginRequest.option{block_input:Yes}` fired a Windows console-freeze
once before the old in-branch clear landed); the `on_message` guard is a 3-way allowlist (input +
remote-*control* reboot/privacy/virtual-display = Remote-only; desktop *capture* = Remote|ViewCamera);
and the flag-gated sinks the guard's message set misses now key on `AuthConnType`/`voice_calling` —
host clipboard-*text* write (Remote-only; the FileTransfer *file*-clipboard stays), peer→host audio
(voice-call only), cursor/window capture + whiteboard spawn + the Windows RDP session-switch
(Remote-only). The research surfaced **two instances beyond the known set**, both closed: a **HIGH**
outbound host-audio-*capture* by FileTransfer/Terminal (the audio analog of the CVE's screen capture —
closed by deriving `self.audio` from `AuthConnType`, since the `audio_service` subscribe reads
`audio_enabled()`), and cursor-position/window-focus capture. Validated: docker `cargo check` (both
feature sets), `verify.sh` all-green incl. the generalized R-S19 gate (asserts derivation-before-options
+ the 3-way guard + the sink gates), `apple-conform-check` PASS (iOS/macOS source-conformant). The
Windows-cfg `SelectedSid` edit is type-trivial (the R-B2 Windows build re-prove confirms it). `MessageQuery`
(which answers `make_display_changed_msg` — monitor geometry/resolution) is now confined to the
Remote-or-ViewCamera `is_desktop_capture` allowlist too, so a FileTransfer/Terminal/PortForward peer can no
longer read display metadata (verify.sh R-S19 asserts it). Not a §2 exposure
(all instances moot for the trusted password-holder); least-privilege coherence the actually-secure fork
carries as a MUST. **The final dedicated all-platform Opus sweep is DONE** (`60f8904`): PART 1 confirmed
the connection.rs fix is sound / not bypassable (cross-confirmed by multiple independent passes — SAS is
Remote-gated, peer-elevation is proto-excised, the headless `--service` trust model holds); PART 2 found
**four more edge instances of the same shape** the on_message dispatch didn't reach, all now closed with a
`verify.sh` "R-S19 edge residuals" gate: (1) a **screenshot** cross-source leak — SCREENSHOTS was keyed by
display index alone, so a concurrent Remote monitor loop could serve a ViewCamera peer a desktop frame
(now keyed by `(VideoSource, idx)`); (2) the **viewer-side clipboard reciprocal** — a hostile peer in a
non-default session the viewer opened could write the viewer's OS clipboard (now `is_default()`-gated,
the viewer analog of `AuthConnType::Remote`); (3) the **Windows CLIPRDR→CM** forward was unconditional
(now gated on the confined `self.clipboard && self.file`, removing a latent approve-mode-pin dependence);
(4) **Android MediaProjection** fired for view-camera/terminal (now excluded in both the Dart and Kotlin
gates). All moot under §2; validated via docker cargo check + verify.sh + apple-conform + dart-verify.
Accepted low-severity residual (no host action/capability): the video-QoS metadata arms
(`ClientRecordStatus`/`AutoAdjustFps`). Remaining: R-B2 all-3-platform build
re-prove at this HEAD (a background build loop is handling it; the connection.rs/video_service.rs changes
are in all builds, and the Windows/Kotlin edges are validated by the win-exe/apk builds).

**R-B2 — the reproducible release is produced + published by DEFAULT script runs, no manual step.** The
whole flow is opinionated + self-validating end to end, so an operator (not an AI agent) produces AND
uploads an official GitHub release with bare commands and NO env vars:

```
scripts/online-fetch.sh            # once: fetch + stage the digest-pinned toolchains / caches / VM helper
scripts/gen-android-keystore.sh    # once: mint the stable R-B2 signing key at its default location
scripts/provision-windows-vm.sh    # once: build the §12.2 Windows golden VM
scripts/build-release.sh           # each release: cold, all 3 platforms, double-build A==B -> dist/ + SHA256SUMS
scripts/publish-github-release.sh  # each release: upload dist/ as a GitHub release (draft; --publish to go live)
```

`build-release.sh` cleans from scratch and builds Debian/Android/Windows each **byte-identical
double-build A==B**, pins the release commit so the set is **coherent** (it rejects itself if HEAD moves
mid-build), and writes the authoritative manifest `dist/SHA256SUMS` (HEAD + `SOURCE_DATE_EPOCH` + the
four SHAs) — so the per-release SHAs live THERE and in the published GitHub release, never hand-copied
into this ledger. `publish-github-release.sh` refuses to publish anything not matching a clean
committed+pushed HEAD and its recorded SHAs. Three build-integrity fixes make that trust sound (each
was caught fail-loud during development, not shipped):
- **`.msi` cross-day reproducibility (`c47bca8`)** — `res/msi/preprocess.py` had stamped the wall-clock
  build date into an ARP `InstallDate` (DATE-granular: it passed a same-day double-build but differed
  across calendar days). Now `SOURCE_DATE_EPOCH`-derived (UTC, timezone-independent); verify.sh §(6) gates it.
- **clean-worktree assertion (`99fcadd`)** — deb/apk refuse a dirty/stale tree (`ALLOW_DIRTY_TREE=1` for a
  deliberate local build); the keystore + every other input default correctly, so no env var is required.
- **concurrent-commit coherence (`1405369`)** — Windows pins the commit for both double-build passes, and
  build-release.sh rejects the set if HEAD moves mid-build, so the manifest can never mislabel a
  mixed-commit set.
`verify-release.sh` (8 source gates: compile + PAKE KATs + runtime smoke + flutter analyze + Rust/Dart
advisories + the R-B2 determinism guards + the build-harness fail-loud suite) is the source-side
confirmation. The reproducible set folds in the R-S19 structural closure of CWE-863 / CVE-2026-58056
(every peer-triggerable capability derived from `AuthConnType` by construction).

Prior re-prove (superseded; its `.msi` `2d8b8aed` was later found NOT cross-day reproducible — fixed
`c47bca8` above; exe/deb/apk WERE reproducible): **R-B2 at HEAD `5e03011` (2026-07-02)** after the R-V3
crypto-audit publication (`docs/CRYPTO-AUDIT-2026-07-02.md`, VERDICT **SOUND**): deb `d15c6ed5…` / apk
`6d06a547…` / exe `beed598c…` / msi `2d8b8aed…`.

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
memory-hard Argon2id hash, never the plaintext — R-P1).
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

**The residual is armed, not latent (recorded 2026-07-05 under the universal-deployment re-rating).**
The pinned in-process decoders on the peer-reachable **viewer** path carry **open, unfixed, RCE-class
CVEs right now** (see `docs/NATIVE-CODEC-WATCH.md`, recorded 2026-06-29 against the Debian security tracker):
- **libaom 3.12.1** — the AV1 decoder (`aomdec`), reached when a hostile peer sends an `Av1s` frame:
  **CVE-2026-56211** (remote code execution), **CVE-2026-56209** (arbitrary address write),
  **CVE-2026-56210** (heap-buffer-overflow read), **CVE-2026-56208** (heap buffer overflow). No-DSA /
  unfixed across every Debian release — **no fixed aom release exists**.
- **libvpx 1.15.2** — the VP8/VP9 decoder: **CVE-2026-1861**, a decoder heap buffer overflow (malformed
  video → OOB heap write; fixed in Chrome 144.0.7559.132 via "enhanced bounds checking in the libvpx
  decoder"). The pinned 1.15.2 (a 2025 release) predates the fix; the fixed libvpx commit is not yet pinned.
All lie in the **decoder**, not the encoder (the fork encodes its own screen, so encoder-only advisories
are N/A). So the spec's "pinned ≠ CVE-free" caveat is **not hypothetical**: there are live, unfixed
memory-corruption / RCE bugs on the exact bytes an in-process viewer decodes when connected to a
hostile-but-password-correct box — in **every** binary (every build ships the full viewer, R-R2b). This
does not change the `ACCEPT`/SHOULD disposition, but it makes the SHOULD-sandbox the **highest-value open
hardening item** for a universal-deployment posture (where a viewer routinely connects to boxes it does
not control), and the strongest argument to reconsider a *narrow* decoder sandbox (a maintainer call — do
**not** unilaterally re-add the reverted subsystem). The controlled/`--server` role is **unaffected**: it
decodes no peer video (it encodes its own screen); its only inbound native decode is Opus, gated behind an
operator-accepted voice call (R-S19), plus 64 MiB-bounded zstd.

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
- **Mobile (iOS + Android) at-rest config wrapper keyed by `get_uuid()`** — the mobile face of Appendix
  C #14. On BOTH iOS and Android the
  `password_prs` at-rest wrapper is keyed by the config keypair PK (`get_uuid()` — the off-file
  `machine_uid` block is cfg-compiled out on both mobile platforms, `lib.rs:331`), which is itself
  stored in plaintext in the same TOML, so the `symmetric_crypt` wrapper adds no confidentiality over
  a plain config read. Scoped out, not fixed: §2 explicitly excludes endpoint at-rest reads, and the
  stored value is already the Argon2id PRS (a memory-hard salted hash, R-P1/R-S9) — not the plaintext
  password and not the OS/sudo credential even when those are reused — so a cold read yields only the
  connect-equivalent hash. A proper fix rebinds the **mobile** at-rest key to the iOS Keychain
  (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecUseDataProtectionKeychain`) / Android Keystore
  (AES-256-GCM, StrongBox + TEE fallback, non-auth-bound, `setUnlockedDeviceRequired(false)`) — a
  device-bound, hardware-wrapped, this-device-only random storage key — sourced ONLY by `symmetric_crypt`
  via a new `at_rest_storage_key()` seam (NOT `get_uuid()`, a separate device-id function also exported as
  the `main_get_uuid` FFI), and it MUST NOT change `derive_cpace_prs` output bytes (only the wrapper's key
  SOURCE changes). A full fail-safe design + no-data-loss proof was worked out (2026-07-06): encrypt under
  the hardware key; on decrypt try it, else **fall back to the legacy PK key and re-wrap** (the exact
  desktop pattern at `password_security.rs:203-215`/`:546`, generalized to mobile); adopt the hardware key
  only after an in-process encrypt→decrypt **self-test** passes, else degrade to today's behavior — so a
  broken Keystore/Keychain/JNI integration cannot lose data; and the ultimate backstop is that the stored
  value is `Argon2id(password)`, re-derivable by re-entering the password. It is NOT landed now: it is
  LOW-severity (both local-exfil channels below are already closed), it lives in the single
  highest-blast-radius at-rest chokepoint (`symmetric_crypt` keys EVERY at-rest secret — `config.password`
  / `password_prs`, per-peer creds, socks pw, `unlock_pin`, `enc_id`, address book), and its
  Keystore/Keychain round-trip is unverifiable on this Linux host (no device/emulator; iOS unbuildable; a
  JNI marshaling error under `panic='abort'` can hard-abort rather than surface catchably). The fail-safe
  design is ready to land after ONE on-device validation pass (Android emulator first; iOS as
  source-conformance like the fork's other Apple-gated items) — recorded as a documented residual, not a
  partial, unverifiable change. The Documents directory this wrapper
  sits in had **two** local-exfiltration channels, now closed by two separate fixes: (a) the **Files-app /
  iTunes file-sharing BROWSE** channel was closed by the APPLE-6 plist fix (dropping
  `UIFileSharingEnabled`/`UISupportsDocumentBrowser`, so the directory is no longer user-browsable); and
  (b) the **device-BACKUP** channel — iCloud and unencrypted local iTunes/Finder backups copy the
  Documents directory *regardless* of the file-sharing keys — is closed by setting
  `NSURLIsExcludedFromBackupKey` on the config directory at startup
  (`flutter/ios/Runner/AppDelegate.swift`), the iOS twin of Android's `allowBackup="false"` (R-X6).
  APPLE-6 alone did **not** close the backup vector — dropping the file-sharing keys stops browsing, not
  backup. (Source-layer fix, presence-asserted by `apple-conform-check.sh` `(2e)`; the Swift is not
  runtime-built on this Linux host, like the fork's other Apple source-conformance items. Raising the
  config's iOS data-protection class to `NSFileProtectionComplete` was assessed and declined: the default
  `CompleteUntilFirstUserAuthentication` already protects a not-yet-unlocked device, `Complete` makes the
  file unreadable whenever the device is locked — breaking backgrounded/locked config writes and
  reconnect — and it addresses only physical seizure of an unlocked-since-boot device, which §2 scopes
  out as endpoint compromise.)
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
  **Superseded (2026-07-04, host-key retirement):** the host-proof / no-TOFU host-key-pin elements
  these two audits reviewed (the `HostIdentity` Ed25519 proof, the viewer pin-compare, the DiD-1
  `set_pinned_pk` confinement gate, DiD-3's host-proof signing, and the host-key-derived PRS salt) are
  now RETIRED — the CPace PRS is derived from the password alone (fixed salt, R-P1) with no host
  identity, host-proof, or local pin (R-P5), so those specific items are moot. The audits' core
  findings on the PAKE state machine, two-key cipher, constant-time paths, R-P3 MAC, and Argon2id
  memory-hardness are UNAFFECTED and stand.
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
  **⤷ NOTE: this bullet sampled ~5 items; it is SUPERSEDED by the `## Incomplete`
  section immediately below (2026-07-03 full sweep = ~80 sites, incl. 7 user-visible
  defects + 1 live race this earlier note missed).**
- **File-transfer receive write-path no-follow (R-S8/R-A5) — POSIX handle walk confirmed
  correct-by-design.** The Unix receive-write path (`libs/hbb_common/src/fs.rs`:
  `open_parent_dir_no_follow` ~828, `open_recv_write_no_follow_std` ~979) opens **every** parent
  component with `openat(O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)` walking down from `/` (or cwd),
  then the target with `openat(O_NOFOLLOW)` (rejecting non-regular targets), and finalizes with
  `renameat`/`unlinkat`/`fstatat` under that same parent handle — a full-path **handle walk**, not a
  final-component check. This is **correct-by-design and deliberately not narrowed**: it is a
  *per-write TOCTOU* guarantee (R-A5) defending the authenticated peer's **own** privileged write
  (root on the §17 box) against a **local unprivileged** attacker racing a symlink into an
  intermediate directory or the target between validation and write. It is **not** scope-confinement —
  per §2/R-S8 the password-holding peer is trusted with full-filesystem reach as a single unconfined
  mode, and a confinement toggle is forbidden (R-S12). Two intended design consequences: (1) a receive
  destination that legitimately *traverses* a symlinked prefix (a relocated `~/Downloads` on a
  symlinked volume, a macOS firmlink, an Android `/sdcard` bind) is **refused** — the walk cannot tell
  a trusted admin-made prefix symlink from an attacker-raced one without canonicalizing, and
  canonicalizing the peer-chosen base then reopening by path would reintroduce the exact race; on the
  deployed Ubuntu box (`/home/user`, `/root` — no symlink components) it never triggers. (2) The
  proposed **narrowing** to "no-follow only the peer-relative segments, trust the base prefix" was
  **considered and rejected as a TOCTOU regression**: the peer-chosen base is uncanonicalized, so
  following base-prefix symlinks reopens the escape. The one airtight way to support symlinked-prefix
  destinations without reopening the race is a *trusted-symlink resolver* (a `chase_symlinks`/
  CHASE_SAFE walk that follows a link component only when its immediate parent is root/euid-owned and
  non-group/other-writable, else refuses) — **deferred** until a deployment concretely needs it (this
  one does not). **Both roles** ride the same shared path — server-receive (upload into the box,
  `src/ui_cm_interface.rs:1002 handle_fs` → `TransferJob::new_write`) and client/viewer-receive
  (download from a peer, `src/client/io_loop.rs:797,869`) — so R-A5's per-write assertion binds the
  viewer path too, per R-S8. Behavior-tested (`fs.rs`
  `recv_write_no_follow_refuses_symlink_{target,parent_component}` +
  `recv_finish_renameat_replaces_symlink_final_...`, `#[cfg(unix)]`) and gated by `verify.sh` (3c) /
  the R-S8/R-A5 grep gate.
- **Windows file-transfer parent-junction TOCTOU — ✅ CLOSED (applied 2026-07-05, Windows-VM-validated).**
  The Windows receive-write path now performs the same reparse-safe, handle-relative walk as the POSIX
  side — the "Windows equivalent" of `openat(O_NOFOLLOW)` that R-S8 mandates. Previously the Windows
  branch opened only the **final** component reparse-safe and let the OS resolve every intermediate
  directory *by path*, so a junction / mount-point / symlink planted on a parent between validation and
  write was followed (the intermediate-directory TOCTOU the Unix walk closes). That path-based resolve
  is replaced by the NT layer (`fs.rs` module `nt_nofollow`, `#[cfg(windows)]`): open the volume root
  once via Win32 (`FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` — the analogue of the Unix
  `/` anchor), then walk each `Normal` component with `NtCreateFile` +
  `OBJECT_ATTRIBUTES{ RootDirectory = parent_handle, ObjectName = <bare component> }` +
  `FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE` (the real `openat` equivalent — resolves relative to
  the parent HANDLE and opens the reparse point itself instead of traversing it), fail-closed
  **rejecting** any component whose handle reports `FILE_ATTRIBUTE_REPARSE_POINT` (catches NTFS
  **junctions**, `IO_REPARSE_TAG_MOUNT_POINT`, *and* symlinks — the junctions `is_symlink()` misses).
  The final target is opened relative to the walked handle, and the finalize/cleanup steps that also
  shared the old gap are now handle-relative too: rename via
  `NtSetInformationFile(FileRenameInformation, RootDirectory=parent)`, and digest/sidecar read+delete
  relative to the walked parent — so no step re-resolves a parent by path.
  `validate_no_symlink_components` is made junction-inclusive on Windows
  (`file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT (0x400)` — the primitive
  `src/platform/windows/acl.rs::is_reparse_point` uses) as defense-in-depth atop the walk (being a
  separate syscall from the open, that stat is TOCTOU-prone on its own, so it complements rather than
  replaces the handle walk). **Both roles** on Windows — server-receive (upload; the `--cm` process's
  `ui_cm_interface.rs handle_fs` → `TransferJob::new_write`) and viewer-download (`io_loop.rs`) — ride
  the same `fs.rs` path, so R-A5's per-write no-follow guarantee now binds the viewer path on Windows too.
  **Severity was LOW, Windows-only** (the deployed box is Ubuntu/Xorg — unaffected). **Privilege reality
  (corrected — the earlier "SYSTEM / service account" wording overstated it):** the redirected write
  would have run at the **interactive logged-in user's** privilege, **not** SYSTEM. On Windows the
  SYSTEM `--server` does not write received files itself — it forwards the file bytes over IPC to the
  `--cm` connection-manager, which runs in the *active user's* session (an explorer /
  `CreateProcessAsUserW` token via `run_as_user`) and performs the actual `open_recv_write`; the
  viewer/download side likewise writes as the user running the client. So the (now-closed) exposure was
  a **local cross-user write-redirection**, capped at the interactive user's privilege, not a
  SYSTEM-LPE. Exploitation still needed a co-located **local** principal able to plant/swap a reparse
  point on an intermediate directory **on** the receive path *and* writable by them: creating an NTFS
  **junction** needs **no** privilege (`mklink /J` / `FSCTL_SET_REPARSE_POINT`), a **symlink** needs
  `SeCreateSymbolicLinkPrivilege`/Developer-Mode — but either way write access to that specific dir,
  which the default per-user download dir (ACL'd to the owner) denies a lower-privileged user; the
  practical exposure was a **non-default** receive path traversing a directory writable by a
  lower-privileged principal. Hence LOW — and now closed regardless.
  **Validated in the §12.2 Windows VM (2026-07-05).** The fork's rule is *never ship a raw-NT-syscall
  Windows security change that cannot be run here* (a mis-shaped
  `OBJECT_ATTRIBUTES`/`UNICODE_STRING`/`FILE_RENAME_INFORMATION` = memory corruption), so the walk was
  built correct-by-construction from primary sources (the `cap-std` Windows resolver, the `ntapi 0.4.1`
  + `winapi 0.3.9` struct/fn shapes, and the ntifs docs) **and then type-checked + run on real Windows**:
  `cargo test -p hbb_common --target x86_64-pc-windows-msvc --lib fs::tests` under the pinned Rust 1.75
  (MSVC) **compiled and passed 25/25** (1 privileged-symlink e2e `ignore`d), including the new
  `#[cfg(windows)]` junction tests that plant an NTFS junction (`mklink /J`, unprivileged) as the
  intermediate/final component and assert: a junction **parent** is REFUSED and does not redirect the
  write out of tree (`recv_write_no_follow_refuses_junction_parent_component`); a junction **final**
  component is REFUSED and its target directory is untouched (`..._refuses_junction_final_component`);
  a legit nested non-junction path SUCCEEDS (`..._allows_regular_nested_target_windows`); the
  junction-inclusive validate rejects (`validate_no_symlink_components_rejects_junction_windows`); and
  the handle-relative finalize renames on a clean path yet refuses a junction parent
  (`recv_finish_rename_windows_happy_path` / `recv_finish_refuses_junction_parent_windows`).
  (The earlier boundary — `cargo check --target x86_64-pc-windows-msvc` fails on *this Linux host* at the
  native-C-dep build, `zstd-sys`/`sodiumoxide`/`ring` needing MSVC `lib.exe` — is why the change is
  validated in the VM, not on the host; the VM has Rust 1.75-msvc + VS Build Tools + the Win11 SDK.)
  **Gated:** `verify.sh` now asserts the Windows walk tokens (`mod nt_nofollow`, `NtCreateFile`,
  `OBJECT_ATTRIBUTES`, `oa.RootDirectory = parent`, `FILE_OPEN_REPARSE_POINT`, `FILE_DIRECTORY_FILE`,
  `FILE_ATTRIBUTE_REPARSE_POINT`, `FileRenameInformation`, the `nt_nofollow::*` wiring, the
  junction-inclusive `is_symlink_or_reparse_point`, the junction tests, and the `ntapi` dep) alongside
  the Unix `openat`/`O_NOFOLLOW` tokens — closing the gate's prior **Windows false-green** (it grepped
  only the always-present `#[cfg(unix)]` tokens, so the `cfg(not(unix))` receive-write branch went
  entirely unasserted on a Windows build). **New dependency:** `ntapi = "0.4"` (already resolved in the
  lock, built on the same `winapi 0.3` hbb_common already uses — no new external crate lineage) plus the
  winapi `ntdef`/`fileapi` features. (The `fs.rs` module doc-comment describes the walk in full; the
  code + the VM-run tests are the record.)

## ✅ CLOSED — the excision-vestige backlog + the R-S17 pin-GUI defects (implemented 2026-07-04)

> **⤷ SUPERSEDED (2026-07-04, host-key retirement).** The R-S17 pin-GUI items in this record — I-1
> (fingerprint boards render), I-2 (first-contact fingerprint-entry pin dialog), I-3 (host-key-mismatch
> re-key loop), and I-8 (`--get-fingerprint` phantom-key race) — described fixes to the host-key /
> fingerprint / known-hosts subsystem, which has since been **RETIRED in full** (spec `16b67a2`). The
> CPace PRS is now derived from the password alone (fixed salt, R-P1); there is no host identity,
> host-proof, or local pin (R-P5). So the fingerprint boards, the pin/known-hosts dialogs, the
> `HostIdentity` frame, and the `--get-fingerprint`/`--pin-host`/`--forget-host` CLI are **removed, not
> fixed** — those I-items are retained below only as the historical record. The non-pin items in this
> backlog (the dead-scaffolding excisions) stand.

**✅ STATUS: ALL CLOSED — 2026-07-04.** The backlog enumerated below was IMPLEMENTED in full by a
single coherent excision pass (36 files, **+441 / −1790**) and reviewed to standard: all source gates
green (the `verify-release` bundle — verify.sh / smoke-server / dart-verify / native-codec-watch /
apple-conform / audit / dart-audit / test-build-faillo — plus `flutter-verify` for the flutter-feature
Rust), **zero dangling references across all five platforms** (Rust / Dart / Kotlin / Swift / proto /
tests), and R-B2 reproducibility re-proven per release (build-release.sh → dist/SHA256SUMS, double-build
A==B per target). The four tiers below are **retained as the implementation record** — each item's
problem statement and the fix that closed it.

**The original finding (2026-07-03).** Six independent Opus-1M code audits swept the entire auth /
identity / online-status / connection-manager / server-config / viewer-peer-list surface, every
load-bearing claim re-verified against source by hand. The verdict was **behaviorally sound but
structurally incomplete** — every user-visible control and every security path was correctly
neutralized and failed closed (**zero security hazards, zero peer-reachable bugs**), but the excisions
had left a large stratum of **orphaned plumbing**: dialogs that could never open, FFI shims with no
caller, IPC enum variants nothing sent, state flags stuck forever in one branch, and helpers that
returned the semantic opposite of their name — **~80 distinct dead-or-wrong sites, ~15 root excisions**
(rendezvous/`register_pk`, relay, 2FA/OTP, TOFU→R-P1 salt-is-the-pin, account/address-book, QR,
numeric-ID→direct-address, socks/proxy, attended-accept, permission-widener).

**Why it was non-negotiable.** "Excise, don't disable," **R-G1 "remove, don't grey,"** and **R-S12 "no
defaulted-off-but-present"** are the whole point of this project — and they apply one level down, to
plumbing, exactly as they apply to visible toggles. A codebase that advertises itself as
secure-by-assertion and "correct as if written correctly from the first place" could not carry a
rendezvous signed-id verifier nothing calls, a two-factor-auth pipe wired end-to-end behind a trigger
that never fires, or a "Password Required" dialog whose OK button authenticates nothing. Dead code that
*looks alive* is worse than a stale comment: it makes the next auditor reason about a data flow that
does not exist. That entire stratum is now gone — the tiers below record each site and its fix.

### Tier 1 — user-visible correctness defects ✅ DONE (a user SAW these)

- **[I-1] The box's own R-S17 fingerprint renders BLANK on every GUI screen — the worst item in
  this document.** `ui_interface::get_fingerprint` gates the value on `Config::get_key_confirmed()`
  (desktop via `src/ipc.rs:847`, mobile via `src/ui_interface.rs:1090`), but
  `Config::set_key_confirmed(true)` is called **nowhere in the entire tree** — the only thing that
  ever flipped it true was the *excised* rendezvous `register_pk` acknowledgement (only
  `set_key_confirmed(false)` survives: `ipc.rs:870`, `ipc.rs:1519`, `ui_interface.rs:1299`; `= true`
  appears solely in a config-parser unit test). The flag is therefore permanently false and the
  fingerprint shows **empty** on the desktop home board
  (`flutter/lib/desktop/pages/desktop_home_page.dart:214`), the mobile server page
  (`flutter/lib/mobile/pages/server_page.dart:357`), and mobile settings
  (`flutter/lib/mobile/pages/settings_page.dart:459`). This guts the trust model in the one place it
  matters most: R-S17 is "the operator reads the box's fingerprint out-of-band and the viewer pins
  it," and the screen meant to *show* that fingerprint shows nothing. Only the headless
  `--get-fingerprint` still works (it computes the fp directly, ungated) — which is exactly why the
  deployed `--server` box appears fine while every GUI is broken. **FIX (opinionated):** DELETE the
  gate; do NOT "set the flag true." A direct-IP fork with no rendezvous has nothing to confirm, and
  the self-generated Ed25519 key is *always* present (`Config::get_key_pair()` generates it on first
  read). Return `pk_to_fingerprint(get_key_pair().1)` unconditionally at both sites, and excise the
  whole `key_confirmed`/`keys_confirmed` concept (also `OnlineStatus.confirmed`/`ConfirmedKey`, Tier 4).

- **[I-2] The first-contact pin dialog HANGS; on mobile it means the app connects to NOTHING, ever.**
  Because the CPace password (PRS) is Argon2id-salted with the pinned host key (R-P1), the viewer
  bails *before keying* when there is no pin (`src/client.rs:347`) — the host key is never received,
  so `pending_host_pk` stays `None`. The shared Flutter first-contact dialog `hostNotPinnedDialog`
  (`flutter/lib/common/widgets/dialog.dart:586`, desktop+mobile) then shows a **"Trust"** button
  whose `bind.sessionPinHost` → `set_pin_host_and_reconnect` (`src/ui_session_interface.rs:1319`)
  finds `pending_host_pk == None`, logs "refusing," and returns **without reconnecting** — while the
  dialog has already thrown up a `showLoading("Connecting…")` spinner. Net: the spinner hangs forever,
  no fingerprint is shown, and there is no field to type one into. The dialog is a vestige of the
  pre-R-P1 trust-on-first-use design; its own comment ("the box keyed… show the fingerprint")
  describes a flow that can no longer happen. Desktop users can escape via the `--pin-host` CLI;
  **Android/iOS have no CLI and no deep-link/QR/import pin channel, so a fresh mobile install
  literally cannot connect to any host.** **FIX:** replace the dead "Trust" with a fingerprint-ENTRY
  dialog (paste the out-of-band fingerprint → a new FFI `session_pin_host_by_fingerprint(session_id,
  hex)` → `host_pin::set_pinned_pk` → reconnect), mirroring the working `hostMismatchDialog`
  text-field pattern (`dialog.dart:641`). That is the only honest UI for a no-TOFU design.

- **[I-3] A legitimately re-keyed host dead-ends the viewer in an eternal "Password Required" loop.**
  If the box is wiped and re-provisioned (new Ed25519 key, password re-set → `password_prs`
  re-derived under the new key, read at `src/server.rs:426`), a viewer still pinned to the OLD key
  derives a PRS under the old key → the salts differ → **CPace fails first** (`src/client.rs:370`),
  and that failure is routed to the pre-keying password prompt (`src/client.rs:3074`, "Password
  Required"). Re-typing the correct password re-derives the same non-matching PRS → identical failure
  → infinite loop, with **no hint** the real cause is a changed host key. The elaborate
  `hostMismatchDialog` re-pin UI is **unreachable** here (it requires CPace to *succeed* yet the proof
  key to differ — a contrived stale-PRS corruption, never a normal re-key), and even when reached it
  does **not** restore connectivity (re-pinning rewrites known_hosts but does not re-derive the host's
  PRS — only a host-side `--password` heals it). **FIX:** route "CPace handshake failed" to a message
  naming BOTH causes ("wrong password OR the box's host key changed — re-verify the fingerprint
  out-of-band and re-pin"), and delete the near-dead mismatch machinery (`client.rs:400` branch +
  `hostMismatchDialog`) or make a key change genuinely distinguishable.

- **[I-4] A dead "Sort by → Status" option in the peer menu.** `PeerSortType.status = 'Status'`
  (`flutter/lib/common/widgets/peers_view.dart:28`) is offered in the Favorites sort menu; its
  comparator `peers.sort((p1, p2) => p1.online ? -1 : 1)` (`peers_view.dart:389`) reads `peer.online`,
  which is **always false** (the rendezvous online query is a no-egress stub, Tier 4), so the sort is
  a visible no-op. **FIX:** remove `status` from `PeerSortType.values`.

- **[I-5] Stale numeric-ID-era labels "Remote ID" / "Search ID" render literally.**
  `PeerSortType.remoteId = 'Remote ID'` (`peers_view.dart:25`) and the "Search ID" hint
  (`flutter/lib/desktop/pages/peer_tab_page.dart:727`) are absent from `src/lang/en.rs`, so they
  display verbatim — numeric-rendezvous-ID wording in a fork whose identity is a direct address.
  **FIX:** relabel to "Remote address" / "Search address."

- **[I-6] There is NO saved-credential indicator anywhere, and the one that exists is misdesigned.**
  The peer-card key/lock badge `_shouldBuildPasswordIcon` (`flutter/lib/common/widgets/peer_card.dart:163`)
  is gated on `currentTab == PeerTabIndex.ab.index` — the address-book tab, structurally disabled
  (`isEnabled = [true,true,false,false]`) — so it **never renders**, and it reads the old shared-AB
  `peer.password` field rather than the per-address PRS the fork actually stores. **FIX:** re-gate on
  `mainPeerHasPassword(peer.id)` for the recent/favorite tabs so the lock reflects the real PRS.

- **[I-7] iOS advertises camera + photo-library access "to scan QR codes" for a scanner that was
  excised.** `flutter/ios/Runner/Info.plist:73-76` still declares `NSCameraUsageDescription`
  ("…to scan QR codes") and `NSPhotoLibraryUsageDescription` ("…to get QR codes from image"), but the
  QR scanner (`scan_page.dart`) and its `rustdesk://config` import backend are gone. A straight R-G1
  "defaulted-off-but-present" trap and an **App-Store-review privacy red flag** — permissions
  requested for a capability that does not exist. **FIX:** delete both plist keys.

### Tier 2 — a LIVE latent bug ✅ DONE (not merely dead code)

- **[I-8] `--get-fingerprint` on a keyless box can make the operator pin a PHANTOM key.**
  `Config::get_key_pair()` persists a freshly-generated key via a **detached** background thread
  (`libs/hbb_common/src/config.rs:1160`); `--get-fingerprint` (`src/core_main.rs:390`) prints the
  fingerprint and immediately exits — potentially **before** that store commits. The next process then
  generates a *different* key and the box uses it, while the operator has pinned the printed
  (never-persisted) key → CPace fails forever. `set_permanent_password` is immune (it force-commits
  the key synchronously, `config.rs:1357-1370`); `--get-fingerprint` is not. The window is narrow
  (only on a brand-new box, before `--service`/a password exists — the deployed haggai box is
  unaffected because the server comes up first), but the documented onboarding order is exactly "read
  the fingerprint, then pin it," so this is a real footgun. **FIX:** have `--get-fingerprint`
  synchronously commit the key if it just generated one (or refuse on a keyless box with an actionable
  "set the password / start the service first" error).

### Tier 3 — "live-looking dead" code ✅ DONE (deleted — it had lied to the next auditor)

- **[I-9] `enterPasswordDialog` is a normal-looking "Password Required" dialog that authenticates
  NOTHING.** Its submit calls `gFFI.login()`, which sends a passwordless `LoginRequest` the host
  authorizes purely by CPace (`src/server/connection.rs:2000`). It is unreachable — the host never
  sends `LOGIN_MSG_PASSWORD_EMPTY`, and the only `LOGIN_MSG_PASSWORD_WRONG` send sits behind
  `if !self.stream.is_secured()` (`connection.rs:2007`), a branch that cannot execute because login is
  only reached on a keyed stream (R-A1). But it *looks* completely live
  (`flutter/lib/common/widgets/dialog.dart:556`) — that is the danger. Do NOT confuse it with the LIVE
  pre-keying `enterConnectPasswordDialog`. **FIX:** delete `enterPasswordDialog` and the non-`preKeying`
  branch of `_connectDialog`; delete the dead `input-password`/`re-input-password` msgbox arms
  (`client.rs:2923-2929`) and their `src/cli.rs` handlers.

- **[I-10] A connection-manager `SwitchPermission` receiver whose comment asserts a data flow that
  does not exist.** `src/ui_cm_interface.rs:591` handles a "privacy-mode rollback"
  `Data::SwitchPermission` from the connection, and its comment states "the backend currently sends
  SwitchPermission back to CM…" — but **nothing in `connection.rs`/`libs` ever constructs that
  message**; the only senders are the CM→connection direction, and `connection.rs` has no
  `SwitchPermission` arm (it falls to `_ => {}`). **FIX:** delete the receiver arm and the false comment.

- **[I-11] The `enable_trusted_devices` two-factor pipe is wired end-to-end behind a trigger that
  never fires.** Wire field (`libs/hbb_common/protos/message.proto:152`) → `REQUIRE_2FA` reader
  (`src/client/io_loop.rs:1590`) → `LoginConfigHandler` field (`src/client.rs:1362`) → getter
  (`src/ui_session_interface.rs:1382`, **zero native callers**): a fully intact, fully disconnected
  pipe — the host never sets the flag and never sends `REQUIRE_2FA` (the responder 2FA gate is
  excised, `connection.rs:1073`). Same cluster: `LOGIN_MSG_2FA_WRONG`/`REQUIRE_2FA` consts
  (`client.rs:114`); the `input-2fa` msgbox emitter that **survives on the Rust side though Dart has
  no handler** (`client.rs:2938` — a half-excision); `trust-this-device` (read `client.rs:2932`, never
  set to "Y"); and the never-instantiated Dart widgets `Dialog2FaField`/`DialogEmailCodeField`/
  `DialogVerificationCodeField` (`dialog.dart:204/278/342`). **FIX:** excise the whole
  2FA/trusted-devices cluster on both sides and drop the proto field.

- **[I-12] `IdPk` + `decode_id_pk` — dead rendezvous crypto.** `message IdPk { id; pk }`
  (`libs/hbb_common/protos/message.proto:38`) and `decode_id_pk` (`src/common.rs:1121`), which verified
  a rendezvous server's signature over an id→public-key binding, have **zero callers** and `IdPk` is
  never constructed (the one `server.rs` reference is a comment). **FIX:** delete both.

### Tier 4 — inert dead scaffolding ✅ DONE (~65 sites excised by root cause)

Safe at runtime, but each is R-G1 debt a from-scratch direct-IP fork would never contain:

- **Rendezvous online-status cluster (always-0 / always-offline):** the `ONLINE` latency map +
  `get_online_state()` are permanently 0 because `update_latency`/`reset_online` are never called
  (`config.rs:995/999`); `status_num` and the mobile `_connectStatus` getter feed off it and are dead;
  the whole viewer peer-online pipeline — `peer.online`, `_updateOnlineState`, `_cbQueryOnlines`, and a
  **300 ms poll loop with a deleted payload** (`peers_view.dart:312`, `peer_model.dart`) — spins
  forever behind an already-invisible dot (`getOnline()` → `SizedBox.shrink()`). Excise the map, the
  loop, and the pipeline.
- **`using_public_server()` returns the semantic OPPOSITE of its name** —
  `get_custom_rendezvous_server(...).is_empty()` (`src/common.rs:1133`) is always `true` in a fork
  with no rendezvous, so it reports "using the public server" when there is no server at all; its
  callers (a quality cap, a peer-loop cadence) are inert. Delete the function + FFI.
- **Viewer `direct`/relay residue:** `direct` is hardcoded `Some(true)` and
  `direct_failures`/`set_direct_failure` are dead (`client.rs:314`); the `allow_more` quality cap, the
  `retry_for_relay` misnomer, and the `getConnectionText` "Relay"→"TCP" branch are unreachable;
  `set_connection_type`'s `is_secured`/`direct` args are sent always-true and ignored by Dart.
  Simplify to unconditionally-direct.
- **Dead FFI exports (zero Dart callers):** `main_test_if_valid_server`, `main_get_proxy_status`,
  `main_handle_relay_id`, `main_resolve_avatar_url` (`src/flutter_ffi.rs`). Drop the exports.
- **Dead Rust backends:** the socks/proxy module (`set_socks`/`get_socks`/`get_proxy_status`, not
  flutter-exported, no actuator), `change_id`/`change_id_shared`, the ipc `rendezvous_server(s)` query
  answer (`ipc.rs:838`), and the `resolve_avatar_url`/`get_api_server` builder (resolves empty). Excise.
- **Dead Dart option constants:** `kOptionHideServerSetting`, `kOptionHideProxySetting`,
  `kOptionDisableChangeId`, `kOptionAllowDeepLinkServerSettings` (`flutter/lib/consts.dart:171-187`) —
  zero consumers. Delete.
- **The attended-accept IPC pipeline (8 sites, A1–A8):** because `approve-mode` is pinned to
  `"password"` (`config.rs:3176`), every connection is authorized before the CM sees it, so
  `buildUnAuthorized`, `showLoginDialog`, the `cmLoginRes`/`authorize()` accept path, and the
  `Data::Authorize` IPC variant are all dead. Excise the pipeline.
- **The runtime permission-widener IPC pipeline (5 sites, B1–B5):** the CM permission chips are
  read-only (`canModifyPermission=false`) and `connection.rs` has no `SwitchPermission` handler (dead
  sink), so `cm_switch_permission`/`switch_permission`/`switch_permission_all` and the
  `Data::SwitchPermission` variant are dead. Excise.
- **Misc:** the unshown my-numeric-ID machinery (`server_model.dart` `_serverId`/`fetchID`, fetched
  and never rendered); the serialized-but-unread `forceAlwaysRelay`/`sameServer`/`recording`/
  `block_input`/`restart` fields; `reconnect(_forceRelay)`; the `formatID` numeric-grouping
  passthrough; the `switch_sides()` empty stub; `logOut(apiServer)`; and the `--get-id` CLI (a
  meaningless numeric ID in the direct-IP model). Delete.

### Verified CLEAN — do NOT re-open these (keeps the backlog honest)

The security-critical excisions were done correctly and must not be re-litigated: the `LoginRequest`
proto is stripped to session metadata (password/os_login/hwid fields reserved+deleted,
`connection.rs:2000`); the top-level auth message types (`SignedId`, `PublicKey`, `Auth2FA`,
`SwitchSides`, `OSLogin`, `Hash`) are absent; **elevation/OS-login proto fields are retired, nothing
dangles on the wire** (`elevation_request`/`_response`/`portable_service_running`, `message.proto:839-842`
— this closes the old "R-X9 Windows-deferred" worry: there is no dangling handler); `get_key` is
pinned to `RS_PUB_KEY` ignoring any `option("key")` override (regression-tested, `common.rs:1500`);
the deep-link `config`/`password` write authorities return `null` (`common.dart:2352`); the settings
surface carries no id/relay/key/proxy/whitelist row; voice-call accept gates host audio (R-S19); the
status dot was correctly rewired to a service-listening indicator ("Listening on :21118"); and
"Remember/Forget password" are PRS-coherent (both check/clear `password` and `password_prs`).
(Corrected stale note: `maxTabCount` is **4**, not the "5→3" in an earlier record; all parallel tab
arrays are consistent at 4, no out-of-bounds risk.)

### Discipline for closing this

Excise by root cause, not by scattered line; each removal carries its own **R-B2 reproducible-build
re-prove** (Debian/Android/Windows double-build A==B) and re-runs `verify.sh` plus the out-of-loop
gates (`audit.sh`, `dart-audit.sh`, `apple-conform-check.sh`, the smoke harness). Any code-audit help
uses **Opus-1M subagents told to research extensively** — the recurring failure mode in this very
sweep was agents trusting a stale comment (e.g. "the dialog shows the fingerprint" — it does not), so
every claim must be verified against source. Tiers 1–2 are the priority (a user sees them / a box can
mis-pin); Tiers 3–4 are the coherence work that lets this tree finally read as
correct-from-the-first-place. This section supersedes the "Inert dead-code leftovers" sample above.

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
5cf47b53870ca386886ce5337e211f11adf11623110e08027de376a4a6b0902f  requirements.html
```

`requirements.html` is not edited by routine implementation work; the only deliberate
exception is an audit-status disclosure update like this one, which re-pins the hash here,
in `scripts/native-codec-watch.sh`, and in `docs/NATIVE-CODEC-WATCH.md`.
