# Hardening implementation status

This fork is being built **into** the hardened RustDesk specified by
[`requirements.html`](./requirements.html). This file is an honest, living map of
how far the implementation has progressed against that normative spec, and what
each unfinished item needs.

## Working constraints (updated — a build/test loop IS available, in docker)

Earlier iterations assumed **no running of code / no installations** and deferred
everything fail-silent. That premise was **wrong** and has been corrected: a
build/test loop is available **inside disposable docker containers** (the operator
mandate is: compile, install packages, and test *only* in temporary containers,
and never listen on `0.0.0.0`). Empirically:

- **`cargo` 1.75 (the pinned toolchain) + network work**; pure-Rust crates build
  and test directly. The `libs/pake` PAKE — the spec's core, long deferred as
  "RISK-SILENT because the KATs can't run here" — is now **KAT-verified** this way
  (16/16, incl. the published CFRG vector + both fork anchors). The `Cargo.lock`
  **was regenerated via cargo** (the additive `pake` member), so the R-R1/R-A7
  `--locked` invariant is *maintained*, not blocked.
- The **full workspace** still needs native system libs (OpenSSL, libsodium,
  libvpx/yuv/aom, …) that aren't on the host (no passwordless sudo) — but those
  install with `apt` **inside a container**, so the OpenSSL-linked crates
  (`hbb_common` and the two-key secretbox rewrite) are build-verifiable there.
- **The FULL main crate now `cargo check`s in docker** (`scripts/Dockerfile.devcheck`,
  `cargo check --features linux-pkg-config` — distro libvpx/aom/yuv via scrap's
  pkg-config path + a synthesized `libyuv.pc`). This **re-classifies every
  DEFER-BUILD main-crate item below as now-verifiable** — the choke-point cutover,
  the §8 excisions (R-X5/7/8/9/10/11/13/14, R-D4), the §9 main-crate asserts. Only
  the **flutter** build (FRB codegen) and the two-host R-A8/A9 wire tests remain
  out of this loop.

What stays genuinely deferred is only what needs the heavy full-app pipeline or a
real two-host network (the active-attacker R-A8/A9 wire tests), and the items not
yet implemented. Fail-loud source edits still surface at first compile; fail-silent
work (crypto/policy) is now **verified in-container, not committed blind**.

## Landed vs. remaining (quick read)

**Landed and inspection-verified** (the structured-creation pass, ~45 commits):
the structural monorepo (1.4.7 + absorbed `hbb_common`, `.git` stripped); the
toolchain/version pinning + `rust-toolchain.toml`; the **complete build harness**
(9 scripts) + the R-B2 determinism patch; the `Cpace` PAKE wire format; the §8
excisions **R-X1** (updater RCE), **R-X2** (plugin loader), **R-X3** (all 3 re-home
twins), **R-X4** (CLI gadgets + `get_key` trust-anchor pin), **R-X6** (Android +
deep-link writes), **R-X12** (display-server env knob); **R-F4** (direct-port pin);
**R-D3a** (systemd confinement); **R-SV8** (iOS entitlements).

**NOT done** (and why) — this is the load-bearing honesty: the **CPace
construction** (§10.4, RISK-SILENT — gated on KATs that can't run here), the
**two-key secretbox rewrite + choke-point integration** (§10/R-P14), the **§9
assertions**, the **R-S16 policy funnel** (RISK-SILENT, fail-open if wrong), the
**R-R2b role split**, the **R-S18/R-D4/R-B6-coordinated excisions** (R-X5/7/8/9/10/
11/13/14, Sciter, mediator), and the **R-R3 dependency audit** (BLOCK-CARGO). These
are the *majority* of the security spec by substance, and they require a
build/test loop — which the "no running of code" constraint precludes — to do
*correctly and verifiably*. **The project is therefore NOT "implemented in full,
correctly."** Doing the fail-silent work (crypto/policy) blind would be the opposite
of the spec's secure-by-assertion intent, so it is deferred, not faked.

## Status legend

`DONE` · `PARTIAL` (clean part landed, rest noted) · `DEFER-BUILD` (needs a
compile/test loop) · `BLOCK-CARGO` (needs a lockfile regen) · `RISK-SILENT`
(fail-silent; unsafe to do blind) · `TODO`

## Structural baseline & build pinning

| Area | Status | Notes |
|---|---|---|
| §16 monorepo: clone 1.4.7 (`0c86d46`), absorb `hbb_common` (`df6badc`) in-tree, strip `.git`, drop `.gitmodules` | **DONE** | `c2abd3b`; 279→264 Rust files (−15 plugin); no nested repos |
| R-R1 committed `rust-toolchain.toml` (the one pin upstream omits) | **DONE** | `f67a744`; pinned 1.75 |
| R-B7/B9/B10/B11/B12 build harness — all 9 scripts + determinism patch | **DONE** (structure) | `pins.env` + `lib.sh` + `host-provision`/`cleanup` (R-B11) + `online-fetch` (R-B10) + `build-debian`/`build-android`/`build-windows.ps1` + `provision-windows-vm.sh` (R-B7/B8/B9/§12.1/§12.2) + the R-B2 `gen_version` SOURCE_DATE_EPOCH patch (`c5429a4`). Every version pinned + verified in-tree. **Cannot be run/verified under no-run**; SHA-256 digests stay the fail-closed R-B12 sentinel (audited bootstrap is online); the R-R2b controlled-only build profile awaits the Cargo feature split |
| R-R1 keep deps pinned-not-vendored | **DONE** | `Cargo.lock`/`pubspec.lock`/`vcpkg.json` untouched; nothing vendored |
| R-R2/R-R2a prune CI to 3 targets; drop appimage/flatpak/non-Debian | **PARTIAL** | `01bb8a8` deleted fdroid/nightly/playground/clear-cache. `flutter-build.yml` 14-job matrix prune + appimage/flatpak dir removal (coupled to `build.py`+`bump.sh`) = TODO |
| R-B6 drop Sciter | **DEFER-BUILD / BLOCK-CARGO** | non-flutter path is the *default* build (58 `not(feature="flutter")` blocks + the inherited tests run default-features), so a clean cut means making flutter the default/test path — a build-process change; and `sciter-rs` removal is `BLOCK-CARGO` |

## The PAKE (§10) — the core

| Area | Status | Notes |
|---|---|---|
| R-P14 `Cpace` wire message (dedicated top-level, not in `Message` union) | **DONE** | `7931abc`; additive proto |
| §10.1–10.4 CPace construction in `libs/pake` (draft-21 CPACE-RISTR255-SHA512) | **DONE — KAT-VERIFIED** | `339b3dd`; construction (lv_cat/o_cat/generator_string/ISK/HKDF/MACs) + R-P14a type-state machine (both roles) + R-P1/2/3/5/6/7/8/9/11/12/14c. **Built & tested in a disposable `rust:1.75-slim` container under the pinned toolchain + pinned lock — all 16 KATs pass**: the CFRG draft-21 published ristretto255 vector (g=`222b6b19…`/ISK_SY=`544199d7…`), fork anchor A (16B sid) and anchor B (32B sid, driven through the full state machine), plus the adversarial set (AD-mismatch, identity, decode, wrong-password→Confirmation, empty-PRS, replay-abort, NFC cross-spelling). No new external crate; lock regen is the single additive `pake` entry (1059→1060, R-R1/R-A7 held). Constraint correction: the "KATs can't run here" premise was false — pure-Rust crates build+test in docker (see memory). |
| R-P2/R-P10 two-key `secretbox` rewrite | **PARTIAL — keying engaged & VERIFIED** | `5ec40de` `DirectionalCipher` (R-P10 fix) + `0108349` `tcp::StreamCipher{Single,Dual}` now backs `FramedStream`/`WsFramedStream`/`Stream` with `set_session_keys(DirectionalKeys)`. **Verified end-to-end on the pinned toolchain**: a CPace handshake over a loopback socket → `set_session_keys` → an app frame travels encrypted and decrypts on the peer both directions (cpace_it, 6 tests). Non-breaking (legacy `set_key` kept for the not-yet-cut SignedId/box_ callers). REMAINING: the choke point calls `set_session_keys` (cutover below), then remove the single-key `set_key`/`Encrypt`/`box_` (R-A6) |
| R-S1/R-P4/R-P14 choke-point integration in `create_tcp_connection` | **PARTIAL — driver wire-VERIFIED** | `5ec40de`; `cpace::run_responder`/`run_initiator` drive the full handshake (Cpace proto ↔ pake state machine, R-P14a ordering, R-P14b bounded reads, R-P14c limiter taxonomy), **verified end-to-end on the pinned 1.75 toolchain** by the `cpace_it` crate (4 tests, incl. wrong-password→Confirmation and out-of-order→Protocol). REMAINING (main crate, fail-loud at full build): call the drivers from `server.rs`/`client.rs`, drop the `if secure` SignedId↔PublicKey bootstrap + `box_`/`sign` (R-P5/§8), adapt `common.rs` secure_tcp |

## Excisions (§8)

| Req | Status | Notes |
|---|---|---|
| R-X2 native-plugin loader (`src/plugin/`, `plugin_framework`) | **DONE** | `f91dcb9`; 15 files + all 8-file refs removed, zero R-A6 tokens, behavior-neutral (was gated off) |
| R-X6 Android manifest (legacy-storage perms, fake-boot broadcast, `exported`, `allowBackup`, cleartext-deny) | **DONE** | `d4cb686` |
| R-X6 `FloatingWindowService` + `SYSTEM_ALERT_WINDOW` cut | **DONE** | `f8ddac8`; perms 12→9 |
| R-X6 deep-link config/password WRITE authorities (Dart) | **PARTIAL** | `198910d`; write authorities gone. Connect-path `?key=`/`?password=` confirmation + Rust `client.rs` adoption + D-Bus/WM/`_url` transports = `DEFER-BUILD` (Rust-entangled) |
| R-X4 trust-anchor override removal (CLI gadgets + `get_key()`) | **PARTIAL** | `201b13c` excised `--remove`/`--import-config`/`--config` + `import_config()` (R-A6 tokens zero); `59750e7` made `get_key()` return the baked `RS_PUB_KEY` unconditionally — every runtime override (the `"key"` option, IPC blob, Windows exe-name spoof) ignored, on every platform. Remainder (`mod custom_server` + its HKLM/registry/`naming`-bin callers, the Windows `get_license_from_exe_name`, `--set-id`/`--assign`/`--deploy`) = `DEFER-BUILD` (entangled w/ R-D4 account removal + Windows registry) |
| R-X1 auto-updater fetch-and-run RCE | **PARTIAL** | `26125a1`; the whole chain removed — `updater.rs` + `mod updater` + the 3 callers (mediator/ipc/flutter_ffi) + the general & macOS `--update` apply-handlers + the Flutter download-new-version/update-me/extract-update-dmg keys. `crate::updater`/`"download-new-version"`/`"update-me"` = zero. Residual: the now-unreachable platform appliers (`windows.rs update_to`/`update_me`, `macos.rs update_from_dmg`) still hold the last 2 `"--update"` tokens — Windows clean-unused removal + macOS Apple-source = `DEFER-BUILD` |
| R-X3 server-list / config re-home twins (all 3) | **DONE** (behavior) | All 3 re-home writes neutralized on every build: `handle_config_options` (sync.rs, `c658967`), the `TestNatResponse.cu` rewrite (common.rs, `557982a`), and the mediator `ConfigureUpdate` arm (`28c328e`). Full *token*-absence (R-A6 grep) of `mod sync`/NAT-probe/mediator comes with R-D4's cfg-gating; the behavior is closed now, defense-in-depth |
| R-X12 capture-backend pin (forced-display-server env knob) | **PARTIAL** | `340f9b4`; the `RUSTDESK_FORCED_DISPLAY_SERVER` runtime override removed (R-A6 token zero). The structural twin — drop the `wayland` scrap feature + gate the ~20 ungated `Display::WAYLAND`/`Capturer::WAYLAND` refs in `scrap/common/linux.rs` + pin `is_x11()` true — is a coordinated scrap change = `DEFER-BUILD` |
| R-X5 LAN · R-X7 OTP/TOTP · R-X8 terminal · R-X9 Win run-mode/elevation · R-X10 Linux run-mode · R-X11 gtk_sudo · R-X13 uinput/rdp_input · R-X14 os_login PAM | **DEFER-BUILD** | entangled with R-D4 (mediator refactor) / R-B6 (Sciter) / each other, or require semantic reworks (not pure deletion), or `BLOCK-CARGO` for their dep drops (`totp-rs`, `impersonate_system`). Footprints + the de-tangling order (Sciter → mediator → the rest) are mapped in `.claude/ralph-progress.md` |

## Secure-by-assertion, policy, role split, deployment, sovereignty, GUI

| Area | Status | Notes |
|---|---|---|
| §9 R-A1–R-A10 runtime/build/test assertions | **PARTIAL — gate RUNS** | `a583fd9` `scripts/verify.sh` is the executable §9.3/R-V3 assurance basis: it RUNS the R-A10 KATs (pake 16 + cpace_it 5 + config_it), compile-checks the main crate (lockdown off/on), and hard-gates the **R-A6** greps for the completed excisions (R-X1/X2/X4-CLI/X6/X12 = 0 tokens) — all green. **R-A5** engaged-keys assertion done (`7394561`). REMAINING: the PAKE-downstream runtime asserts R-A1/A2/A3 (no-message-before-keying, authorized-only-on-KEYED-edge, set_raw seal) land with the choke-point cutover; R-A6 turns red→green per excision as each lands; R-A8/A9 are the two-host active-attacker/wire tests |
| R-S16 controlled-policy `PINNED_SETTINGS` funnel | **PARTIAL — config funnel VERIFIED** | `675514b`; (a) `keys::PINNED_SETTINGS` table + (b) `get_option` read funnel + (c) `is_option_can_save` write guard, behind a new `lockdown` feature (empty/no-op when off). **Tested on the pinned 1.75 toolchain** (`config_it` crate, lockdown on): every pinned key returns its policy value and resists override, non-pinned keys unaffected. Was RISK-SILENT (fail-open if wrong) — now behavior-pinned. **R-S16(d)(i) done** (`af15880`): the main-crate `lockdown` feature + `Connection::permission` early-return skipping the `control_permissions` server-push bypass — compile-verified both lockdown on/off. REMAINING: `get_builtin_option` (d)(iv) mirror (only if a KEYS_BUILDIN value is ever pinned), and R-S16's password-storage twin (PRS-at-rest, part of the choke-point cutover) |
| R-S2 FSM collapse · R-S5 `set_raw` seal · R-S9 PRS-at-rest · R-S10 limiter re-key · R-S13 initiator bar · R-S17 host-key pin · R-S18 OS-credential delete | **DEFER-BUILD** | all PAKE-downstream or core-logic |
| R-R2b viewer / controlled-only build split (`decode`/`hwcodec`/`vram`/`flutter` features, `mod client` gating) | **DEFER-BUILD / BLOCK-CARGO** | feature-graph surgery; CI must assert the resolved feature set |
| R-F4 direct port pinned to compile-time `21118` | **DONE** | `128d838`; new `config::DIRECT_PORT = 21118`, `get_direct_port` returns it unconditionally (no config read, no rendezvous+2 derivation) — load-bearing for the §10.4 CPace `CI` KAT be16(21118)=527e. The orphaned `direct-access-port` UI setting is a §19 cleanup |
| R-D3a systemd confinement of the root service | **DONE** | `64e11b4`; the exact R-D3a directive set (CapabilityBoundingSet, RestrictAddressFamilies=AF_UNIX AF_INET, ProtectKernel*, SystemCallFilter, …), NoNewPrivileges deliberately omitted, MemoryDenyWriteExecute documented-but-disabled pending runtime validation |
| R-D1/D2/D4–D8 deployment (direct-only build, v4-only, silent egress, config pins) | **DEFER-BUILD** | R-D4 is the mediator refactor (lift `direct_server`→`start_direct_only`); overlaps R-S16 pins + R-R2b build split |
| R-SV8 iOS entitlements (APNs push + wifi-info) | **DONE** | `dd3be96`; both removed (no-phone-home), `associated-domains` confirmed absent (R-X6). macOS entitlements left (functionally required, retain-and-check); iOS `SDWebImage` pod = finding, removal pod-regen-blocked; no Firebase/analytics pod (R-SV8 holds) |
| §18 R-SV3/SV4 sovereignty (kill version-check egress + `test_nat_type` probe) | **DEFER-BUILD** | shared `common.rs`/`socket_client.rs`; call-graph (not grep) removal, R-D4-tied |
| §19 R-G* GUI/UX conformance (remove selectors/toggles/dead assets/links the core no longer honors) | **TODO** | partly unblocked by the deep-link work; large Dart sweep |
| R-R3 dependency audit (Appendix D bumps) | **TODO (lock-regen now possible in docker)** | lock can be regenerated under cargo in-container, so bumps are no longer blocked. **New finding:** the `webrtc` 0.14 dev-dependency pulls `sdp` 0.10.0, which calls `usize::is_multiple_of` (unstable on the pinned 1.75 **and** on 1.96) — so `cargo test -p hbb_common` does not compile on the pinned toolchain, blocking the inherited tests + the §9 R-A8/A9/A10 gates that live in hbb_common. Worked around for the PAKE via the isolated `cpace_it` crate (depends on hbb_common's library only, no dev-deps); a real fix is an R-R3 bump of `sdp`/`webrtc` (or dropping the webrtc transport under R-R2). |

## Roadmap for a build-capable continuation

1. Stand up the build env (the `scripts/` harness, R-B7 baseline parity first).
2. **De-tangle in order:** R-B6 Sciter (make flutter default; drop `sciter-rs` with a
   lock regen) → R-D4 mediator (extract `direct_server`→`start_direct_only`) → then
   R-X1/R-X3/R-X4/R-X5/R-X11/R-F4 fall out near-self-contained.
3. Implement `libs/pake` against the §10.4 KAT anchors; wire it + the two-key
   `secretbox` rewrite + the choke point (R-P14); run the KAT/negative suite.
4. Land R-S16 `PINNED_SETTINGS` and the §9 assertions; make the R-A6 CI greps green.
5. R-R2b build split, R-R3 audit, §19 GUI sweep, R-R2 CI prune, smoke-tests (R-B4).

The commit history is the per-change record (each message cites its requirement and
what it defers); this file is the per-requirement overview.
