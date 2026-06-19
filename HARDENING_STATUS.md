# Hardening implementation status

This fork is being built **into** the hardened RustDesk specified by
[`requirements.html`](./requirements.html). This file is an honest, living map of
how far the implementation has progressed against that normative spec, and what
each unfinished item needs.

## Working constraints (why some items are deferred, not skipped)

The fork is assembled under two hard constraints: **no running of code** and **no
installations**. Every change here is therefore made by source edit + static
analysis and is **build-unverified**. That is safe for *fail-loud* changes (a Rust
/ Kotlin / Dart / XML slip surfaces at the first compile) but **not** for
*fail-silent* ones — cryptographic construction and security-policy funnels can be
subtly wrong while still "working", so those are deferred to a build/test-capable
pass rather than committed unverified. Two structural blockers follow from the
constraints:

- **No `cargo` ⇒ no `Cargo.lock` regen.** Dependencies cannot be added or removed
  and new crates cannot be wired into the workspace without invalidating the
  committed lockfile (`--locked`, R-R1/R-A7). This blocks every "remove the X
  crate" / "add `libs/pake` as a member" step.
- **No build/test loop** ⇒ the spec's "secure by assertion" gates (KAT vectors,
  CI greps, double-build, runtime asserts, the 206 inherited tests) cannot be
  *shown to pass* here, which is the bar the completion criterion sets.

## Status legend

`DONE` · `PARTIAL` (clean part landed, rest noted) · `DEFER-BUILD` (needs a
compile/test loop) · `BLOCK-CARGO` (needs a lockfile regen) · `RISK-SILENT`
(fail-silent; unsafe to do blind) · `TODO`

## Structural baseline & build pinning

| Area | Status | Notes |
|---|---|---|
| §16 monorepo: clone 1.4.7 (`0c86d46`), absorb `hbb_common` (`df6badc`) in-tree, strip `.git`, drop `.gitmodules` | **DONE** | `c2abd3b`; 279→264 Rust files (−15 plugin); no nested repos |
| R-R1 committed `rust-toolchain.toml` (the one pin upstream omits) | **DONE** | `f67a744`; pinned 1.75 |
| R-B9/B10/B11 build harness — manifest, helpers, provision/cleanup, design | **PARTIAL** | `fb4f4c7` (pins.env) + `lib.sh` (fail-loud helpers, R-B9/B10) + `host-provision.sh`/`cleanup.sh` (R-B11 additive-provision / reversible-cleanup pair, `34b4921`). The build-script *bodies* (build-debian/android.sh, build-windows.ps1 — upstream's exact 1.4.7 commands), `online-fetch.sh`, and `provision-windows-vm.sh` = TODO/`DEFER-BUILD`. SHA-256 digests stay the fail-closed R-B12 sentinel |
| R-R1 keep deps pinned-not-vendored | **DONE** | `Cargo.lock`/`pubspec.lock`/`vcpkg.json` untouched; nothing vendored |
| R-R2/R-R2a prune CI to 3 targets; drop appimage/flatpak/non-Debian | **PARTIAL** | `01bb8a8` deleted fdroid/nightly/playground/clear-cache. `flutter-build.yml` 14-job matrix prune + appimage/flatpak dir removal (coupled to `build.py`+`bump.sh`) = TODO |
| R-B6 drop Sciter | **DEFER-BUILD / BLOCK-CARGO** | non-flutter path is the *default* build (58 `not(feature="flutter")` blocks + the inherited tests run default-features), so a clean cut means making flutter the default/test path — a build-process change; and `sciter-rs` removal is `BLOCK-CARGO` |

## The PAKE (§10) — the core

| Area | Status | Notes |
|---|---|---|
| R-P14 `Cpace` wire message (dedicated top-level, not in `Message` union) | **DONE** | `7931abc`; additive proto |
| §10.1–10.4 CPace construction in `libs/pake` (draft-21 CPACE-RISTR255-SHA512) | **RISK-SILENT / BLOCK-CARGO** | the §10.4 KAT anchors gate correctness (R-A7/R-A10) and cannot be run here; an off-by-one in `lv_cat`/generator/ISK is silent. Crate also can't be wired without a lock regen. Full byte-level construction is captured in `.claude/ralph-progress.md` for a build pass |
| R-P2/R-P10 two-key `secretbox` rewrite (`tcp.rs`/`stream.rs`/`websocket.rs`) | **DEFER-BUILD** | ripples the public `Encrypt`/`set_key` signature; `RISK-SILENT` (single-key regression is the catastrophic bug) |
| R-S1/R-P4/R-P14 choke-point integration in `create_tcp_connection` | **DEFER-BUILD** | depends on the construction above |

## Excisions (§8)

| Req | Status | Notes |
|---|---|---|
| R-X2 native-plugin loader (`src/plugin/`, `plugin_framework`) | **DONE** | `f91dcb9`; 15 files + all 8-file refs removed, zero R-A6 tokens, behavior-neutral (was gated off) |
| R-X6 Android manifest (legacy-storage perms, fake-boot broadcast, `exported`, `allowBackup`, cleartext-deny) | **DONE** | `d4cb686` |
| R-X6 `FloatingWindowService` + `SYSTEM_ALERT_WINDOW` cut | **DONE** | `f8ddac8`; perms 12→9 |
| R-X6 deep-link config/password WRITE authorities (Dart) | **PARTIAL** | `198910d`; write authorities gone. Connect-path `?key=`/`?password=` confirmation + Rust `client.rs` adoption + D-Bus/WM/`_url` transports = `DEFER-BUILD` (Rust-entangled) |
| R-X4 trust-anchor override removal (CLI gadgets + `get_key()`) | **PARTIAL** | `201b13c` excised `--remove`/`--import-config`/`--config` + `import_config()` (R-A6 tokens zero); `59750e7` made `get_key()` return the baked `RS_PUB_KEY` unconditionally — every runtime override (the `"key"` option, IPC blob, Windows exe-name spoof) ignored, on every platform. Remainder (`mod custom_server` + its HKLM/registry/`naming`-bin callers, the Windows `get_license_from_exe_name`, `--set-id`/`--assign`/`--deploy`) = `DEFER-BUILD` (entangled w/ R-D4 account removal + Windows registry) |
| R-X1 auto-updater fetch-and-run RCE | **PARTIAL** | `26125a1`; the whole chain removed — `updater.rs` + `mod updater` + the 3 callers (mediator/ipc/flutter_ffi) + the general & macOS `--update` apply-handlers + the Flutter download-new-version/update-me/extract-update-dmg keys. `crate::updater`/`"download-new-version"`/`"update-me"` = zero. Residual: the now-unreachable platform appliers (`windows.rs update_to`/`update_me`, `macos.rs update_from_dmg`) still hold the last 2 `"--update"` tokens — Windows clean-unused removal + macOS Apple-source = `DEFER-BUILD` |
| R-X3 ConfigureUpdate twins · R-X5 LAN · R-X7 OTP/TOTP · R-X8 terminal · R-X9 Win run-mode/elevation · R-X10 Linux run-mode · R-X11 gtk_sudo · R-X12 Wayland capture · R-X13 uinput/rdp_input · R-X14 os_login PAM | **DEFER-BUILD** | entangled with R-D4 (mediator refactor) / R-B6 (Sciter) / each other, or require semantic reworks (not pure deletion), or `BLOCK-CARGO` for their dep drops (`totp-rs`, `impersonate_system`). Footprints + the de-tangling order (Sciter → mediator → the rest) are mapped in `.claude/ralph-progress.md` |

## Secure-by-assertion, policy, role split, deployment, sovereignty, GUI

| Area | Status | Notes |
|---|---|---|
| §9 R-A1–R-A10 runtime/build/test assertions | **DEFER-BUILD** | most presuppose the PAKE; the CI greps (R-A6) and KATs (R-A10) are the "secure by assertion" gates that must *run* |
| R-S16 controlled-policy `PINNED_SETTINGS` funnel | **RISK-SILENT** | modifies core `config.rs` `get_option`/`is_option_can_save`; a wrong funnel is fail-open and looks fine. Mechanism understood (funnel read), deferred for verification |
| R-S2 FSM collapse · R-S5 `set_raw` seal · R-S9 PRS-at-rest · R-S10 limiter re-key · R-S13 initiator bar · R-S17 host-key pin · R-S18 OS-credential delete | **DEFER-BUILD** | all PAKE-downstream or core-logic |
| R-R2b viewer / controlled-only build split (`decode`/`hwcodec`/`vram`/`flutter` features, `mod client` gating) | **DEFER-BUILD / BLOCK-CARGO** | feature-graph surgery; CI must assert the resolved feature set |
| R-D1–D8 deployment (systemd, v4-only, silent egress, direct-only) | **DEFER-BUILD** | overlaps R-D4 mediator refactor + R-S16 pins |
| §18 R-SV* sovereignty (kill version-check egress + `test_nat_type` probe) | **DEFER-BUILD** | shared `common.rs`/`socket_client.rs`; call-graph (not grep) removal |
| §19 R-G* GUI/UX conformance (remove selectors/toggles/dead assets/links the core no longer honors) | **TODO** | partly unblocked by the deep-link work; large Dart sweep |
| R-R3 dependency audit (Appendix D bumps) | **BLOCK-CARGO** | every fix is a lockfile change |

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
