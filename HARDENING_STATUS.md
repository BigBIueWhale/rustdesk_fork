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

**Landed — compile/test-verified in docker** (the structured-creation pass plus
the docker-build phase that overturned the false "no-build" premise; pinned 1.75
toolchain, `scripts/verify.sh` is the running gate): the structural monorepo
(1.4.7 + absorbed `hbb_common`, `.git` stripped); the toolchain/version pinning +
`rust-toolchain.toml`; the **complete build harness** (9 scripts) + the R-B2
determinism patch.
- **The CPace PAKE is real, not just a wire format:** the **§10.4 construction**
  (`libs/pake`, 16 KATs — the published draft-21 vector + the fork anchors,
  KAT-VERIFIED); the **two-key secretbox** (`DirectionalCipher`, R-P10) + the
  **choke-point integration** (`server.rs create_tcp_connection` runs
  `run_responder` **unconditionally** — the responder authenticates purely by
  CPace; SignedId/`box_` gone); the per-IP **R-S10** online-guess limiter — all
  wire-tested over loopback (`cpace_it`).
- **§9 assertions:** **R-A1** (keyed-stream-only), **R-A2** (no resume), **R-A3**
  (`set_raw` seal), **R-A4** (startup self-check — policy reads back pinned, PRS
  non-empty, empty BUILTIN/HARD funnels, **and now the live socket surface:
  1×TCP v4:21118, 0×UDP**), **R-A5** (engaged-keys) — all fail-closed,
  lockdown-gated. **R-S16** policy funnel (`PINNED_SETTINGS`, `config_it`-tested);
  **R-S2/S5/S6/S7/S9** as noted below (**R-S7** = the load-bearing pre-auth frame
  cap 4 KiB→32 MiB + the 64 MiB decompress bound, the post-key zstd-bomb twin).
- **Direct-only + sovereign:** **R-D4 behavior** (rendezvous loop + LAN emptied),
  **R-D5** (v4-only bind — `listen_any_v4`), **R-SV3/SV4** (version/NAT/heartbeat
  phone-home deleted), **R-F4** (direct-port pin); **R-D3a** (systemd
  confinement); the §8 excisions **R-X1/X2/X3/X4/X6/X11/X12/X14**; **R-SV8** (iOS).

**NOT done** (and why — the load-bearing honesty): the entire **viewer/initiator
side** (`client.rs run_initiator` + the R-S16 viewer-twin) and the **§19 GUI** are
**flutter-gated** (the FRB-generated bridge needs the heavy flutter SDK — installs
but version-skewed, deferred); **R-B6** (Sciter→flutter) and the **R-R2b** role
split sit behind the same gate; the *token-absent* completion of the excisions
(**R-X5/7/8/9/10/11/13**, the SignedId proto removal) is entangled with R-B6/R-D4;
**R-R3** dependency audit (4 code-vulns fixed + deny.toml → `cargo audit` green;
the fork-bumps + CI wiring remain); **R-S13** viewer bar, **R-S17** host-key
pin; **R-D6** silent TCP egress (rests on the firewall, not a runtime check); and
the **R-A8/A9 two-host tests + the R-V3 independent audit**, which need real hosts
and an outside auditor. **The project is therefore NOT "implemented in full,
correctly"** — the responder (the exposed box) is comprehensively done and
verified, but the viewer, the GUI, the build split, and the external audit remain.

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
| R-S1/R-P4/R-P14 choke-point integration in `create_tcp_connection` | **PARTIAL — responder WIRED (fail-closed); viewer next** | drivers `5ec40de` + foundations `0108349`/`ef8fa72`, then **`c005da3`: the controlled side now runs `cpace::run_responder` on the direct path** (the `else` of the `if secure` block) with the live PRS, `set_session_keys` on success, fail-closed otherwise (R-A1/R-S1/R-P14c). Compile-verified; the handshake is the cpace_it-proven driver. So the **box refuses unkeyed direct connections** instead of accepting plaintext. `9e65a5b`: **the SignedId↔PublicKey device-identity bootstrap is removed** — CPace now keys UNCONDITIONALLY (no `secure`-gated path, no box_/sign keypair), so the responder side of R-P14/R-P5/§8 is done. `2cf3ad6` did R-S2/R-A2 (authorized only on the keyed edge). REMAINING (viewer = operator's device, intricate + needs a two-host test): `client.rs secure_connection`'s direct branch → `run_initiator` with the entered plaintext password **+ the R-S16 viewer twin** (PeerConfig.password as plaintext PRS), the client-side SignedId send removal, the proto SignedId/PublicKey message removal, and `validate_password` deletion (R-S6). |

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
| R-X5 LAN · R-X7 OTP/TOTP · R-X8 terminal · R-X9 Win run-mode/elevation · R-X10 Linux run-mode · R-X11 gtk_sudo · R-X13 uinput/rdp_input · R-X14 os_login PAM | **R-X11 DONE; R-X13 + R-X5 + R-X14 NEUTRALIZED; rest DEFER-BUILD** | **R-X13 core done** (`b1e9522`): `start_uinput_service()` + its unconditional service-entry call removed — the dormant world-mode `_uinput_*` cross-uid sockets the X11 `--server` never used are no longer created (R-S11a surface shrinks to `_service` alone); `wayland_use_uinput()`/`wayland_use_rdp_input()` pinned constant-false so XTEST/enigo is the sole injector by construction (R-X12). uinput.rs/rdp_input.rs stay buildable (§14) but unreachable from the service entry — R-X13's CI bar is call-graph unreachability; the full module compile-out is a follow-on. Hard-gated (`start_uinput_service` absent), compile-verified off+on. **R-X11 done** (`8fb2167`): the **gtk_sudo interactive-elevation cluster is excised** — `src/platform/gtk_sudo.rs` + its `pub mod` decl + the `-gtk-sudo` core_main arm + `run_cmds_privileged` all removed; the two service install/uninstall callers now use a non-elevated status runner (effective only in the root systemd-service context, a no-op on the per-user UI — the .deb + systemctl own lifecycle), and `check_super_user_permission` returns `is_root()` instead of driving an elevation prompt. R-A6 tokens (`gtk_sudo`/`run_cmds_privileged`/`-gtk-sudo`) = 0, **hard-gated in verify.sh**, compile-verified lockdown off+on. `6920db9` stops the LAN UDP discovery listener (no pre-auth UDP surface); `0685c28` strips the peer-supplied `os_login` so no PAM/X-session login runs on the peer's behalf (R-X14/R-S18). Full token-absence (`mod lan`, the linux_desktop_manager PAM code, the os_login proto field) pends the ui.rs/flutter_ffi sweep + R-D4. The rest are entangled with R-D4 / R-B6 (Sciter) / each other, need semantic reworks, or `BLOCK-CARGO` dep drops (`totp-rs`, `impersonate_system`) — compile-verifiable as de-tangled |

## Secure-by-assertion, policy, role split, deployment, sovereignty, GUI

| Area | Status | Notes |
|---|---|---|
| §9 R-A1–R-A10 runtime/build/test assertions | **PARTIAL — gate RUNS** | `a583fd9` `scripts/verify.sh` is the executable §9.3/R-V3 assurance basis: it RUNS the R-A10 KATs (pake 16 + cpace_it 5 + config_it), compile-checks the main crate (lockdown off/on), and hard-gates the **R-A6** greps for the completed excisions (R-X1/X2/X4-CLI/X6/X12 = 0 tokens) — all green. **R-A5** done (`7394561`); **R-A1 done** (`3e97f37`, lockdown-gated `is_secured()` assert before `Connection::start`); **R-A4 DONE** (`2957396`/`5140124`/`b6df149`): `assert_startup_invariants()` at the service entry refuses to listen unless the policy reads back pinned (verification-method/approve-mode via `get_option`), a permanent password exists (R-S9), AND the BUILTIN_SETTINGS / HARD_SETTINGS funnels are empty (R-S16(d)(iv)(v)); and post-listen `assert_socket_surface()` confirms the live bound-socket surface — exactly **1×TCP v4:21118, 0×UDP of any kind** (a pure `/proc/self/net` parser + policy, unit-tested in `surface_it`; counts LISTEN-state only so a session's ESTABLISHED row never miscounts; the any-UDP rule closes the ephemeral-egress blind spot; non-Linux records *unavailable* per R-A4's Darwin clause) — all fail-closed. REMAINING: only the R-A8/A9 two-host exercise of these asserts; **R-A2 done** (`2cf3ad6`): the is_recent_session 30-s reconnect and the SwitchSidesResponse resume — both set `authorized` without a fresh handshake — are removed, so authorization coincides with the CPace KEYED edge; **R-A3 done** (`ddb5c05`): a lockdown-gated assert seals `set_raw` so a keyed stream can't be downgraded to raw. REMAINING: R-A6 turns red→green per excision; R-A8/A9 are the two-host tests |
| R-S16 controlled-policy `PINNED_SETTINGS` funnel | **PARTIAL — config funnel VERIFIED** | `675514b`; (a) `keys::PINNED_SETTINGS` table + (b) `get_option` read funnel + (c) `is_option_can_save` write guard, behind a new `lockdown` feature (empty/no-op when off). **Tested on the pinned 1.75 toolchain** (`config_it` crate, lockdown on): every pinned key returns its policy value and resists override, non-pinned keys unaffected. Was RISK-SILENT (fail-open if wrong) — now behavior-pinned. **R-S16(d)(i) done** (`af15880`): the main-crate `lockdown` feature + `Connection::permission` early-return skipping the `control_permissions` server-push bypass — compile-verified both lockdown on/off. REMAINING: `get_builtin_option` (d)(iv) mirror (only if a KEYS_BUILDIN value is ever pinned), and R-S16's password-storage twin (PRS-at-rest, part of the choke-point cutover) |
| R-S2 FSM collapse · R-S5 `set_raw` seal · R-S7 pre-auth frame cap + decompress bound · R-S9 PRS-at-rest · R-S10 limiter re-key · R-S13 initiator bar · R-S17 host-key pin · R-S18 OS-credential delete | **PARTIAL** | **R-S2 resume paths removed** (`2cf3ad6`, see R-A2); **R-S9 PRS-at-rest** done (`ef8fa72` plaintext-PRS storage + the R-A4 non-empty check). **R-S10 limiter** done (`89bc4e9`): per-IP online-guess limiter in `hbb_common::cpace` (60-s window, ≤10 confirmation failures), checked before the scalar-mult and fed ONLY by R-P3 confirmation mismatches (R-P14c) — wired at the choke point, unit-tested. **R-S6** done (`ab5083a`): the redundant login-time password proof collapses into the PAKE — skipped when CPace-keyed. With SignedId gone (`9e65a5b`), the responder authenticates purely by CPace. **R-S5** set_raw seal done (`ddb5c05`). **R-S7** done (`7e67843`, the load-bearing pre-auth DoS control): the pre-PAKE frame cap (4 KiB — `set_max_packet_length` in `run_responder`/`run_initiator`, the only attacker-reachable parser before keying, closing the ~1 GiB/connection amplification) is RESET to the 32 MiB session ceiling on keying (else legit frames break at 4 KiB), and the post-key twin caps `compress::decompress` output at 64 MiB — rejecting a zstd bomb that the inherited unbounded `zstd::decode_all` would inflate without limit. Both unit-tested (`cpace_it` behavioral frame-cap, `compress_it` bomb-rejection). The kcp C-parser drop (direct-only, both roles TCP) pends R-D4. **R-S17 partial** (`e060f7d`): the headless **`--get-fingerprint`** CLI arm (prints `pk_to_fingerprint(get_key_pair().1)` directly — no daemon, no network — the substitution-defense bootstrap the controlled box was missing, since the GUI `get_fingerprint` is compiled out by R-R2b) is added beside `--get-id`; and (`a0829ee`) the **R-SV5-shared address-normalization** function (`hbb_common::address::normalize_address` — lowercase, IDNA to_ascii, port-fill to 21118, IPv4-canonicalize, reject colon/IPv6) is pinned with a **frozen KAT** (`address_it`, 8 tests incl. the spec's `1.2.3.4`≡`1.2.3.4:21118` and `EXAMPLE.com:21118`≡`example.com:21118`), foreclosing the substitution blind spot. REMAINING: R-S13 viewer bar (viewer side); R-S17's GUI known_hosts seed/mismatch dialogs (flutter) + the controlled-build **HostIdentity** Ed25519 host-proof frame (over sid‖CI‖Ya‖Yb — a responder-side crypto follow-on, the pake transcript is reachable); R-S18 OS-credential delete (Windows/PAM); the R-S7 kcp drop (with R-D4) |
| R-R2b viewer / controlled-only build split (`decode`/`hwcodec`/`vram`/`flutter` features, `mod client` gating) | **DEFER-BUILD / BLOCK-CARGO** | feature-graph surgery; CI must assert the resolved feature set |
| R-F4 direct port pinned to compile-time `21118` | **DONE** | `128d838`; new `config::DIRECT_PORT = 21118`, `get_direct_port` returns it unconditionally (no config read, no rendezvous+2 derivation) — load-bearing for the §10.4 CPace `CI` KAT be16(21118)=527e. The orphaned `direct-access-port` UI setting is a §19 cleanup |
| R-D3a systemd confinement of the root service | **DONE** | `64e11b4`; the exact R-D3a directive set (CapabilityBoundingSet, RestrictAddressFamilies=AF_UNIX AF_INET, ProtectKernel*, SystemCallFilter, …), NoNewPrivileges deliberately omitted, MemoryDenyWriteExecute documented-but-disabled pending runtime validation |
| R-D1/D2/D4–D8 deployment (direct-only build, v4-only, silent egress, config pins) | **PARTIAL — direct-only BEHAVIOR live (VERIFIED)** | `6920db9`; `start_all` no longer connects to any rendezvous server (rendezvous loop emptied — closes the phone-home that the R-S16 `custom-rendezvous-server=""` pin alone could NOT, since `get_rendezvous_servers()` defaults to the built-in upstream) and no longer starts LAN discovery. The box is reachable only by direct connection. `59d4983`: the direct listener is now **unconditional** — no longer gated on the `direct-server` option, so the box's only inbound path (and the CPace responder) reliably starts (R-D4/R-F4; the spec keeps direct-server out of PINNED_SETTINGS for this). Compile-verified. **R-D5 done** (`b6df149`): the direct listener now binds **v4-only** via `listen_any_v4` (the v4 body used unconditionally, not the dual-stack `[::]:21118` socket) — IPv6 unreachability is a property of the binary, not a host sysctl / `ip6tables` rule that can drift, and R-A4 asserts it post-listen. REMAINING: the full R-D4 token-absent mediator removal (lift `direct_server`→`start_direct_only`), the R-R2b build split |
| R-SV8 iOS entitlements (APNs push + wifi-info) | **DONE** | `dd3be96`; both removed (no-phone-home), `associated-domains` confirmed absent (R-X6). macOS entitlements left (functionally required, retain-and-check); iOS `SDWebImage` pod = finding, removal pod-regen-blocked; no Firebase/analytics pod (R-SV8 holds) |
| §18 R-SV3/SV4 sovereignty — no phone-home (universal) | **PARTIAL — egress CLOSED (VERIFIED)** | The box's entire outbound surface is now closed at the behavior level: `fa56d66` deleted `do_check_software_update` (version API, R-SV3) + `test_nat_type_` (rendezvous NAT probe + `cu` re-home, R-SV4); `6920db9` emptied the rendezvous-registration loop (no register_pk/heartbeat to the rendezvous, closing the default-server fallback the R-S16 pin missed); `56e2ad2` unspawned the HBBS sync loop (no `<api-server>/api/heartbeat` heartbeat + sysinfo upload). Auto-updater was R-X1. All compile-verified. REMAINING: token-absent removal of the neutralized workers/callers (with R-D4); R-D5 v4-only bind is now done (`b6df149`) |
| §19 R-G* GUI/UX conformance (remove selectors/toggles/dead assets/links the core no longer honors) | **TODO** | partly unblocked by the deep-link work; large Dart sweep |
| R-R3 dependency audit (Appendix D bumps) | **PARTIAL — 4 code-vulns FIXED, `cargo audit` GREEN via deny.toml** | `5ef7cfe`: in-range lockfile bumps clear **4 code-vulns** on the pinned 1.75 toolchain (all compile-verified lockdown on+off, crypto suite green) — **url 2.5.4** (idna 0.5.0→1.0.3, RUSTSEC-2024-0421; pinned `idna_adapter 1.1.0` unicode-rs backend to dodge icu 2.x/edition2024, ~20 crates lighter), **rand 0.8.6** (2026-0097, the `thread_rng` UB in the CSPRNG for password/salt + CPace scalars), **crossbeam-channel 0.5.15** (2025-0024 double-free), **tracing-subscriber 0.3.20** (2025-0055). New **`deny.toml`** records **41 conscious accepts** each with a reason (R-R3's "ignore + reason"); **cargo-audit 0.21.1** (the last rustc-1.75 line) returns **EXIT=0** against a pinned pre-2026 advisory-db — green, zero unignored. The wired audit surfaced more than the offline Appendix D screen (openssl 2025-0004, crossbeam, tracing-subscriber, libgit2-sys), exactly as the spec predicted. The **Rust audit gate is WIRED** (`4e118ee`): `scripts/audit.sh` + `scripts/Dockerfile.audit` run cargo-audit 0.21.1 against a pinned advisory-db (commit `4ea955ae`, in `pins.env`) with the deny.toml accepts, fail-closed — `bash scripts/audit.sh` returns green. REMAINING: the **fork-bumps** (bindgen 0.59→0.69 clears atty+ansi_term; users→uzers — both need editing the rustdesk-org git-dep forks), the **openssl** pair (fix needs openssl-sys/rustc 1.80, colliding with the R-B5a 1.75 pin — a real toolchain-vs-advisory tension), **time** macOS-prune (with R-R2), the **Dart `osv-scanner`** half of the gate, and the `sdp`/`webrtc` dev-dep `is_multiple_of`/1.75 bump (worked around via the isolated test crates). |

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
