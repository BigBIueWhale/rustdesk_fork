#!/usr/bin/env bash
#
# verify.sh — the day-to-day "secure by assertion" CI gate (§9.2/§9.3, R-V3).
#
# Runs, in a disposable container built from scripts/Dockerfile.devcheck on the
# pinned 1.75 toolchain:
#   1. the §10.4 PAKE KATs + the R-P3 self-consistency / negative KATs (R-A10);
#   2. the wire-level CPace handshake + two-key-cipher integration tests;
#   3. the R-S16 PINNED_SETTINGS policy funnel test (now unconditional, R-R2b);
#   4. a compile check of the whole main crate (hardening unconditional);
#   5. the R-A6 build-time greps — forbidden tokens of the completed excisions
#      and closed follow-up stages MUST be absent.
#
# This is the reproducible assurance basis the §11 review and the spec's
# "secure by assertion" gates rest on. It is NOT the release build (that is the
# vcpkg flow in build-debian.sh). Exit non-zero if any gate fails.
#
# COMPANION GATE: scripts/audit.sh runs the R-R3/R-A7 dependency-advisory check
# for the Rust crate graph (cargo-audit + cargo-deny against deny.toml and a pinned advisory-db),
# and scripts/dart-audit.sh is its Dart-side mirror (osv-scanner against
# flutter/pubspec.lock + the deny-style accept-list scripts/dart-audit-ignores.txt,
# offline against a pinned OSV "Pub" snapshot). Both are kept separate because they
# need an advisory-db + a tool fetch/compile — slower, and run in CI / before a
# release rather than on every inner-loop edit.
#
# COMPANION GATE: scripts/native-codec-watch.sh is the offline source gate for
# vcpkg-built native codec/advisory coverage. Cargo/Dart advisory tools do not
# see those C/C++ libraries, so this gate keeps the manual watch ledger in sync
# with the exact vcpkg manifest and pins; it is not the decoder sandbox.
#
# COMPANION GATE: scripts/apple-conform-check.sh runs the R-R2 Apple (macOS/iOS)
# SOURCE-conformance gate: retain-and-check, R-A6 greps on the Apple cfg, structured
# plist/entitlement/pod/Xcode allow-lists, and cargo cross-checks across the documented
# Apple target matrix with the real Apple Flutter features. Kept separate because it
# builds a second toolchain image and cross-checks the Apple targets (slower), and Apple
# is NOT a build target (R-R2). The Linux `cargo check` below cannot see the cfg(macos)/
# cfg(ios) clusters, so that gate is where their hardening is proven.
#
# Usage:  scripts/verify.sh
set -euo pipefail

cd "$(dirname "$0")/.."
# The fork-version reader/validator (defines fork_version; see docs/VERSIONING.md).
# shellcheck source=scripts/fork-version.sh
source scripts/fork-version.sh
IMG=rd-devcheck
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-verify-target:/build
  -e CARGO_TARGET_DIR=/build
  -e RUSTUP_TOOLCHAIN=1.75.0
  -w /work "$IMG")
rc=0

echo "== building the compile-check image =="
docker volume create rd-cargo-cache  >/dev/null
docker volume create rd-git-cache    >/dev/null
docker volume create rd-verify-target >/dev/null
docker build -q -t "$IMG" -f scripts/Dockerfile.devcheck scripts >/dev/null

echo "== (1-3) KAT + handshake + policy funnel + R-A4 surface + R-S7 frame/decompress (pinned 1.75) =="
"${RUN[@]}" cargo test -p pake -p cpace_it -p config_it -p surface_it -p compress_it -p address_it --color never

# (3b) IPC parent-dir hardening BEHAVIOR (R-S11a / R-S11a(b)): the docker test-runner is root, so these
# unit tests actually exercise the root-only branches — symlink-parent reject, and the R-S11a(b)
# foreign-owned service dir REJECT-AND-RECREATE (fresh inode, never fchown-adopt) + its fail-closed on a
# non-emptyable foreign dir. These were un-run before (verify.sh only `cargo check`ed the main crate).
echo "== (3b) IPC parent-dir hardening behavior tests (R-S11a/R-S11a(b), root-exercised) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::ipc_fs::tests --color never

# (3b-i) IPC service-socket peer-uid AUTHORIZATION policy (R-S11a / §17 root box): the Linux `_service`
# IPC socket is 0666 (world-connectable so the active non-root user process can reach it), gated at
# accept-time by is_allowed_service_peer_uid — admits ONLY root (SO_PEERCRED uid 0) or the active-session
# uid, and FAIL-CLOSED (root-only) when active_uid is unknown — backed by a /proc/pid/exe match against
# the current binary. test_service_peer_uid_policy pins that boundary; it lives in `ipc::ipc_auth::tests`,
# which the `ipc::ipc_fs::tests` filter above does NOT match, so it was previously UNGATED. Gate it so the
# local-privilege-escalation boundary on the root box cannot silently regress (the win/macos peer-policy
# tests in the same module are cfg-compiled out on this Linux build and simply filter out).
echo "== (3b-i) IPC service-socket peer-uid authorization policy (R-S11a/§17) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::ipc_auth::tests --color never

# (3b-i-r) R-G6/R-SV4 relay-route compatibility helper: it must be an identity
# transform, never a suffix stripper. This pins the Rust-side defense in depth
# for stale generated bridge or native callers.
echo "== (3b-i-r) relay-route suffix identity test (R-G6/R-SV4) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ui_interface::relay_route_tests --color never

# (3b-ii) api-server RESOLUTION sovereignty (R-SV6(d)/R-D6): get_api_server("","") and
# get_custom_rendezvous_server("") must resolve to "" — no hardwired global host. The upstream
# "https://admin.rustdesk.com" fallback is excised and PROD_RENDEZVOUS_SERVER stays empty (zero
# write sites). The account/address-book HTTP client and generic request FFI are deleted separately
# below; this guards the resolution layer against re-introducing either hardwired host. The config-pin
# layer (api-server/custom-rendezvous-server pinned empty) is covered by config_it.
echo "== (3b-ii) api-server resolution dials-nobody behavior test (R-SV6(d)) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config common::tests::api_server_resolution_defaults_to_sovereign_empty --color never

# (3b-iv) R-A4/R-X4/R-S11b-3: the rendezvous trust anchor (get_key) must return the baked RS_PUB_KEY,
# and the legacy "key" option must not persist at all. Upstream re-pointed the client via
# Config::get_option("key") / the async IPC options blob / the Windows license; the fork pins the option
# empty and reads NO override.
echo "== (3b-iv) trust-anchor option is pinned empty and get_key is constant (R-A4/R-X4/R-S11b-3) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config common::tests::get_key_uses_pinned_anchor_and_rejects_option_override --color never

echo "== (3b-iv-a) custom-client app-name is a constrained system identifier (R-S11d-26) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config common::tests::custom_client_app_name_identifier_contract --color never

# (3b-iii) R-S11 / Appendix C #15: the MAIN IPC channel (UI⇄service, 0o0600 same-uid) is a config-
# integrity boundary. main_channel_admits_state_mutation is a POSITIVE allowlist over mutating
# arms. The legacy generic write shapes are absent: no Data::Config((name, Some(value))) for
# id/salt/permanent-password/voice-call-input, no Data::Socks(Some) proxy mutation, and no generic
# send_config/set_config helper. Config IPC is request/value only; remaining writes are typed:
# voice-call-input, typed user-owned permanent password/options only for user-owned servers.
# Service-owned servers reject typed user-owned voice/password/options writes and storage/salt sync (R-S11b-2a/R-S11b-3a). Behavior-tested AND the
# loop routes through the allowlist before handle() (R-A6 reachability), AND the allowlist is asserted
# POSITIVE. Whole-config IPC is not a gated variant: SyncConfig is absent.
echo "== (3b-iii) IPC main-channel state-mutation positive allowlist (R-S11) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::test::main_channel_rejects_untyped_state_mutations --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_get_id_is_side_effect_free --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_get_salt_is_side_effect_free --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_load_does_not_generate_id_for_empty_config --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_load_reads_legacy_plaintext_id_without_storing --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_store_clears_empty_id_storage --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_store_preserves_existing_enc_id --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_store_does_not_rewrite_existing_enc_id --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_set_preserves_existing_id_fields --color never
r_s11=
grep -q 'if !main_channel_admits_state_mutation(' src/ipc.rs                            || r_s11="$r_s11 loop-not-wired"
grep -q 'SyncConfig' src/ipc.rs && r_s11="$r_s11 whole-config-ipc-variant-present"
grep -q 'SyncConfig' src/server.rs && r_s11="$r_s11 server-whole-config-import-present"
grep -q 'Data::SetUserOwnedPermanentPassword(_) => {' src/ipc.rs                    || r_s11="$r_s11 typed-user-owned-password-arm-missing"
grep -A3 'Data::SetUserOwnedPermanentPassword(_) => {' src/ipc.rs | grep -q 'authority.allows_main_channel_user_owned_password_write()' || r_s11="$r_s11 typed-user-owned-password-not-authority-gated"
grep -q 'SetUserOwnedPermanentPasswordResult(bool)' src/ipc.rs                          || r_s11="$r_s11 typed-user-owned-password-result-missing"
grep -q 'permanent-password-user-owned-writable' src/ipc.rs                            || r_s11="$r_s11 password-writability-receiver-missing"
grep -q 'permanent-password-user-owned-writable' src/flutter_ffi.rs                    || r_s11="$r_s11 password-writability-ffi-missing"
grep -q 'permanent-password-writable' src/flutter_ffi.rs                              || r_s11="$r_s11 owner-aware-password-writability-ffi-missing"
grep -q 'canSetPermanentPassword' flutter/lib/desktop/pages/desktop_home_page.dart    || r_s11="$r_s11 home-owner-aware-password-writability-ui-missing"
grep -q 'canSetPermanentPassword' flutter/lib/desktop/pages/desktop_setting_page.dart || r_s11="$r_s11 settings-owner-aware-password-writability-ui-missing"
grep -q '"permanent-password" => authority.allows_main_channel_user_owned_password_write()' src/ipc.rs && r_s11="$r_s11 password-still-generic-config-key"
grep -q '"permanent-password" => authority.allows_main_channel_password_write()' src/ipc.rs && r_s11="$r_s11 password-still-generic-config-key"
grep -q 'Data::Config((' src/ipc.rs && r_s11="$r_s11 config-write-shape-present"
grep -q 'send_config(' src/ipc.rs && r_s11="$r_s11 generic-send-config-present"
grep -q 'set_config_async' src/ipc.rs && r_s11="$r_s11 generic-set-config-async-present"
grep -q 'pub async fn set_config' src/ipc.rs && r_s11="$r_s11 generic-set-config-present"
grep -q 'Data::Options(Some(_)) => authority.allows_main_channel_options_write()' src/ipc.rs || r_s11="$r_s11 options-authority-not-gated"
grep -q 'fn allows_main_channel_voice_call_input_write' src/ipc.rs                     || r_s11="$r_s11 voice-input-authority-helper-missing"
grep -q 'Data::SetVoiceCallInput(_) => authority.allows_main_channel_voice_call_input_write()' src/ipc.rs || r_s11="$r_s11 voice-input-not-authority-gated"
if grep -q 'Data::SetVoiceCallInput(_) => true' src/ipc.rs; then
  r_s11="$r_s11 voice-input-still-unconditionally-admitted"
fi
grep -q 'fn allows_service_owned_main_channel_close' src/ipc.rs                        || r_s11="$r_s11 service-owned-close-peer-authority-missing"
grep -q 'fn allows_main_channel_close' src/ipc.rs                                      || r_s11="$r_s11 close-receiver-authority-missing"
grep -q 'Data::Close => authority.allows_main_channel_close(peer_authority)' src/ipc.rs || r_s11="$r_s11 close-not-authority-gated"
grep -q 'Windows service-owned IPC process-close actions' requirements.html           || r_s11="$r_s11 close-requirements-disposition-missing"
grep -q 'R-S11c-13 — service-owned IPC close is receiver-authorized' HARDENING_STATUS.md || r_s11="$r_s11 close-hardening-ledger-missing"
grep -q 'ConfigRequest(String)' src/ipc.rs                                             || r_s11="$r_s11 config-request-missing"
grep -q 'ConfigValue((String, Option<String>))' src/ipc.rs                             || r_s11="$r_s11 config-value-missing"
grep -q 'Socks(Option' src/ipc.rs && r_s11="$r_s11 socks-ipc-variant-present"
grep -q 'Data::Socks' src/ipc.rs && r_s11="$r_s11 socks-ipc-reference-present"
main_policy_body=$(sed -n '/pub(crate) fn main_channel_admits_state_mutation/,/^async fn send_main_channel_mutation_rejection_ack/p' src/ipc.rs)
echo "$main_policy_body" | grep -q 'Data::Login { .. }' || r_s11="$r_s11 main-policy-explicit-nonmutating-classification-missing"
if rg -n 'CheckHwcodec|HwCodecConfig|notify_server_to_check_hwcodec|get_hwcodec_config_from_server|client_get_hwcodec_config_thread|hwcodec_process|--check-hwcodec-config|start_check_process\(|check_available_hwcodec\(|HwCodecConfig::' \
  src >/tmp/rd_verify_hwcodec_ipc.$$; then
  r_s11="$r_s11 hwcodec-ipc-probe-surface-present:$(tr '\n' ';' </tmp/rd_verify_hwcodec_ipc.$$)"
fi
rm -f /tmp/rd_verify_hwcodec_ipc.$$
if echo "$main_policy_body" | grep -qE '^[[:space:]]*\| Data::Close([[:space:]]|$)'; then
  r_s11="$r_s11 close-in-unconditional-main-policy-bucket"
fi
if echo "$main_policy_body" | grep -qE '^[[:space:]]*_ =>'; then
  r_s11="$r_s11 main-policy-wildcard-fallback-present"
fi
config_get_id_body=$(awk '/pub fn get_id\(\) -> String \{/{flag=1} flag{print} flag && /^[[:space:]]{4}\}/{exit}' libs/hbb_common/src/config.rs)
echo "$config_get_id_body" | grep -q 'CONFIG.read' || r_s11="$r_s11 config-get-id-not-reading-config"
if echo "$config_get_id_body" | grep -qE 'Config::set_id|set_id\(|Config::gen_id|gen_id\(|CONFIG\.write|store\('; then
  r_s11="$r_s11 config-get-id-mutates-identity"
fi
config_get_salt_body=$(awk '/pub fn get_salt\(\) -> String \{/{flag=1} flag{print} flag && /^[[:space:]]{4}\}/{exit}' libs/hbb_common/src/config.rs)
echo "$config_get_salt_body" | grep -q 'CONFIG.read' || r_s11="$r_s11 config-get-salt-not-reading-config"
if echo "$config_get_salt_body" | grep -qE 'Config::set_salt|set_salt\(|get_auto_password|CONFIG\.write|store\('; then
  r_s11="$r_s11 config-get-salt-mutates-salt"
fi
config_load_body=$(awk '/fn load\(\) -> Config \{/{flag=1} flag{print} flag && /^[[:space:]]{4}\}/{exit}' libs/hbb_common/src/config.rs)
if echo "$config_load_body" | grep -qE 'config\.store\(|Config::set_id|set_id\(|encrypt_str_or_original\(&config\.id'; then
  r_s11="$r_s11 config-load-persists-identity"
fi
if grep -q 'encrypt_str_or_original(&config.id' libs/hbb_common/src/config.rs; then
  r_s11="$r_s11 config-store-rewrites-numeric-id"
fi
config_set_body=$(awk '/pub fn set\(mut cfg: Config\) -> bool \{/{flag=1} flag{print} flag && /^[[:space:]]{4}\}/{exit}' libs/hbb_common/src/config.rs)
echo "$config_set_body" | grep -q 'cfg.id = lock.id.clone();' || r_s11="$r_s11 config-set-imports-id"
echo "$config_set_body" | grep -q 'cfg.enc_id = lock.enc_id.clone();' || r_s11="$r_s11 config-set-imports-enc-id"
if grep -RInE 'set_id\(|fn gen_id\(|fn get_auto_id\(|update_id\(|is_disable_change_id|OPTION_ALLOW_HOSTNAME_AS_ID|OPTION_DISABLE_CHANGE_ID' src libs --include='*.rs' 2>/dev/null \
  | grep -v '//' >/tmp/rd_verify_identity_writers.$$; then
  r_s11="$r_s11 numeric-id-writer-or-generator-present"
fi
mac_address_hits=$({
  grep -InE 'mac_address' Cargo.toml Cargo.lock libs/hbb_common/Cargo.toml libs/virtual_display/Cargo.lock 2>/dev/null || true
  grep -RInE 'mac_address' libs/hbb_common/src src --include='*.rs' 2>/dev/null || true
})
if [ -n "$mac_address_hits" ]; then
  printf '%s\n' "$mac_address_hits" >/tmp/rd_verify_mac_address.$$
  r_s11="$r_s11 mac-address-id-dependency-present"
fi
ipc_get_id_body=$(awk '/^pub fn get_id\(\) -> String \{/{flag=1} flag{print} flag && /^\}/{exit}' src/ipc.rs)
if echo "$ipc_get_id_body" | grep -qE 'Config::set_id|set_id\(|Config::set_salt|set_salt\(|get_config\("salt"\)'; then
  r_s11="$r_s11 ipc-get-id-copies-id-or-salt"
fi
if awk '/if !hbb_common::is_ip_str\(&lr\.username\)/,/send_login_error/' src/server/connection.rs | grep -q 'Config::get_id'; then
  r_s11="$r_s11 server-login-still-accepts-numeric-id"
fi
ipc_start_block=$(awk '/^pub async fn start\(postfix: &str\)/,/^}/' src/ipc.rs)
echo "$ipc_start_block" | grep -q 'Config::ensure_loaded();' || r_s11="$r_s11 main-ipc-start-does-not-init-config"
# R-S11 binds EVERY shipped artifact, not Linux/macOS alone (Windows .exe/.msi are shipped). The
# allowlist MUST also guard the Windows main pipe (postfix == ""). Because the linux/macos gate logs
# stream.peer_uid() (unix-only, SO_PEERCRED), Windows needs its OWN cfg(windows) gate calling the same
# allowlist fn — so there must be >=2 gate call sites and the fn must be cfg'd for windows. Without this
# a same-session/same-exe process could Config(id|salt) the host key_pair on the
# Windows artifact (the linux-only gate + the linux-cfg unit test are blind to it).
[ "$(grep -c 'if !main_channel_admits_state_mutation(' src/ipc.rs)" -ge 2 ]            || r_s11="$r_s11 windows-main-pipe-gate-missing"
grep -B1 'pub(crate) fn main_channel_admits_state_mutation' src/ipc.rs | grep -q 'windows' || r_s11="$r_s11 allowlist-fn-not-cfg-windows"
windows_main_peer_authority_block=$(awk '/let peer_authority = match &data/,/_ => MainIpcPeerAuthority::Ordinary/' src/ipc.rs)
echo "$windows_main_peer_authority_block" | grep -q 'Data::Close' || r_s11="$r_s11 windows-close-peer-token-not-resolved"
echo "$windows_main_peer_authority_block" | grep -q 'MainIpcPeerAuthority::for_windows_main_pipe(&stream)' || r_s11="$r_s11 windows-main-peer-token-helper-not-used"
windows_service_close_block=$(awk '/ipc::Data::Close => \{/,/ipc::Data::Test =>/' src/platform/windows.rs)
echo "$windows_service_close_block" | grep -q 'windows_pipe_client_token_is_local_system' || r_s11="$r_s11 windows-service-close-not-localsystem-gated"
echo "$windows_service_close_block" | grep -q 'Rejected Windows _service close: caller is not LocalSystem' || r_s11="$r_s11 windows-service-close-rejection-missing"
if [ -n "$r_s11" ]; then echo "  FAIL R-S11 main-channel state-mutation allowlist:$r_s11"; rc=1; else
  echo "  ok  R-S11/R-S11b/R-S11c main-channel state-mutation boundary (whole-config IPC, generic Config writes, generic config helpers, Socks IPC, and read-time identity/salt writes are absent; typed voice/password/options are user-owned scoped; service-owned close is root/LocalSystem-gated on main IPC and Windows _service; the policy table is exhaustive with no wildcard fallback; gate binds Linux/macOS AND the Windows main pipe)"; fi
rm -f /tmp/rd_verify_identity_writers.$$ /tmp/rd_verify_mac_address.$$

echo "== (3b-iii-a1) desktop at-rest wrapper does not mint service identity material (R-S11b-3f) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config pk_fallback --color never
r_s11b3f=
get_uuid_body=$(awk '/^pub fn get_uuid\(\) -> Vec<u8> \{/{flag=1} flag{print} flag && /^}/{exit}' libs/hbb_common/src/lib.rs)
echo "$get_uuid_body" | grep -q 'machine_uuid()' || r_s11b3f="$r_s11b3f desktop-uuid-not-machine-uid"
if echo "$get_uuid_body" | grep -q 'Config::get_key_pair'; then
  r_s11b3f="$r_s11b3f desktop-uuid-mints-keypair"
fi
grep -B1 'pub fn get_key_pair' libs/hbb_common/src/config.rs | grep -q 'target_os = "android".*target_os = "ios"' || r_s11b3f="$r_s11b3f keypair-generator-not-mobile-cfg"
if grep -q 'pub fn get_cached_pk' libs/hbb_common/src/config.rs; then
  r_s11b3f="$r_s11b3f cached-pk-api-present"
fi
if awk '/^mod test /{exit} /crate::get_uuid\(\)/ {print}' libs/hbb_common/src/password_security.rs | grep -q .; then
  r_s11b3f="$r_s11b3f symmetric-crypt-still-uses-get-uuid"
fi
grep -q 'pub fn at_rest_storage_key() -> ResultType<Vec<u8>>' libs/hbb_common/src/lib.rs || r_s11b3f="$r_s11b3f fallible-at-rest-key-api-missing"
grep -q 'let storage_key = crate::at_rest_storage_key()' libs/hbb_common/src/password_security.rs || r_s11b3f="$r_s11b3f symmetric-crypt-not-using-fallible-key"
grep -q 'fn secretbox_key_from_storage_key' libs/hbb_common/src/password_security.rs || r_s11b3f="$r_s11b3f key-derivation-helper-missing"
grep -A4 'fn secretbox_key_from_storage_key' libs/hbb_common/src/password_security.rs | grep -q 'storage_key.is_empty()' || r_s11b3f="$r_s11b3f empty-at-rest-key-not-rejected"
grep -A14 'pub fn encrypt_str_or_original' libs/hbb_common/src/password_security.rs | grep -q 'return String::default()' || r_s11b3f="$r_s11b3f string-encrypt-failure-not-fail-closed"
grep -A18 'pub fn encrypt_vec_or_original' libs/hbb_common/src/password_security.rs | grep -q 'return Vec::new()' || r_s11b3f="$r_s11b3f vec-encrypt-failure-not-fail-closed"
if [ -n "$r_s11b3f" ]; then echo "  FAIL R-S11b-3f desktop at-rest key/identity boundary:$r_s11b3f"; rc=1; else
  echo "  ok  R-S11b-3f desktop at-rest wrapping uses a fallible machine-UID key, never get_uuid/keypair generation; legacy keypair decrypt remains read-only and mobile-only generation is cfg-isolated"; fi

echo "== (3b-iii-a1b) credential-bearing local stores use hardened raw-file writes (R-S11b-4d) =="
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::store_raw_config_bytes --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::raw_encrypted_json_load_failure_preserves_payload_for_recovery --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_load_path_present_but_unreadable_is_transient_not_stale --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::empty_peer_cleanup_requires_loaded_semantically_empty_config --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::peer_cleanup_decision_is_bound_to_the_enumerated_path --color never
index_s11b4d=
grep -q 'fn store_raw_config_bytes(path: PathBuf, data: &\[u8\]) -> Result<()>' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-helper-missing"
grep -q 'fn load_raw_config_bytes(path: &Path) -> Result<Vec<u8>>' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-load-helper-missing"
grep -q 'windows_config_acl::prepare_config_path_for_store(&path)' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-windows-acl-not-prepared"
grep -q 'windows_config_acl::prepare_config_path_for_load(path)' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-load-windows-acl-not-prepared"
grep -q 'options.mode(0o600)' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-unix-mode-not-owner-only"
grep -q 'fs::set_permissions(&path, fs::Permissions::from_mode(0o600))' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-unix-final-mode-not-owner-only"
grep -q 'file.sync_all()' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-sync-missing"
grep -q 'fn replace_raw_config_file(tmp: &Path, path: &Path) -> Result<()>' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-replace-helper-missing"
grep -q 'MoveFileExW' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-windows-replace-primitive-missing"
grep -q 'MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-store-windows-replace-flags-missing"
grep -q 'enum ConfigLoadStatus' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d typed-load-status-missing"
grep -q 'fn load_path_with_status' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d typed-load-helper-missing"
grep -q 'Self::load_path_with_status(Self::path(id), Some(id))' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d peer-config-id-load-not-through-path-wrapper"
grep -q 'fn load_path_with_status(path: PathBuf, stored_peer_id: Option<&str>) -> ConfigLoad<PeerConfig>' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d peer-config-exact-path-load-helper-missing"
grep -q 'fn is_semantically_empty_peer_config(config: &PeerConfig) -> bool' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d semantic-empty-peer-helper-missing"
grep -q 'config == &PeerConfig::default()' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d semantic-empty-peer-not-default-comparison"
grep -q 'fn should_remove_empty_peer_config(status: ConfigLoadStatus, config: &PeerConfig) -> bool' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d empty-peer-cleanup-policy-missing"
grep -q 'matches!(status, ConfigLoadStatus::Loaded) && is_semantically_empty_peer_config(config)' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d empty-peer-cleanup-not-loaded-empty-only"
grep -q 'if should_remove_empty_peer_config(status, &c)' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d batch-peer-cleanup-not-status-and-content-gated"
grep -q 'let loaded = PeerConfig::load_path_with_status(p.clone(), Some(id));' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d batch-peer-cleanup-not-bound-to-enumerated-path"
grep -q 'with_rdp_password' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d rdp-password-peer-cleanup-regression-missing"
grep -q 'peer_cleanup_decision_is_bound_to_the_enumerated_path' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d alias-path-cleanup-regression-missing"
if grep -q 'let loaded = PeerConfig::load_with_status(&id)' libs/hbb_common/src/config.rs; then
  index_s11b4d="$index_s11b4d batch-peer-cleanup-loads-canonical-id-path"
fi
if grep -q 'let mut config: PeerConfig = load_path(Self::path(id));' libs/hbb_common/src/config.rs; then
  index_s11b4d="$index_s11b4d peer-config-direct-untyped-load-present"
fi
if grep -q 'confy::load_path(Self::path(id))' libs/hbb_common/src/config.rs; then
  index_s11b4d="$index_s11b4d peer-config-direct-confy-load-present"
fi
[ "$(grep -c 'store_raw_config_bytes(Self::path(), &data)' libs/hbb_common/src/config.rs)" -eq 2 ] || index_s11b4d="$index_s11b4d address-book-or-group-raw-store-not-used"
grep -q 'load_encrypted_json_config::<Ab>(&path, "address book")' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d address-book-raw-load-not-used"
grep -q 'load_encrypted_json_config::<Self>(&path, "group")' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d group-raw-load-not-used"
grep -q 'preserve_raw_config_file(&path, "address book")' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d address-book-corrupt-preserve-missing"
grep -q 'preserve_raw_config_file(&path, "group")' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d group-corrupt-preserve-missing"
grep -q 'fn preserve_raw_config_file(path: &Path, label: &str)' libs/hbb_common/src/config.rs || index_s11b4d="$index_s11b4d raw-corrupt-preserve-helper-missing"
if grep -q 'std::fs::File::create(Self::path())' libs/hbb_common/src/config.rs; then
  index_s11b4d="$index_s11b4d address-book-or-group-direct-create-present"
fi
if grep -q 'file.write_all(&data).ok()' libs/hbb_common/src/config.rs; then
  index_s11b4d="$index_s11b4d address-book-or-group-silent-write-present"
fi
grep -q 'Local credential-bearing store file hardening' requirements.html || index_s11b4d="$index_s11b4d requirements-disposition-missing"
grep -q 'R-S11b-4d — local credential-bearing store file hardening' HARDENING_STATUS.md || index_s11b4d="$index_s11b4d hardening-ledger-missing"
if [ -n "$index_s11b4d" ]; then echo "  FAIL R-S11b-4d local credential-bearing store hardening:$index_s11b4d"; rc=1; else
  echo "  ok  R-S11b-4d PeerConfig uses typed hardened load status so transient peer-read failures are not deleted and loaded peer files are removed only when semantically empty; raw encrypted address-book/group stores keep their byte format while using ACL/0600 replacing writes and corrupt-payload preservation without silent direct File::create/write_all drops"; fi

echo "== (3b-iii-a2) Linux _pa audio helper requires capture authority (R-S11c-7) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config pa_capture_authority --color never
r_s11c7=
grep -q 'PulseAudioStart {' src/ipc.rs || r_s11c7="$r_s11c7 tokened-pa-start-missing"
grep -q 'owner: PeerProcessIdentity' src/ipc.rs || r_s11c7="$r_s11c7 pa-start-owner-identity-missing"
grep -q 'ValidatePulseAudioStart' src/ipc.rs || r_s11c7="$r_s11c7 pa-start-validation-message-missing"
if grep -q 'PulseAudioSource' src/ipc.rs src/server/audio_service.rs; then
  r_s11c7="$r_s11c7 legacy-pa-source-message-present"
fi
start_pa_body=$(awk '/^pub async fn start_pa\(\) \{/{flag=1} flag{print} flag && /^}/{exit}' src/ipc.rs)
echo "$start_pa_body" | grep -q 'Data::PulseAudioStart {' || r_s11c7="$r_s11c7 pa-helper-does-not-require-tokened-start"
echo "$start_pa_body" | grep -q 'owner' || r_s11c7="$r_s11c7 pa-helper-does-not-read-owner-identity"
echo "$start_pa_body" | grep -q 'validate_pulse_audio_start_authority(&owner, &token)' || r_s11c7="$r_s11c7 pa-helper-does-not-validate-token-through-owner"
echo "$start_pa_body" | grep -q 'Rejected _pa client without audio capture authority' || r_s11c7="$r_s11c7 missing-token-not-rejected"
pa_validate_body=$(awk '/^async fn validate_pulse_audio_start_authority/,/^}/' src/ipc.rs)
echo "$pa_validate_body" | grep -q 'connect_for_uid(1_000, owner.uid(), "")' || r_s11c7="$r_s11c7 pa-helper-validation-not-owner-uid-routed"
echo "$pa_validate_body" | grep -q 'ensure_peer_process_identity_matches(&stream, owner, "")' || r_s11c7="$r_s11c7 pa-helper-validation-not-owner-identity-authenticated"
if echo "$pa_validate_body" | grep -q 'connect(1_000, "")'; then
  r_s11c7="$r_s11c7 pa-helper-validation-still-ambient-main-ipc"
fi
grep -q 'static ref PA_CAPTURE_AUTHORITY' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-registry-missing"
grep -q 'fn install_pa_capture_authority(conn_ids: Vec<i32>) -> ResultType<PaCaptureAuthorityGuard>' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-installer-missing"
grep -q 'validate_pa_capture_authority' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-validator-missing"
grep -q 'expected_peer: crate::ipc::PeerProcessIdentity' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-peer-identity-missing"
grep -q 'fn ensure_pa_endpoint_matches_authority' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-endpoint-peer-check-missing"
grep -q 'ensure_peer_process_identity_matches(stream, authority.expected_peer(), "_pa")' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-endpoint-peer-identity-not-checked"
grep -q 'peer_process_identity_is_live(peer, "_pa")' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-live-peer-not-checked"
grep -q 'expected_cm_peer_identity_for_conn_ids(conn_ids)' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-not-bound-to-cm-peer"
grep -q 'install_pa_capture_authority(sp.subscriber_ids())' src/server/audio_service.rs || r_s11c7="$r_s11c7 pa-authority-not-bound-to-subscribers"
grep -q 'Data::PulseAudioStart' src/server/audio_service.rs || r_s11c7="$r_s11c7 audio-service-not-sending-tokened-start"
grep -q 'let owner = crate::ipc::current_process_identity("_pa")' src/server/audio_service.rs || r_s11c7="$r_s11c7 audio-service-not-sending-owner-identity"
grep -q 'struct PeerProcessIdentity' src/ipc/auth.rs || r_s11c7="$r_s11c7 peer-process-identity-missing"
grep -q 'linux_proc_start_time(pid)' src/ipc/auth.rs || r_s11c7="$r_s11c7 peer-identity-start-time-missing"
grep -q 'cm_launch_token: String' src/ipc/auth.rs || r_s11c7="$r_s11c7 peer-identity-cm-launch-token-missing"
grep -q 'cm_launch_parent: u32' src/ipc/auth.rs || r_s11c7="$r_s11c7 peer-identity-cm-launch-parent-missing"
grep -q 'CM_LAUNCH_TOKEN_ENV' src/common.rs src/ipc/auth.rs src/ipc/fs.rs src/server/connection.rs || r_s11c7="$r_s11c7 cm-launch-token-env-missing"
grep -q 'CM_LAUNCH_PARENT_ENV' src/common.rs src/ipc/auth.rs src/ipc/fs.rs src/server/connection.rs || r_s11c7="$r_s11c7 cm-launch-parent-env-missing"
grep -q 'fn linux_process_has_ancestor' src/ipc/auth.rs || r_s11c7="$r_s11c7 cm-launch-parent-ancestor-check-missing"
grep -q 'authenticate_cm_endpoint' src/ipc/auth.rs || r_s11c7="$r_s11c7 cm-endpoint-authenticator-missing"
grep -q 'expected_launch_token: &str' src/ipc/auth.rs || r_s11c7="$r_s11c7 cm-endpoint-authenticator-not-token-bound"
grep -q 'expected_launch_parent: u32' src/ipc/auth.rs || r_s11c7="$r_s11c7 cm-endpoint-authenticator-not-parent-bound"
grep -q 'identity.cm_launch_token != expected_launch_token' src/ipc/auth.rs || r_s11c7="$r_s11c7 cm-endpoint-launch-token-not-checked"
grep -q 'linux_process_has_ancestor(identity.pid, expected_launch_parent)' src/ipc/auth.rs || r_s11c7="$r_s11c7 cm-endpoint-launch-parent-not-checked"
grep -q 'static ref CM_LAUNCH_TOKEN' src/server/connection.rs || r_s11c7="$r_s11c7 cm-server-launch-token-missing"
common_conn_lazy_static=$(awk '/lazy_static::lazy_static! \{/{flag=1} flag{print} flag && /^}/{exit}' src/server/connection.rs)
if echo "$common_conn_lazy_static" | grep -Eq 'CM_PEER_IDENTITIES|CM_LAUNCH_TOKEN'; then
  r_s11c7="$r_s11c7 platform-cm-state-inside-shared-lazy-static"
fi
grep -B2 'static ref CM_PEER_IDENTITIES' src/server/connection.rs | grep -Fq '#[cfg(target_os = "linux")]' || r_s11c7="$r_s11c7 cm-peer-identities-not-linux-outer-cfg"
grep -B2 'static ref CM_LAUNCH_TOKEN' src/server/connection.rs | grep -Fq '#[cfg(any(target_os = "linux", target_os = "macos"))]' || r_s11c7="$r_s11c7 cm-launch-token-not-unix-outer-cfg"
grep -q 'fn cm_launch_env()' src/server/connection.rs || r_s11c7="$r_s11c7 cm-launch-env-helper-missing"
grep -q 'run_me_with_env(args, cm_launch_env())' src/server/connection.rs || r_s11c7="$r_s11c7 same-user-cm-launch-not-tokenized"
grep -q 'cm_launch_env()' src/server/connection.rs || r_s11c7="$r_s11c7 cm-launch-env-not-used"
grep -q 'fn connect_authenticated_cm' src/server/connection.rs || r_s11c7="$r_s11c7 authenticated-cm-connect-missing"
grep -q 'connect_authenticated_cm(1000, current_euid(), "--cm")' src/server/connection.rs || r_s11c7="$r_s11c7 default-cm-connect-not-authenticated"
grep -q 'connect_authenticated_cm(1000, uid, "--cm-no-ui")' src/server/connection.rs || r_s11c7="$r_s11c7 uid-cm-connect-not-authenticated"
grep -q 'cm_launch_token()' src/server/connection.rs || r_s11c7="$r_s11c7 cm-connect-not-launch-token-authenticated"
grep -q 'std::process::id()' src/server/connection.rs || r_s11c7="$r_s11c7 cm-connect-not-launch-parent-authenticated"
grep -q 'register_cm_peer_identity_for_conn' src/server/connection.rs || r_s11c7="$r_s11c7 cm-peer-identity-not-registered"
grep -q 'struct CmPeerIdentityRegistration' src/server/connection.rs || r_s11c7="$r_s11c7 cm-peer-identity-guard-missing"
grep -q 'clear_cm_peer_identity_for_conn(self.0)' src/server/connection.rs || r_s11c7="$r_s11c7 cm-peer-identity-not-cleared-by-conn-drop"
grep -q 'clear_cm_peer_identity_for_conn(self.conn_id)' src/server/connection.rs || r_s11c7="$r_s11c7 cm-peer-identity-not-cleared-by-ipc-drop"
grep -q 'expected_cm_peer_identity_for_conn_ids' src/server/connection.rs || r_s11c7="$r_s11c7 cm-peer-identity-resolver-missing"
grep -q 'peer_process_identity_is_live(cm_peer_identity, "_cm")' src/server/connection.rs || r_s11c7="$r_s11c7 cm-peer-identity-live-check-missing"
grep -q 'pub fn subscriber_ids(&self) -> Vec<i32>' src/server/service.rs || r_s11c7="$r_s11c7 service-subscriber-id-snapshot-missing"
grep -q 'authenticate_cm_endpoint(' src/ipc/fs.rs || r_s11c7="$r_s11c7 cm-stale-socket-probe-not-authenticated"
grep -q 'CM_LAUNCH_TOKEN_ENV' src/ipc/fs.rs || r_s11c7="$r_s11c7 cm-stale-socket-probe-not-launch-token-bound"
grep -q 'CM_LAUNCH_PARENT_ENV' src/ipc/fs.rs || r_s11c7="$r_s11c7 cm-stale-socket-probe-not-launch-parent-bound"
grep -q 'ensure_peer_process_identity_matches(&stream, &expected, "_pa")' src/ipc/fs.rs || r_s11c7="$r_s11c7 pa-stale-socket-probe-not-identity-bound"
if grep -q 'owner_pid' src/ipc.rs src/server/audio_service.rs; then
  r_s11c7="$r_s11c7 legacy-pa-owner-pid-present"
fi
if grep -q 'CM_PEER_PIDS\|expected_cm_peer_pid\|register_cm_peer_pid\|clear_cm_peer_pid' src/server/connection.rs src/server/audio_service.rs; then
  r_s11c7="$r_s11c7 legacy-bare-cm-peer-pid-authority-present"
fi
start_ipc_before_ready=$(awk '/^async fn start_ipc\(/,/tx_stream_ready\.send/' src/server/connection.rs)
if echo "$start_ipc_before_ready" | awk '
  /#\[cfg\(target_os = "linux"\)\]/ { linux = 1; next }
  /#\[cfg\(target_os = "macos"\)\]/ { linux = 0; next }
  /#\[cfg\(not\(target_os = "linux"\)\)\]/ { linux = 0; next }
  /#\[cfg\(not\(any\(target_os = "linux", target_os = "macos"\)\)\)\]/ { linux = 0; next }
  linux && /crate::ipc::connect\(1000, "_cm"\)/ { found = 1 }
  END { exit found ? 0 : 1 }
'; then
  r_s11c7="$r_s11c7 unauthenticated-default-cm-connect-before-ready"
fi
if echo "$start_ipc_before_ready" | grep -q 'crate::ipc::connect_for_uid(1000, uid, "_cm")'; then
  r_s11c7="$r_s11c7 unauthenticated-uid-cm-connect-before-ready"
fi
if [ -n "$r_s11c7" ]; then echo "  FAIL R-S11c-7 Linux _pa audio helper authority:$r_s11c7"; rc=1; else
  echo "  ok  R-S11c-7 Linux _pa capture starts only after authenticated live owner/CM/_pa process-identity binding plus a token minted from the active audio subscriber set; missing/wrong/stale/wrong-peer tokens, ambient main-IPC validators, and launch-tokenless fixed-path _cm listeners are rejected"; fi

echo "== (3b-iii-a3) Windows named-pipe endpoints are DACL-bound (R-S11c-6) =="
r_s11c6=
grep -q 'windows_ipc_listener_security_attributes(postfix)' src/ipc.rs              || r_s11c6="$r_s11c6 listener-not-dacl-routed"
grep -q 'SecurityAttributes::from_sddl' src/ipc/auth.rs                            || r_s11c6="$r_s11c6 no-sddl-security-attributes"
grep -q 'String::from("D:P(A;;GA;;;SY)")' src/ipc/auth.rs                         || r_s11c6="$r_s11c6 base-dacl-not-system-only"
grep -q 'WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK: u32 = 0x0012_019b' src/ipc/auth.rs || r_s11c6="$r_s11c6 narrow-client-mask-missing"
grep -q 'FILE_CREATE_PIPE_INSTANCE' src/ipc/auth.rs                                || r_s11c6="$r_s11c6 create-instance-negative-test-missing"
grep -q 'open_windows_named_pipe_client' src/ipc.rs                                || r_s11c6="$r_s11c6 custom-client-open-missing"
grep -q 'CreateFileW' src/ipc.rs                                                   || r_s11c6="$r_s11c6 direct-client-open-missing"
grep -q 'ensure_windows_ipc_server_matches_current(&client, postfix)' src/ipc.rs   || r_s11c6="$r_s11c6 server-verification-not-wired"
grep -q 'GetNamedPipeServerProcessId' src/ipc/auth.rs                              || r_s11c6="$r_s11c6 server-pid-check-missing"
grep -q 'refresh_service_ipc_listener(incoming).await' src/platform/windows.rs     || r_s11c6="$r_s11c6 service-listener-session-refresh-missing"
if grep -q 'should_allow_everyone_create_on_windows' src/ipc.rs src/ipc/auth.rs; then
  r_s11c6="$r_s11c6 legacy-world-create-policy-present"
fi
if grep -q 'String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)' src/ipc/auth.rs; then
  r_s11c6="$r_s11c6 administrators-in-base-dacl"
fi
if [ -n "$r_s11c6" ]; then echo "  FAIL R-S11c-6 Windows named-pipe DACL hardening:$r_s11c6"; rc=1; else
  echo "  ok  R-S11c-6 Windows named pipes use SDDL DACLs, narrow client opens, server PID verification, and session-refreshed _service listeners"
fi

echo "== (3b-iii-a4) Windows terminal helper pipes bind to launched helper PID (R-S11c-12) =="
r_s11c12=
grep -q 'GetNamedPipeClientProcessId' src/server/terminal_helper.rs || r_s11c12="$r_s11c12 client-pid-query-missing"
grep -q 'fn ensure_named_pipe_client_pid' src/server/terminal_helper.rs || r_s11c12="$r_s11c12 client-pid-gate-missing"
grep -q 'expected_client_pid: u32' src/server/terminal_helper.rs || r_s11c12="$r_s11c12 expected-pid-parameter-missing"
grep -q 'client_pid != expected_client_pid' src/server/terminal_helper.rs || r_s11c12="$r_s11c12 client-pid-match-missing"
grep -q 'FILE_FLAG_FIRST_PIPE_INSTANCE' src/server/terminal_helper.rs || r_s11c12="$r_s11c12 first-pipe-instance-flag-missing"
grep -q 'PIPE_REJECT_REMOTE_CLIENTS' src/server/terminal_helper.rs || r_s11c12="$r_s11c12 reject-remote-clients-flag-missing"
grep -q 'HelperProcessGuard::new(helper_process_info.handle, helper_process_info.pid)' src/server/terminal_service.rs || r_s11c12="$r_s11c12 helper-pid-source-missing"
terminal_helper_pipe_connects=$(awk '/wait_for_pipe_connection\(/,/\)\?;/' src/server/terminal_service.rs | grep -c 'helper_pid' || true)
if [ "$terminal_helper_pipe_connects" -ne 2 ]; then
  r_s11c12="$r_s11c12 helper-pid-not-passed-to-both-pipes"
fi
if grep -q 'Creating pipes: input={}, output={}' src/server/terminal_service.rs; then
  r_s11c12="$r_s11c12 service-logs-terminal-pipe-names"
fi
if grep -q 'Created restricted DACL for pipe: {}\|Creating named pipe: {} (for_input={}, restricted_dacl=true)\|Named pipe created: {}\|Waiting for pipe connection: {}' src/server/terminal_helper.rs; then
  r_s11c12="$r_s11c12 helper-logs-terminal-pipe-names"
fi
grep -q 'R-S11c-12 — Windows terminal helper pipe binding' HARDENING_STATUS.md || r_s11c12="$r_s11c12 hardening-ledger-missing"
grep -q 'R-S11c-12 closes the Windows terminal helper pipe-binding class' requirements.html || r_s11c12="$r_s11c12 requirements-disposition-missing"
if [ -n "$r_s11c12" ]; then echo "  FAIL R-S11c-12 Windows terminal helper pipe binding:$r_s11c12"; rc=1; else
  echo "  ok  R-S11c-12 Windows terminal helper pipes are first-instance/local-only and accept only the helper PID returned by CreateProcessAsUserW"; fi

echo "== (3b-iii-a5) Windows installer service root is fixed and shell fallbacks are absent (R-S11d) =="
r_s11d=
grep -q 'SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None)' src/platform/windows.rs || r_s11d="$r_s11d exe:no-known-folder-program-files"
grep -q 'fn fixed_service_install_path(requested_path: &str) -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d="$r_s11d exe:no-fixed-install-path-gate"
grep -q 'fn fixed_service_install_dir_and_exe() -> ResultType<(String, String)>' src/platform/windows.rs || r_s11d="$r_s11d exe:no-fixed-service-exe-helper"
grep -q 'let (_, exe) = fixed_service_install_dir_and_exe()?' src/platform/windows.rs || r_s11d="$r_s11d exe:after-install-bypasses-fixed-service-root"
grep -q 'let (path, exe) = match fixed_service_install_dir_and_exe()' src/platform/windows.rs || r_s11d="$r_s11d exe:install-service-bypasses-fixed-service-root"
grep -q 'custom Windows install paths are not supported for the installed service' src/platform/windows.rs || r_s11d="$r_s11d exe:custom-path-not-rejected"
grep -q 'GetSystemDirectoryW(Some(&mut buffer))' src/platform/windows.rs || r_s11d="$r_s11d exe:no-trusted-cmd-path"
grep -q 'runas::Command::new(cmd)' src/platform/windows.rs || r_s11d="$r_s11d exe:elevated-cmd-not-absolute"
grep -q 'share_mode(FILE_SHARE_READ)' src/platform/windows.rs || r_s11d="$r_s11d exe:command-file-write-sharing-not-denied"
grep -Fq 'if not exist \"{exe}\" exit /b 1' src/platform/windows.rs || r_s11d="$r_s11d exe:service-binary-existence-not-checked"
grep -q 'if errorlevel 1 exit /b 1' src/platform/windows.rs || r_s11d="$r_s11d exe:sc-errors-not-fatal"
grep -q "bind.installInstallMe(options: args, path: '')" flutter/lib/desktop/pages/install_page.dart || r_s11d="$r_s11d flutter:fixed-install-entry-not-used"
if grep -qE 'std::env::var\("ProgramFiles"\)|runas::Command::new\("cmd\.exe"\)|Change Path|selectInstallPath|file_picker|package:path/path' src/platform/windows.rs flutter/lib/desktop/pages/install_page.dart; then
  r_s11d="$r_s11d exe-or-flutter:custom-path-or-path-selected-cmd"
fi
if grep -RInE 'INSTALLFOLDER_INNER|WIXUI_INSTALLDIR|ChangeFolder|BrowseDlg|InstallFolderSearch|SavedInstallFolder|RestoreSavedInstallFolder|SetInstallFolder' res/msi >/tmp/rd_verify_r_s11d_msi.$$; then
  cat /tmp/rd_verify_r_s11d_msi.$$
  r_s11d="$r_s11d msi:public-install-folder-or-browse-surface"
fi
rm -f /tmp/rd_verify_r_s11d_msi.$$
if grep -RInE 'TryCreateStartServiceByShell|TryStopDeleteServiceByShell|ShellExecuteW\(NULL, L"open", L"(sc|cmd\.exe|reg)"' res/msi/CustomActions >/tmp/rd_verify_r_s11d_msi_shell.$$; then
  cat /tmp/rd_verify_r_s11d_msi_shell.$$
  r_s11d="$r_s11d msi:service-or-registry-shell-fallback"
fi
rm -f /tmp/rd_verify_r_s11d_msi_shell.$$
grep -q 'Id="CreateStartService".*Return="check"' res/msi/Package/Fragments/CustomActions.wxs || r_s11d="$r_s11d msi:create-service-return-not-checked"
grep -q 'Id="TryStopDeleteService".*Return="check"' res/msi/Package/Fragments/CustomActions.wxs || r_s11d="$r_s11d msi:delete-service-return-not-checked"
grep -q 'Id="AddFirewallRules".*Return="check"' res/msi/Package/Fragments/CustomActions.wxs || r_s11d="$r_s11d msi:add-firewall-return-not-checked"
grep -q 'Id="RemoveFirewallRules".*Return="check"' res/msi/Package/Fragments/CustomActions.wxs || r_s11d="$r_s11d msi:remove-firewall-return-not-checked"
if grep -qE 'Id="(CreateStartService|TryStopDeleteService|AddRegSoftwareSASGeneration|AddFirewallRules|RemoveFirewallRules)".*Return="ignore"' res/msi/Package/Fragments/CustomActions.wxs; then
  r_s11d="$r_s11d msi:privileged-custom-action-return-ignored"
fi
grep -Fq 'HRESULT AddFirewallRule(bool add, LPWSTR exeName, LPWSTR exeFile)' res/msi/CustomActions/Common.h || r_s11d="$r_s11d msi:firewall-helper-not-hresult"
grep -Fq 'HRESULT AddFirewallRule(bool add, LPWSTR exeName, LPWSTR exeFile)' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-helper-definition-not-hresult"
grep -Fq 'hr = AddFirewallRule(exeFile[0] == L'\''1'\'', exeNameNoExt, exeFile + 1);' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:firewall-helper-result-not-propagated"
grep -Fq 'Failed to update firewall rules for:' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:firewall-failure-not-fatal"
if grep -qE '^[[:space:]]*AddFirewallRule\(exeFile\[0\].*\);' res/msi/CustomActions/CustomActions.cpp; then
  r_s11d="$r_s11d msi:firewall-helper-result-discarded"
fi
grep -Fq "if (exeFile[0] != L'0' && exeFile[0] != L'1')" res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:firewall-mode-not-validated"
grep -Fq "if (exeFile[1] == L'\\0')" res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:firewall-empty-path-not-rejected"
if grep -Fq 'StringCchPrintfW(exeNameNoExt, 500, exeName)' res/msi/CustomActions/CustomActions.cpp; then
  r_s11d="$r_s11d msi:firewall-exe-name-format-string-copy"
fi
if grep -Fq 'StringCchPrintfW(pwszTemp, STRING_BUFFER_SIZE, exeName)' res/msi/CustomActions/FirewallRules.cpp; then
  r_s11d="$r_s11d msi:firewall-group-format-string-copy"
fi
grep -Fq 'MAX_FIREWALL_RULE_REMOVALS' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-remove-not-bounded"
grep -Fq 'pNetFwRules->Item(RuleName, &pNetFwRule)' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-remove-does-not-prove-absence"
grep -Fq 'bool absenceProven = false;' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-remove-absence-proof-missing"
grep -Fq 'ERROR_FILE_NOT_FOUND' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-absent-file-not-found-not-noop"
grep -Fq 'ERROR_NOT_FOUND' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-absent-not-found-not-noop"
grep -Fq 'ERROR_PATH_NOT_FOUND' res/msi/CustomActions/FirewallRules.cpp || r_s11d="$r_s11d msi:firewall-absent-path-not-found-not-noop"
grep -q 'Service still exists after deletion' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:service-delete-not-verified"
grep -q 'HRESULT_FROM_WIN32(lastErrorCode)' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:service-delete-errors-not-propagated"
grep -q 'if (!QueryServiceStatusExW(serviceName, &serviceStatus))' res/msi/CustomActions/ServiceUtils.cpp || r_s11d="$r_s11d msi:service-status-query-not-guarded"
grep -Fq 'if (!DeleteRuntimeGeneratedFile(installFolder, L"RuntimeBroker_rustdesk.exe"))' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:runtime-broker-cleanup-result-not-checked"
grep -q 'Failed to remove runtime-generated broker executable' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:runtime-broker-cleanup-not-fatal"
grep -q 'Id="RemoveRuntimeGeneratedFiles".*Return="check"' res/msi/Package/Fragments/CustomActions.wxs || r_s11d="$r_s11d msi:runtime-generated-cleanup-return-not-checked"
if grep -q 'Id="RemoveRuntimeGeneratedFiles".*Return="ignore"' res/msi/Package/Fragments/CustomActions.wxs; then
  r_s11d="$r_s11d msi:runtime-generated-cleanup-return-ignored"
fi
if rg -n 'CustomActionHello|Example CustomAction Hello|TODO: Add your custom action code here' res/msi >/tmp/rd_verify_r_s11d_msi_noop.$$; then
  cat /tmp/rd_verify_r_s11d_msi_noop.$$
  r_s11d="$r_s11d msi:sample-custom-action-leftover"
fi
rm -f /tmp/rd_verify_r_s11d_msi_noop.$$
grep -q 'CreateProcessW(exePath, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, workDir, &startupInfo, &pi)' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-helper-not-absolute-createprocess"
grep -q 'WaitForSingleObject(pi.hProcess, 120000)' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-helper-not-waited"
grep -q 'GetExitCodeProcess(pi.hProcess, &exitCode)' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-helper-exit-code-not-checked"
grep -q 'exitCode == ERROR_SUCCESS_REBOOT_REQUIRED' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-helper-reboot-success-not-accepted"
grep -q 'else if (exitCode != 0)' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-helper-nonzero-not-fatal"
grep -q 'WcaDeferredActionRequiresReboot();' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-reboot-not-signaled"
grep -q 'Id="RemoveAmyuniIdd".*Return="check"' res/msi/Package/Fragments/CustomActions.wxs || r_s11d="$r_s11d msi:amyuni-return-not-checked"
if grep -q 'Id="RemoveAmyuniIdd".*Return="ignore"' res/msi/Package/Fragments/CustomActions.wxs; then
  r_s11d="$r_s11d msi:amyuni-return-ignored"
fi
grep -Fq 'enum DriverUninstallStatus' res/msi/CustomActions/Common.h || r_s11d="$r_s11d msi:amyuni-native-status-enum-missing"
grep -Fq 'HRESULT UninstallDriver(LPCWSTR hardwareId, DriverUninstallStatus& status, BOOL &rebootRequired)' res/msi/CustomActions/Common.h || r_s11d="$r_s11d msi:amyuni-native-helper-not-hresult"
grep -Fq 'HRESULT UninstallDriver(LPCWSTR hardwareId, DriverUninstallStatus& status, BOOL &rebootRequired)' res/msi/CustomActions/DeviceUtils.cpp || r_s11d="$r_s11d msi:amyuni-native-helper-definition-not-hresult"
grep -Fq 'setupApiHr = UninstallDriver(L"usbmmidd", uninstallStatus, rebootRequired);' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-native-result-not-captured"
if grep -Fq 'UninstallDriver(L"usbmmidd", rebootRequired);' res/msi/CustomActions/CustomActions.cpp; then
  r_s11d="$r_s11d msi:amyuni-native-result-discarded"
fi
grep -Fq 'DriverUninstallNotPresent' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-not-present-branch-missing"
grep -Fq 'DriverUninstallRemoved' res/msi/CustomActions/DeviceUtils.cpp || r_s11d="$r_s11d msi:amyuni-removed-status-missing"
grep -Fq 'ERROR_NO_MORE_ITEMS' res/msi/CustomActions/DeviceUtils.cpp || r_s11d="$r_s11d msi:amyuni-enum-completion-not-checked"
grep -Fq 'MultiSzContains(deviceId, hardwareId)' res/msi/CustomActions/DeviceUtils.cpp || r_s11d="$r_s11d msi:amyuni-hardware-id-not-multisz"
grep -Fq 'ZeroMemory(deviceId, sizeof(deviceId));' res/msi/CustomActions/DeviceUtils.cpp || r_s11d="$r_s11d msi:amyuni-hardware-id-buffer-not-cleared"
grep -Fq 'HRESULT_FROM_WIN32(lastError)' res/msi/CustomActions/DeviceUtils.cpp || r_s11d="$r_s11d msi:amyuni-native-errors-not-propagated"
grep -Fq 'hr = FAILED(setupApiHr) ? setupApiHr : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);' res/msi/CustomActions/CustomActions.cpp || r_s11d="$r_s11d msi:amyuni-missing-helper-after-native-failure-not-fatal"
grep -q 'RemoveAmyuniIdd".*Condition="Installed AND (REMOVE=&quot;ALL&quot; OR UPGRADINGPRODUCTCODE)"' res/msi/Package/Components/RustDesk.wxs || r_s11d="$r_s11d msi:amyuni-removal-not-uninstall-upgrade-only"
if grep -qE 'ShellExecuteW\(NULL, L"open", (exe|exePath|L"netsh")' res/msi/CustomActions/CustomActions.cpp; then
  r_s11d="$r_s11d msi:amyuni-or-netsh-shellexecute-leftover"
fi
grep -q 'struct DeviceInstaller64Paths' src/virtual_display_manager.rs || r_s11d="$r_s11d runtime:amyuni-path-struct-missing"
grep -q 'fn get_deviceinstaller64_paths' src/virtual_display_manager.rs || r_s11d="$r_s11d runtime:amyuni-absolute-path-helper-missing"
grep -q 'paths.exe_path.as_ptr()' src/virtual_display_manager.rs || r_s11d="$r_s11d runtime:amyuni-helper-not-absolute"
if grep -qE 'ShellExecuteA|let mut exe_file = INSTALLER_EXE_FILE\.bytes|ShellExecuteW\([^;]*INSTALLER_EXE_FILE' src/virtual_display_manager.rs; then
  r_s11d="$r_s11d runtime:amyuni-helper-bare-name-launch"
fi
grep -q 'Windows installer service-binary root and elevated script authority' requirements.html || r_s11d="$r_s11d requirements-disposition-missing"
grep -q 'R-S11d — Windows installer service-root authority' HARDENING_STATUS.md || r_s11d="$r_s11d hardening-ledger-missing"
grep -q 'Windows Amyuni IDD helper launch provenance' requirements.html || r_s11d="$r_s11d amyuni-requirements-disposition-missing"
grep -q 'R-S11d-1 — Windows Amyuni IDD helper launch provenance' HARDENING_STATUS.md || r_s11d="$r_s11d amyuni-hardening-ledger-missing"
grep -q 'Windows Amyuni IDD cleanup completion authority' requirements.html || r_s11d="$r_s11d amyuni-cleanup-requirements-disposition-missing"
grep -q 'R-S11d-2 — Windows Amyuni IDD cleanup completion authority' HARDENING_STATUS.md || r_s11d="$r_s11d amyuni-cleanup-hardening-ledger-missing"
grep -q 'Windows MSI firewall custom-action completion authority' requirements.html || r_s11d="$r_s11d firewall-requirements-disposition-missing"
grep -q 'R-S11d-7 — Windows MSI firewall custom-action completion authority' HARDENING_STATUS.md || r_s11d="$r_s11d firewall-hardening-ledger-missing"
grep -Fq 'pub(crate) fn trusted_system_tool_path(tool: &str) -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d="$r_s11d windows:trusted-system-tool-helper-not-crate-visible"
grep -Fq 'trusted_system_tool_path("mstsc.exe")' src/port_forward.rs || r_s11d="$r_s11d rdp:mstsc-not-trusted-system-tool"
grep -Fq '"Win32_Security_Credentials"' Cargo.toml || r_s11d="$r_s11d rdp:windows-credential-feature-missing"
if grep -Fq 'Command::new("cmdkey")' src/port_forward.rs || grep -Fq 'Command::new("mstsc")' src/port_forward.rs || grep -Fq 'trusted_system_tool_path("cmdkey.exe")' src/port_forward.rs; then
  r_s11d="$r_s11d rdp:cmdkey-or-bare-mstsc-launch"
fi
grep -Fq 'const RDP_CREDENTIAL_TARGET: &str = "TERMSRV/localhost";' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-target-not-pinned"
grep -Fq 'let has_complete_credentials = !username.is_empty() && !password.is_empty();' src/port_forward.rs || r_s11d="$r_s11d rdp:partial-credentials-not-rejected"
grep -Fq 'Ignoring incomplete RDP credential; username and password are both required' src/port_forward.rs || r_s11d="$r_s11d rdp:partial-credential-warning-missing"
grep -Fq 'args.push("/prompt".to_owned());' src/port_forward.rs || r_s11d="$r_s11d rdp:unseeded-mstsc-not-prompted"
grep -Fq 'CredReadW(' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-state-not-snapshotted"
grep -Fq 'CredWriteW(&raw, 0)' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-not-native-write"
grep -Fq 'CredDeleteW(' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-not-native-delete"
grep -Fq 'CRED_TYPE_GENERIC' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-type-not-generic"
grep -Fq 'CRED_PERSIST_SESSION' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-not-session-scoped"
grep -Fq 'RDP_CREDENTIAL_ACTIVE' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-concurrency-guard-missing"
grep -Fq 'struct RdpCredentialLease' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-lease-missing"
grep -Fq 'impl Drop for RdpCredentialLease' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-lease-drop-missing"
grep -Fq 'cleanup_rdp_credentials_when_mstsc_exits(lease, child);' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-not-restored-after-mstsc"
grep -Fq 'lease.restore()?' src/port_forward.rs || r_s11d="$r_s11d rdp:credential-not-restored-after-spawn-failure"
if grep -Fq '/pass:' src/port_forward.rs || grep -qE 'std::env::(set_var|var)\("rdp_(username|password)"' src/port_forward.rs src/ui_session_interface.rs; then
  r_s11d="$r_s11d rdp:credential-password-argv-or-env"
fi
grep -q 'Windows RDP viewer credential command provenance' requirements.html || r_s11d="$r_s11d rdp-requirements-disposition-missing"
grep -q 'R-S11d-8 — Windows RDP viewer credential command provenance' HARDENING_STATUS.md || r_s11d="$r_s11d rdp-hardening-ledger-missing"
grep -Fq 'pub fn get_default_shell() -> Result<String>' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:helper-not-fallible"
grep -Fq 'fn get_default_shell() -> Result<String>' src/server/terminal_service.rs || r_s11d="$r_s11d terminal-shell:service-not-fallible"
grep -Fq 'GetSystemDirectoryW(Some(&mut buffer))' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:no-systemdir-resolution"
grep -Fq 'PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe")' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:pwsh7-absolute-candidate-missing"
grep -Fq 'PathBuf::from(r"C:\Program Files\PowerShell\6\pwsh.exe")' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:pwsh6-absolute-candidate-missing"
grep -Fq '.join("WindowsPowerShell")' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:system32-powershell-candidate-missing"
grep -Fq 'system_dir.join("cmd.exe")' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:system32-cmd-candidate-missing"
grep -Fq 'Err(anyhow!("no trusted Windows terminal shell found"))' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:no-fail-closed-error"
grep -Fq 'let shell = get_default_shell()?;' src/server/terminal_helper.rs || r_s11d="$r_s11d terminal-shell:helper-open-not-fail-closed"
grep -Fq 'let shell = get_default_shell()?;' src/server/terminal_service.rs || r_s11d="$r_s11d terminal-shell:direct-open-not-fail-closed"
if grep -Fq 'COMSPEC' src/server/terminal_helper.rs src/server/terminal_service.rs \
  || grep -qE '^[[:space:]]*"pwsh\.exe",[[:space:]]*$' src/server/terminal_helper.rs \
  || grep -Fq 'unwrap_or_else(|_| "cmd.exe".to_string())' src/server/terminal_helper.rs src/server/terminal_service.rs; then
  r_s11d="$r_s11d terminal-shell:ambient-or-bare-shell-fallback"
fi
grep -q 'Windows terminal default-shell command provenance' requirements.html || r_s11d="$r_s11d terminal-shell-requirements-disposition-missing"
grep -q 'R-S11d-9 — Windows terminal default-shell command provenance' HARDENING_STATUS.md || r_s11d="$r_s11d terminal-shell-hardening-ledger-missing"
grep -Fq 'trusted_system_tool_path("taskkill.exe")' libs/portable/src/main.rs || r_s11d="$r_s11d portable-taskkill:not-trusted-system-tool"
grep -Fq 'GetSystemDirectoryW(Some(&mut buffer))' libs/portable/src/main.rs || r_s11d="$r_s11d portable-taskkill:no-systemdir-resolution"
grep -Fq 'RuntimeBroker cleanup failed' libs/portable/src/main.rs || r_s11d="$r_s11d portable-taskkill:spawn-error-not-reported"
if grep -Fq 'Command::new("taskkill")' libs/portable/src/main.rs || grep -Fq 'Command::new("taskkill.exe")' libs/portable/src/main.rs; then
  r_s11d="$r_s11d portable-taskkill:bare-launch"
fi
grep -q 'Windows portable RuntimeBroker cleanup command provenance' requirements.html || r_s11d="$r_s11d portable-taskkill-requirements-disposition-missing"
grep -q 'R-S11d-10 — Windows portable RuntimeBroker cleanup command provenance' HARDENING_STATUS.md || r_s11d="$r_s11d portable-taskkill-hardening-ledger-missing"
grep -Fq 'const ELEVATED_INSTALL_ARG: &str = "--rustdesk-protected-install";' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:internal-install-arg-missing"
grep -Fq 'const ELEVATED_SILENT_INSTALL_ARG: &str = "--rustdesk-protected-silent-install";' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:internal-silent-install-arg-missing"
grep -Fq 'const PROTECTED_INSTALL_ENV_KEY: &str = "RUSTDESK_PROTECTED_INSTALL";' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:protected-env-missing"
grep -Fq 'let silent_install = args.iter().any(|arg| arg == "--silent-install");' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:silent-install-not-detected"
grep -Fq 'if click_setup || silent_install || protected_install {' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:silent-install-not-protected"
grep -Fq 'win::run_protected_installer(reader, silent)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:silent-mode-not-bound-to-protected-runner"
grep -Fq 'std::process::exit(1);' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:protected-main-error-exits-success"
grep -Fq 'ShellExecuteExW(&mut info)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:not-shell-execute-ex"
grep -Fq 'SEE_MASK_NOCLOSEPROCESS' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-elevated-process-handle"
grep -Fq 'WaitForSingleObject(process.0, INFINITE)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-parent-wait"
grep -Fq 'GetExitCodeProcess(process.0, &mut exit_code)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:relaunch-exit-code-not-checked"
grep -Fq 'if exit_code != 0 {' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:relaunch-nonzero-not-fatal"
grep -Fq 'relaunch_self_for_protected_install(silent)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:silent-mode-not-preserved-through-uac"
grep -Fq 'current_process_is_elevated()?' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:elevation-check-not-required"
grep -Fq 'FOLDERID_ProgramFilesX86' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:program-files-root-not-width-aware"
grep -Fq 'staging_is_outside_final_install_dir(&path)?' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-final-root-overlap-check"
grep -Fq 'fs::create_dir(&path)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:not-private-create-dir"
grep -Fq 'metadata.file_type().is_symlink() || crate::has_reparse_point(&metadata)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-reparse-root-reject"
grep -Fq '.env(PROTECTED_INSTALL_ENV_KEY, "1")' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:child-not-marked-protected"
grep -Fq 'let install_arg = if silent {' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:protected-runner-not-mode-aware"
grep -Fq '"--silent-install"' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:silent-child-install-arg-missing"
grep -Fq 'finish_with_payload_cleanup(&staging, &payload, result)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-error-path-manifest-cleanup"
grep -Fq 'cleanup_extracted_payload(&staging.path, &payload.files)' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-manifest-cleanup"
grep -Fq 'remove_payload_file(root, file)?' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:manifest-file-removal-missing"
grep -Fq 'ensure_clean_parent_chain(root, file)?' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:no-parent-reparse-check"
grep -Fq 'copy_runtime_broker(dir: &Path) -> Result<(), String>' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:runtime-broker-copy-not-fallible"
grep -Fq 'fs::copy(src, &target_file).map_err' libs/portable/src/main.rs || r_s11d="$r_s11d portable-staging:runtime-broker-copy-error-ignored"
grep -Fq 'relative_payload_path(&self.path)?' libs/portable/src/bin_reader.rs || r_s11d="$r_s11d portable-staging:payload-path-not-validated"
grep -Fq 'absolute embedded payload path is not allowed' libs/portable/src/bin_reader.rs || r_s11d="$r_s11d portable-staging:absolute-path-not-rejected"
grep -Fq 'is_windows_safe_component(component)' libs/portable/src/bin_reader.rs || r_s11d="$r_s11d portable-staging:windows-component-validator-missing"
grep -Fq '.create_new(true)' libs/portable/src/bin_reader.rs || r_s11d="$r_s11d portable-staging:payload-temp-not-create-new"
grep -Fq 'file.sync_all()' libs/portable/src/bin_reader.rs || r_s11d="$r_s11d portable-staging:payload-write-not-synced"
grep -Fq 'std::env::var_os("RUSTDESK_PROTECTED_INSTALL").is_some()' src/ui_interface.rs || r_s11d="$r_s11d portable-staging:run-without-install-not-blocked"
grep -Fq 'const PROTECTED_INSTALL_ENV_KEY: &str = "RUSTDESK_PROTECTED_INSTALL";' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-protected-env-missing"
grep -Fq 'const PROTECTED_INSTALL_STAGING_PREFIX: &str = "RustDesk-staging-";' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-staging-prefix-missing"
grep -Fq 'fn require_protected_install_source(' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-proof-helper-missing"
grep -Fq 'std::env::var_os(PROTECTED_INSTALL_ENV_KEY).as_deref() != Some(OsStr::new("1"))' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-protected-env-not-exact"
grep -Fq 'if !is_elevated(None)? {' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-does-not-require-elevated-child"
grep -Fq 'fs::symlink_metadata(&current_exe)?' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-source-exe-not-inspected"
grep -Fq 'has_reparse_point(&exe_metadata)' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-source-exe-reparse-not-rejected"
grep -Fq 'fs::symlink_metadata(&source_dir)?' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-source-dir-not-inspected"
grep -Fq 'has_reparse_point(&source_metadata)' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-source-dir-reparse-not-rejected"
grep -Fq 'source_name.starts_with(PROTECTED_INSTALL_STAGING_PREFIX)' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-staging-prefix-not-required"
grep -Fq 'normalized_windows_path_text(source_parent) != normalized_windows_path_text(&program_files)' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-program-files-parent-not-required"
grep -Fq 'source == final_install || source.starts_with(&(final_install + "\\"))' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-final-root-overlap-not-rejected"
grep -Fq 'let (current_exe, source_dir) = require_protected_install_source(current_exe, &install_dir)?;' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-proof-not-consumed-by-install"
grep -Fq 'fn copy_source_dir_cmd(' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-source-dir-copy-helper-missing"
grep -Fq 'let src_parent = quoted_batch_path(source_dir)?;' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-copy-source-dir-not-quoted"
grep -Fq 'let copy_exe = copy_exe_cmd(&source_dir, &exe, &path, &tools)?;' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:sink-copy-not-bound-to-proven-source-dir"
grep -Fq 'log::error!("Failed to install: {err}");' src/ui_interface.rs || r_s11d="$r_s11d portable-staging:interactive-install-failure-not-logged"
grep -Fq 'let already_elevated = match is_elevated(None)' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:run-cmds-no-already-elevated-fast-path"
grep -Fq 'std::process::Command::new(&cmd)' src/platform/windows.rs || r_s11d="$r_s11d portable-staging:run-cmds-elevated-direct-cmd-missing"
if grep -Fq 'std::fs::remove_dir_all(&dir).ok()' libs/portable/src/main.rs; then
  r_s11d="$r_s11d portable-staging:old-silent-remove-dir-all"
fi
if grep -Fq 'file.write_to_file(&dir);' libs/portable/src/main.rs; then
  r_s11d="$r_s11d portable-staging:old-infallible-write-shape"
fi
if grep -Fq 'cmd.arg("--install")' libs/portable/src/main.rs && ! grep -Fq '.env(PROTECTED_INSTALL_ENV_KEY, "1")' libs/portable/src/main.rs; then
  r_s11d="$r_s11d portable-staging:unmarked-install-ui-child"
fi
if grep -Fq 'let src_exe = cur_exe.to_owned();' src/platform/windows.rs \
  || grep -Fq 'fn copy_raw_cmd(' src/platform/windows.rs \
  || grep -Fq 'PathBuf::from(src_raw)' src/platform/windows.rs \
  || grep -Fq 'copy_exe_cmd(&src_exe, &exe, &path, &tools)?' src/platform/windows.rs; then
  r_s11d="$r_s11d portable-staging:raw-current-exe-parent-copy-leftover"
fi
silent_install_block=$(awk '/args\[0\] == "--silent-install"/,/args\[0\] == "--uninstall-cert"/' src/core_main.rs)
if ! printf '%s\n' "$silent_install_block" | grep -Fq 'std::process::exit(1);'; then
  r_s11d="$r_s11d portable-staging:silent-child-install-failure-exits-success"
fi
if ! rg -U 'pub fn install_me\(_options: String, _path: String, _silent: bool, _debug: bool\) \{\s*#\[cfg\(windows\)\]\s*std::thread::spawn\(move \|\| \{\s*if let Err\(err\) = crate::platform::windows::install_me\(&_options, _path, _silent, _debug\) \{\s*log::error!\("Failed to install: \{err\}"\);\s*std::process::exit\(1\);' src/ui_interface.rs >/tmp/rd_verify_r_s11d_install_ui.$$; then
  r_s11d="$r_s11d portable-staging:interactive-child-install-failure-exits-success"
fi
rm -f /tmp/rd_verify_r_s11d_install_ui.$$
grep -q 'Windows portable installer source-staging authority' requirements.html || r_s11d="$r_s11d portable-staging-requirements-disposition-missing"
grep -q 'R-S11d-17 — Windows portable installer source-staging authority' HARDENING_STATUS.md || r_s11d="$r_s11d portable-staging-hardening-ledger-missing"
if rg -n 'wmic|by_wmic|get_pids_with_args_by_wmic|get_pids_with_first_arg_by_wmic|get_pids_with_first_arg_check_session|not\(target_pointer_width = "64"\)|all\(target_os = "windows", not\(target_pointer_width = "64"\)\)' src/common.rs src/platform -g '*.rs' >/tmp/rd_verify_r_s11d_wmic.$$; then
  cat /tmp/rd_verify_r_s11d_wmic.$$
  r_s11d="$r_s11d windows:unsupported-32bit-wmic-process-probe-leftover"
fi
rm -f /tmp/rd_verify_r_s11d_wmic.$$
grep -q 'Windows unsupported 32-bit WMIC process-probe deletion' requirements.html || r_s11d="$r_s11d wmic-process-probe-requirements-disposition-missing"
grep -q 'R-S11d-11 — Windows unsupported 32-bit WMIC process-probe deletion' HARDENING_STATUS.md || r_s11d="$r_s11d wmic-process-probe-hardening-ledger-missing"
privacy_broker_create=$(awk '/let create_res = CreateProcessAsUserW\(/,/^[[:space:]]*\);/' src/privacy_mode/win_topmost_window.rs)
privacy_broker_create_one_line=$(printf '%s\n' "$privacy_broker_create" | tr '\n' ' ')
echo "$privacy_broker_create" | grep -q 'broker_path_utf16.as_ptr() as _' || r_s11d="$r_s11d privacy-broker:not-explicit-application-name"
echo "$privacy_broker_create_one_line" | grep -Eq 'broker_path_utf16\.as_ptr\(\) as _[[:space:]]*,[[:space:]]*NULL as _[[:space:]]*,' || r_s11d="$r_s11d privacy-broker:command-line-not-null"
echo "$privacy_broker_create" | grep -q 'current_dir_utf16.as_ptr() as _' || r_s11d="$r_s11d privacy-broker:no-explicit-current-directory"
grep -q 'if !dll_file.is_file()' src/privacy_mode/win_topmost_window.rs || r_s11d="$r_s11d privacy-broker:dll-file-existence-not-checked"
grep -q 'if !broker_file.is_file()' src/privacy_mode/win_topmost_window.rs || r_s11d="$r_s11d privacy-broker:file-existence-not-checked"
if grep -q 'cmd_utf16' src/privacy_mode/win_topmost_window.rs; then
  r_s11d="$r_s11d privacy-broker:command-line-module-parsing-leftover"
fi
grep -q 'let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };' src/platform/windows.rs || r_s11d="$r_s11d user-shortcut:com-init-hresult-not-captured"
grep -q 'if hr.is_ok()' src/platform/windows.rs || r_s11d="$r_s11d user-shortcut:com-init-hresult-success-not-checked"
grep -q 'if hr == RPC_E_CHANGED_MODE' src/platform/windows.rs || r_s11d="$r_s11d user-shortcut:com-init-changed-mode-not-hresult-checked"
if grep -q 'Err(err) if err.code() == RPC_E_CHANGED_MODE' src/platform/windows.rs || grep -q 'Ok(()) => Ok(Self { uninitialize: true })' src/platform/windows.rs; then
  r_s11d="$r_s11d user-shortcut:com-init-uses-wrong-windows-061-result-shape"
fi
create_shortcut_body=$(awk '/^pub fn create_shortcut\(id: &str\)/,/^pub fn enable_lowlevel_keyboard/' src/platform/windows.rs)
echo "$create_shortcut_body" | grep -q 'validate_shortcut_connect_id(id)?' || r_s11d="$r_s11d user-shortcut:id-not-validated"
echo "$create_shortcut_body" | grep -q 'CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)' || r_s11d="$r_s11d user-shortcut:not-native-shelllink"
echo "$create_shortcut_body" | grep -q 'IPersistFile' || r_s11d="$r_s11d user-shortcut:persistfile-save-missing"
echo "$create_shortcut_body" | grep -q 'user_desktop_dir()' || r_s11d="$r_s11d user-shortcut:desktop-known-folder-not-used"
grep -q 'fn validate_shortcut_connect_id' src/platform/windows.rs || r_s11d="$r_s11d user-shortcut:id-validator-missing"
if echo "$create_shortcut_body" | grep -qE 'write_cmds|WScript|CreateShortcut|Command::new\("cscript"\)'; then
  r_s11d="$r_s11d user-shortcut:script-backed-shortcut-leftover"
fi
if grep -q 'fn get_shortcut_icon_location' src/platform/windows.rs; then
  r_s11d="$r_s11d user-shortcut:vbs-icon-helper-leftover"
fi
grep -q 'Windows privacy broker and user shortcut process provenance' requirements.html || r_s11d="$r_s11d privacy-shortcut-requirements-disposition-missing"
grep -q 'R-S11d-12 — Windows privacy broker and user shortcut process provenance' HARDENING_STATUS.md || r_s11d="$r_s11d privacy-shortcut-hardening-ledger-missing"
grep -q 'Windows MSI runtime-generated executable cleanup completion authority' requirements.html || r_s11d="$r_s11d runtime-generated-cleanup-requirements-disposition-missing"
grep -q 'R-S11d-4 — Windows MSI runtime-generated executable cleanup completion authority' HARDENING_STATUS.md || r_s11d="$r_s11d runtime-generated-cleanup-hardening-ledger-missing"
if [ -n "$r_s11d" ]; then echo "  FAIL R-S11d Windows installer service-root authority:$r_s11d"; rc=1; else
  echo "  ok  R-S11d Windows installer service root is fixed to Program Files across EXE service paths; EXE custom path and ProgramFiles-env routing are rejected; elevated command files deny write/delete sharing; MSI public install-folder routing is absent; MSI service custom actions are native, checked, and fail closed; Amyuni helper launch uses the checked absolute helper path; MSI cleanup observes Amyuni and runtime-generated executable completion; portable installer source staging is elevated/protected/manifest-cleaned; unsupported 32-bit WMIC process probes are absent"; fi

echo "== (3b-iii-a5d2) Windows service/session token launch binds executable identity (R-S11d-13) =="
r_s11d13=
grep -Fq 'HANDLE LaunchProcessWin(LPCWSTR application, LPCWSTR cmd' src/platform/windows.cc || r_s11d13="$r_s11d13 cpp-signature-not-explicit-application"
grep -Fq "application == NULL || application[0] == L'\\0' || cmd == NULL || cmd[0] == L'\\0'" src/platform/windows.cc || r_s11d13="$r_s11d13 cpp-null-empty-guard-missing"
grep -Fq 'std::vector<wchar_t> commandLine(wcslen(cmd) + 1)' src/platform/windows.cc || r_s11d13="$r_s11d13 cpp-dynamic-command-buffer-missing"
grep -Fq 'CreateProcessAsUserW(hToken, application, commandLine.data()' src/platform/windows.cc || r_s11d13="$r_s11d13 cpp-createprocess-not-bound-to-application"
if grep -Fq 'CreateProcessAsUserW(hToken, NULL' src/platform/windows.cc; then
  r_s11d13="$r_s11d13 cpp-null-application-createprocess-leftover"
fi
if grep -Fq 'wchar_t buf[MAX_PATH]' src/platform/windows.cc; then
  r_s11d13="$r_s11d13 cpp-fixed-maxpath-command-buffer-leftover"
fi
grep -Fq 'application: *const u16,' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-ffi-application-arg-missing"
grep -Fq 'application.as_ptr(),' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-launch-call-not-passing-application"
grep -Fq 'fn launch_executable_path(exe: &Path) -> ResultType<&Path>' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-launch-path-validator-missing"
grep -Fq 'if !exe.is_absolute()' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-absolute-path-requirement-missing"
grep -Fq 'if !exe.is_file()' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-existing-file-requirement-missing"
grep -Fq 'fn append_windows_command_arg(command_line: &mut Vec<u16>, arg: &OsStr) -> ResultType<()>' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-command-arg-quoting-helper-missing"
grep -Fq 'backslashes * 2 + 1' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-quote-backslash-before-quote-rule-missing"
grep -Fq 'backslashes * 2)' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-quote-trailing-backslash-rule-missing"
grep -Fq 'fn windows_command_line(exe: &Path, arg: &[&str]) -> ResultType<Vec<u16>>' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-command-line-builder-missing"
grep -Fq 'let exe = std::env::current_exe()?' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-service-current-exe-path-missing"
launch_server_body=$(awk '/^async fn launch_server\(/,/^fn launch_executable_path/' src/platform/windows.rs)
echo "$launch_server_body" | grep -Fq 'launch_process_in_session_with_env(' || r_s11d13="$r_s11d13 rust-launch-server-not-using-bound-helper"
echo "$launch_server_body" | grep -Fq 'SERVICE_OWNED_SERVER_ARG' || r_s11d13="$r_s11d13 rust-launch-server-arg-missing"
if echo "$launch_server_body" | grep -Fq 'format!'; then
  r_s11d13="$r_s11d13 rust-launch-server-preformatted-command-leftover"
fi
run_exe_session_body=$(awk '/^fn run_exe_path_in_session_with_env/,/^#\[tokio::main/' src/platform/windows.rs)
echo "$run_exe_session_body" | grep -Fq 'launch_process_in_session_with_env(' || r_s11d13="$r_s11d13 rust-session-launch-not-using-bound-helper"
grep -Fq 'run_exe_path_in_session_with_env(Path::new(exe), arg, session_id, show, envs)' src/platform/windows.rs || r_s11d13="$r_s11d13 rust-public-session-launch-not-delegated"
if grep -Fq 'pub fn launch_privileged_process' src/platform/windows.rs || grep -Fq 'launch_privileged_process' src/core_main.rs src/platform/windows.rs requirements.html HARDENING_STATUS.md; then
  r_s11d13="$r_s11d13 obsolete-launch-privileged-process-reference-leftover"
fi
grep -Fq 'Windows service and session-token process launch provenance' requirements.html || r_s11d13="$r_s11d13 requirements-disposition-missing"
grep -Fq 'R-S11d-13 — Windows service and session-token process launch provenance' HARDENING_STATUS.md || r_s11d13="$r_s11d13 hardening-ledger-missing"
if [ -n "$r_s11d13" ]; then echo "  FAIL R-S11d-13 Windows service/session token launch provenance:$r_s11d13"; rc=1; else
  echo "  ok  R-S11d-13 Windows service/session token launches bind lpApplicationName, quote argv separately, and reject ambient executable identity"; fi

echo "== (3b-iii-a5d3) Windows service/session token source is provenance-checked (R-S11d-14) =="
r_s11d14=
grep -Fq 'static const DWORD kCreateProcessTokenAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;' src/platform/windows.cc || r_s11d14="$r_s11d14 token-access-not-minimum"
grep -Fq 'static BOOL query_logged_on_user_token' src/platform/windows.cc || r_s11d14="$r_s11d14 logged-on-user-token-helper-missing"
grep -Fq 'WTSQueryUserToken(dwSessionId, &hToken)' src/platform/windows.cc || r_s11d14="$r_s11d14 user-token-not-from-wts"
grep -Fq 'static BOOL query_trusted_winlogon_token' src/platform/windows.cc || r_s11d14="$r_s11d14 trusted-winlogon-helper-missing"
grep -Fq 'system32_executable_path(L"winlogon.exe", expectedWinlogonPath)' src/platform/windows.cc || r_s11d14="$r_s11d14 winlogon-system32-path-not-resolved"
grep -Fq 'QueryFullProcessImageNameW(hProcess, 0, imagePath.data(), &imagePathLen)' src/platform/windows.cc || r_s11d14="$r_s11d14 process-image-path-not-queried"
grep -Fq 'process_image_matches(hProcess, expectedWinlogonPath)' src/platform/windows.cc || r_s11d14="$r_s11d14 winlogon-image-not-validated"
grep -Fq 'token_session_matches(hToken, dwSessionId)' src/platform/windows.cc || r_s11d14="$r_s11d14 token-session-not-validated"
grep -Fq 'CreateWellKnownSid(WinLocalSystemSid' src/platform/windows.cc || r_s11d14="$r_s11d14 localsystem-sid-not-built"
grep -Fq 'EqualSid(tokenUser->User.Sid, localSystemSid)' src/platform/windows.cc || r_s11d14="$r_s11d14 token-user-not-compared-to-localsystem"
grep -Fq 'OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procEntry.th32ProcessID)' src/platform/windows.cc || r_s11d14="$r_s11d14 process-open-not-limited-query"
grep -Fq 'OpenProcessToken(hProcess, kCreateProcessTokenAccess, &hToken)' src/platform/windows.cc || r_s11d14="$r_s11d14 token-open-not-minimum-helper"
get_session_token_body=$(awk '/BOOL GetSessionUserTokenWin/,/^    }$/' src/platform/windows.cc)
echo "$get_session_token_body" | grep -Fq 'return query_logged_on_user_token(dwSessionId, lphUserToken, pDwTokenPid);' || r_s11d14="$r_s11d14 as-user-not-wts-helper"
echo "$get_session_token_body" | grep -Fq 'return query_trusted_winlogon_token(dwSessionId, lphUserToken, pDwTokenPid);' || r_s11d14="$r_s11d14 system-token-not-trusted-winlogon-helper"
if grep -Eq 'GetProcessUserName|GetLogonPid|GetFallbackUserPid|sihost\.exe|as_user \? L"explorer\.exe"|L"explorer\.exe"' src/platform/windows.cc src/platform/windows.rs src/server/connection.rs; then
  r_s11d14="$r_s11d14 old-basename-token-source-leftover"
fi
if grep -Fq 'PROCESS_ALL_ACCESS, FALSE, Id' src/platform/windows.cc || grep -Fq 'TOKEN_ALL_ACCESS, lphUserToken' src/platform/windows.cc; then
  r_s11d14="$r_s11d14 all-access-token-source-leftover"
fi
if grep -Fq 'EXPLORER_EXE' src/platform/windows.rs src/server/connection.rs; then
  r_s11d14="$r_s11d14 explorer-error-suppression-leftover"
fi
grep -Fq 'Windows service/session token source provenance' requirements.html || r_s11d14="$r_s11d14 requirements-disposition-missing"
grep -Fq 'R-S11d-14 — Windows service/session token source provenance' HARDENING_STATUS.md || r_s11d14="$r_s11d14 hardening-ledger-missing"
if [ -n "$r_s11d14" ]; then echo "  FAIL R-S11d-14 Windows service/session token source provenance:$r_s11d14"; rc=1; else
  echo "  ok  R-S11d-14 Windows session launches use WTS user tokens and validated LocalSystem winlogon tokens with minimum rights"; fi

echo "== (3b-iii-a5d4) Windows EXE elevated batch completion is authoritative (R-S11d-15) =="
r_s11d15=
run_cmds_body=$(awk '/fn run_cmds\(/,/^}/' src/platform/windows.rs)
write_cmds_body=$(awk '/fn write_cmds\(/,/^}/' src/platform/windows.rs)
uninstall_service_body=$(awk '/pub fn uninstall_service\(/,/^}/' src/platform/windows.rs)
install_service_body=$(awk '/pub fn install_service\(/,/^}/' src/platform/windows.rs)
echo "$write_cmds_body" | grep -Fq 'open(&tmp2)?;' || r_s11d15="$r_s11d15 marker-create-not-mandatory"
if echo "$write_cmds_body" | grep -A8 -F 'let tmp2 = get_undone_file(&command_file.path)?;' | grep -Fq '.ok()'; then
  r_s11d15="$r_s11d15 marker-create-error-ignored"
fi
if ! echo "$run_cmds_body" | grep -Fq 'let status = res?;' \
  && ! echo "$run_cmds_body" | grep -Fq 'let status = if already_elevated {'; then
  r_s11d15="$r_s11d15 elevated-status-not-captured"
fi
if echo "$run_cmds_body" | grep -Fq 'let status = if already_elevated {'; then
  echo "$run_cmds_body" | grep -Fq 'command.status()?' || r_s11d15="$r_s11d15 elevated-direct-status-not-captured"
  echo "$run_cmds_body" | grep -Fq 'runas::Command::new(cmd)' || r_s11d15="$r_s11d15 unelevated-runas-branch-missing"
fi
echo "$run_cmds_body" | grep -Fq 'let marker_left = tmp2.exists();' || r_s11d15="$r_s11d15 marker-state-not-captured"
echo "$run_cmds_body" | grep -Fq 'if !status.success() || marker_left {' || r_s11d15="$r_s11d15 status-or-marker-not-required"
echo "$run_cmds_body" | grep -Fq 'completion marker {}' || r_s11d15="$r_s11d15 failure-message-does-not-report-marker-state"
if echo "$run_cmds_body" | grep -Fq 'let _ = res?;'; then
  r_s11d15="$r_s11d15 elevated-status-still-ignored"
fi
echo "$uninstall_service_body" | grep -Fq 'log::error!("{err}");' || r_s11d15="$r_s11d15 uninstall-failure-not-error-logged"
echo "$uninstall_service_body" | grep -Fq 'return false;' || r_s11d15="$r_s11d15 uninstall-failure-not-false"
if echo "$uninstall_service_body" | grep -Fq 'return true;'; then
  r_s11d15="$r_s11d15 uninstall-failure-still-success"
fi
echo "$install_service_body" | grep -Fq 'crate::ipc::EXIT_RECV_CLOSE.store(true, Ordering::Relaxed);' || r_s11d15="$r_s11d15 install-failure-exit-close-not-restored"
echo "$install_service_body" | grep -Fq 'log::error!("{err}");' || r_s11d15="$r_s11d15 install-failure-not-error-logged"
echo "$install_service_body" | grep -Fq 'return false;' || r_s11d15="$r_s11d15 install-failure-not-false"
if echo "$install_service_body" | grep -Fq 'return true;'; then
  r_s11d15="$r_s11d15 install-failure-still-success"
fi
grep -Fq 'Windows EXE elevated batch completion accounting' requirements.html || r_s11d15="$r_s11d15 requirements-disposition-missing"
grep -Fq 'R-S11d-15 — Windows EXE elevated batch completion accounting' HARDENING_STATUS.md || r_s11d15="$r_s11d15 hardening-ledger-missing"
if [ -n "$r_s11d15" ]; then echo "  FAIL R-S11d-15 Windows EXE elevated batch completion accounting:$r_s11d15"; rc=1; else
  echo "  ok  R-S11d-15 Windows elevated EXE batches require marker creation, successful exit status, marker removal, and false-on-failure service wrappers"; fi

echo "== (3b-iii-a5d4b) Windows EXE elevated batch rejects ambient cmd state (R-S11d-18) =="
r_s11d18=
grep -Fq 'FOLDERID_ProgramData' src/platform/windows.rs || r_s11d18="$r_s11d18 programdata-known-folder-missing"
grep -Fq 'pub(crate) fn program_data_dir() -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d18="$r_s11d18 programdata-helper-missing"
grep -Fq 'fn batch_literal_text<' src/platform/windows.rs || r_s11d18="$r_s11d18 batch-literal-guard-missing"
grep -Fq 'fn batch_path_text(path: &Path, label: &str) -> ResultType<String>' src/platform/windows.rs || r_s11d18="$r_s11d18 batch-path-guard-missing"
grep -Fq "'\"' | '%'" src/platform/windows.rs || r_s11d18="$r_s11d18 cmd-expansion-metachar-quote-not-rejected"
for ch in '%' '!' '&' '|' '<' '>' '^' '@' '\r' '\n'; do
  grep -Fq "'$ch'" src/platform/windows.rs || r_s11d18="$r_s11d18 cmd-expansion-metachar-$ch-not-rejected"
done
grep -Fq 'fn push_installer_command_dir(' src/platform/windows.rs || r_s11d18="$r_s11d18 installer-command-dir-candidate-helper-missing"
grep -Fq 'fn installer_command_dirs() -> ResultType<Vec<PathBuf>>' src/platform/windows.rs || r_s11d18="$r_s11d18 installer-command-dirs-not-fallible-list"
grep -Fq 'for dir in installer_command_dirs()?' src/platform/windows.rs || r_s11d18="$r_s11d18 command-file-creation-does-not-try-safe-candidates"
grep -Fq '"installer command temp directory"' src/platform/windows.rs || r_s11d18="$r_s11d18 temp-dir-not-safety-checked"
grep -Fq '"installer command ProgramData directory"' src/platform/windows.rs || r_s11d18="$r_s11d18 programdata-dir-not-safety-checked"
grep -Fq '"installer command user-accessible directory"' src/platform/windows.rs || r_s11d18="$r_s11d18 user-accessible-dir-not-safety-checked"
grep -Fq 'create_errors.push(format!("{}: {err}", dir.display()));' src/platform/windows.rs || r_s11d18="$r_s11d18 command-file-create-errors-not-tracked"
grep -Fq 'batch_path_text(&path, "installer command file path")?' src/platform/windows.rs || r_s11d18="$r_s11d18 command-file-path-not-safety-checked"
grep -Fq 'let tmp2_quoted = quoted_batch_path(&tmp2)?;' src/platform/windows.rs || r_s11d18="$r_s11d18 marker-path-not-quoted-through-safe-guard"
echo "$run_cmds_body" | grep -Fq 'command.args(["/D", "/V:OFF", "/S", "/C", tmp_fn.as_str()]);' || r_s11d18="$r_s11d18 elevated-cmd-args-not-autorun-delayed-expansion-safe"
echo "$run_cmds_body" | grep -Fq '.args(&["/D", "/V:OFF", "/S", "/C", tmp_fn.as_str()])' || r_s11d18="$r_s11d18 runas-cmd-args-not-autorun-delayed-expansion-safe"
if echo "$run_cmds_body" | grep -Eq 'args\(\["/C"|args\(&\["/C"|/C", tmp_fn\]'; then
  r_s11d18="$r_s11d18 bare-cmd-slash-c-leftover"
fi
grep -Fq 'Windows EXE elevated batch cmd-state hardening' requirements.html || r_s11d18="$r_s11d18 requirements-disposition-missing"
grep -Fq 'R-S11d-18 — Windows EXE elevated batch cmd-state hardening' HARDENING_STATUS.md || r_s11d18="$r_s11d18 hardening-ledger-missing"
if [ -n "$r_s11d18" ]; then echo "  FAIL R-S11d-18 Windows EXE elevated batch cmd-state hardening:$r_s11d18"; rc=1; else
  echo "  ok  R-S11d-18 Windows elevated EXE batches use cmd /D /V:OFF /S /C and reject expansion-sensitive generated paths"; fi

echo "== (3b-iii-a5d4c) Windows EXE uninstall cleanup uses known-folder literal paths (R-S11d-19) =="
r_s11d19=
grep -Fq 'fn get_install_info() -> (String, String, String)' src/platform/windows.rs || r_s11d19="$r_s11d19 stale-install-info-start-menu-field-left"
grep -Fq 'fn get_uninstall(kill_self: bool, tools: &WindowsSystemTools) -> ResultType<String>' src/platform/windows.rs || r_s11d19="$r_s11d19 uninstall-builder-not-fallible"
grep -Fq 'let uninstall_str = get_uninstall(false, &tools)?;' src/platform/windows.rs || r_s11d19="$r_s11d19 install-path-does-not-propagate-uninstall-build-failure"
grep -Fq 'run_cmds(get_uninstall(kill_self, &tools)?, true, "uninstall")' src/platform/windows.rs || r_s11d19="$r_s11d19 uninstall-path-does-not-propagate-uninstall-build-failure"
grep -Fq 'batch_literal_text(&path, "installed path")?' src/platform/windows.rs || r_s11d19="$r_s11d19 installed-path-not-batch-literal-guarded"
grep -Fq 'let start_menu = quoted_batch_path(&common_programs_app_dir()?)?;' src/platform/windows.rs || r_s11d19="$r_s11d19 start-menu-cleanup-not-known-folder-quoted"
grep -Fq 'let public_desktop_shortcut = quoted_batch_path(&public_desktop_app_shortcut_path()?)?;' src/platform/windows.rs || r_s11d19="$r_s11d19 public-desktop-cleanup-not-known-folder-quoted"
grep -Fq 'let startup_tray_shortcut = quoted_batch_path(&common_startup_tray_shortcut_path()?)?;' src/platform/windows.rs || r_s11d19="$r_s11d19 startup-cleanup-not-known-folder-quoted"
grep -Fq 'match common_startup_tray_shortcut_path().and_then(|path| quoted_batch_path(&path))' src/platform/windows.rs || r_s11d19="$r_s11d19 service-uninstall-startup-cleanup-not-known-folder"
grep -Fq '.and_then(|path| quoted_batch_path(&path))' src/platform/windows.rs || r_s11d19="$r_s11d19 service-uninstall-startup-cleanup-not-quoted"
grep -Fq 'if exist {public_desktop_shortcut} del /f /q {public_desktop_shortcut}' src/platform/windows.rs || r_s11d19="$r_s11d19 public-desktop-cleanup-command-not-literal"
grep -Fq 'if exist {startup_tray_shortcut} del /f /q {startup_tray_shortcut}' src/platform/windows.rs || r_s11d19="$r_s11d19 startup-cleanup-command-not-literal"
if grep -nE '%(ProgramData|PROGRAMDATA|PUBLIC)%' src/platform/windows.rs >/tmp/rd_verify_r_s11d19_envroots.$$; then
  cat /tmp/rd_verify_r_s11d19_envroots.$$
  r_s11d19="$r_s11d19 env-expanded-cleanup-root-leftover"
fi
rm -f /tmp/rd_verify_r_s11d19_envroots.$$
grep -Fq 'Windows EXE uninstall cleanup known-folder authority' requirements.html || r_s11d19="$r_s11d19 requirements-disposition-missing"
grep -Fq 'R-S11d-19 — Windows EXE uninstall cleanup known-folder authority' HARDENING_STATUS.md || r_s11d19="$r_s11d19 hardening-ledger-missing"
if [ -n "$r_s11d19" ]; then echo "  FAIL R-S11d-19 Windows EXE uninstall cleanup known-folder authority:$r_s11d19"; rc=1; else
  echo "  ok  R-S11d-19 Windows EXE uninstall cleanup uses known-folder literal paths and no env-expanded ProgramData/Public roots"; fi

echo "== (3b-iii-a5d4d) Windows EXE elevated batch command bodies fail closed (R-S11d-20) =="
r_s11d20=
for helper in \
  'fn checked_batch_cmd(command: impl AsRef<str>) -> String' \
  'fn checked_reg_add(command: String) -> String' \
  'fn require_batch_path_exists(quoted_path: &str) -> String' \
  'fn require_batch_path_absent(quoted_path: &str) -> String' \
  'fn checked_copy_to_path(command: String, quoted_target: &str) -> String' \
  'fn ensure_batch_dir_exists(path: &Path) -> ResultType<String>' \
  'fn delete_batch_path_absent_ok(command: String, quoted_path: &str) -> String' \
  'fn delete_reg_key_absent_ok(reg: &str, key: &str) -> String' \
  'fn delete_firewall_rule_absent_ok(netsh: &str, rule_name: &str) -> String' \
  'fn checked_msi_uninstall_command(command: String) -> String'; do
  grep -Fq "$helper" src/platform/windows.rs || r_s11d20="$r_s11d20 helper-missing:$helper"
done
grep -Fq 'fn delete_service_absent_ok(' src/platform/windows.rs || r_s11d20="$r_s11d20 service-delete-helper-missing"
grep -Fq 'if errorlevel 1 exit /b 1' src/platform/windows.rs || r_s11d20="$r_s11d20 fail-fast-command-check-missing"
grep -Fq 'if not exist {quoted_path} exit /b 1' src/platform/windows.rs || r_s11d20="$r_s11d20 path-exists-postcondition-missing"
grep -Fq 'if exist {quoted_path} exit /b 1' src/platform/windows.rs || r_s11d20="$r_s11d20 path-absent-postcondition-missing"
grep -Fq '{reg} query {key} >nul 2>nul && exit /b 1' src/platform/windows.rs || r_s11d20="$r_s11d20 registry-delete-absence-check-missing"
grep -Fq '{netsh} advfirewall firewall show rule name=\"{rule_name}\" >nul 2>nul && exit /b 1' src/platform/windows.rs || r_s11d20="$r_s11d20 firewall-delete-absence-check-missing"
grep -Fq 'for /L %%i in (1,1,20) do (' src/platform/windows.rs || r_s11d20="$r_s11d20 service-delete-wait-postcondition-missing"
grep -Fq '{sc} delete \"{service_name}\" >nul 2>nul' src/platform/windows.rs || r_s11d20="$r_s11d20 service-delete-not-absence-driven"
grep -Fq 'if %ERRORLEVEL% EQU 3010 goto rustdesk_msi_uninstall_ok' src/platform/windows.rs || r_s11d20="$r_s11d20 msi-reboot-success-code-not-accepted"
grep -Fq 'if %ERRORLEVEL% EQU 1605 goto rustdesk_msi_uninstall_ok' src/platform/windows.rs || r_s11d20="$r_s11d20 msi-absent-product-code-not-accepted"
grep -Fq 'let cur_exe = batch_path_text(&current_exe, "current exe")?;' src/platform/windows.rs || r_s11d20="$r_s11d20 current-exe-not-batch-literal-guarded"
grep -Fq 'let copy_broker = checked_copy_to_path(' src/platform/windows.rs || r_s11d20="$r_s11d20 broker-copy-not-checked"
[ "$(grep -Fc 'let copy_broker = checked_copy_to_path(' src/platform/windows.rs)" -ge 2 ] || r_s11d20="$r_s11d20 all-broker-copy-sites-not-checked"
grep -Fq 'format!("copy /Y \"{origin_process_exe}\" {cur_exe_quoted}")' src/platform/windows.rs || r_s11d20="$r_s11d20 broker-update-copy-target-not-quoted-checked"
grep -Fq '{} {src_parent} {install_dir} /Y /E /H /I /K /R /Z' src/platform/windows.rs || r_s11d20="$r_s11d20 xcopy-not-fail-fast-without-c"
grep -Fq 'let install_dir_cmd = ensure_batch_dir_exists(Path::new(&path))?;' src/platform/windows.rs || r_s11d20="$r_s11d20 install-dir-not-existence-checked"
grep -Fq 'let install_reg_cmds = [' src/platform/windows.rs || r_s11d20="$r_s11d20 install-registry-not-grouped-checked"
grep -Fq 'commands.push(checked_reg_add(format!(' src/platform/windows.rs || r_s11d20="$r_s11d20 hkcr-registry-not-checked"
grep -Fq 'checked_batch_cmd(format!(' src/platform/windows.rs || r_s11d20="$r_s11d20 required-command-wrapper-not-used"
grep -Fq 'run_shortcut_script_cmd(' src/platform/windows.rs || r_s11d20="$r_s11d20 shortcut-runner-missing"
grep -Fq 'require_batch_path_exists(&shortcut_path)' src/platform/windows.rs || r_s11d20="$r_s11d20 shortcut-target-postcondition-missing"
grep -Fq 'delete_reg_key_absent_ok(&tools.reg, &subkey)' src/platform/windows.rs || r_s11d20="$r_s11d20 uninstall-registry-delete-not-absence-checked"
grep -Fq 'delete_firewall_rule_absent_ok(&tools.netsh, &format!("{app_name} Service"))' src/platform/windows.rs || r_s11d20="$r_s11d20 firewall-cleanup-not-absence-checked"
grep -Fq 'delete_service_absent_ok(' src/platform/windows.rs || r_s11d20="$r_s11d20 service-cleanup-not-absence-checked"
grep -Fq '"rustdesk_service_deleted_before_uninstall"' src/platform/windows.rs || r_s11d20="$r_s11d20 full-uninstall-service-delete-label-missing"
grep -Fq '"rustdesk_service_deleted_service_uninstall"' src/platform/windows.rs || r_s11d20="$r_s11d20 service-uninstall-service-delete-label-missing"
grep -Fq 'let remove_install_dir =' src/platform/windows.rs || r_s11d20="$r_s11d20 install-dir-removal-not-postchecked"
grep -Fq 'let remove_start_menu = delete_batch_path_absent_ok(' src/platform/windows.rs || r_s11d20="$r_s11d20 start-menu-removal-not-postchecked"
grep -Fq 'let remove_public_desktop_shortcut = delete_batch_path_absent_ok(' src/platform/windows.rs || r_s11d20="$r_s11d20 desktop-shortcut-removal-not-postchecked"
grep -Fq 'let remove_startup_tray_shortcut = delete_batch_path_absent_ok(' src/platform/windows.rs || r_s11d20="$r_s11d20 startup-shortcut-removal-not-postchecked"
grep -Fq 'checked_msi_uninstall_command(command)' src/platform/windows.rs || r_s11d20="$r_s11d20 bound-msi-uninstall-not-exit-checked"
grep -Fq 'checked_msi_uninstall_command(reg_uninstall_string)' src/platform/windows.rs || r_s11d20="$r_s11d20 fallback-msi-uninstall-not-exit-checked"
if grep -Fq '/Y /E /H /C /I /K /R /Z' src/platform/windows.rs; then
  r_s11d20="$r_s11d20 xcopy-continue-on-error-leftover"
fi
if grep -Fq 'md \"{path}\"' src/platform/windows.rs; then
  r_s11d20="$r_s11d20 raw-install-dir-create-leftover"
fi
if grep -Fq '{sc} delete {app_name}' src/platform/windows.rs; then
  r_s11d20="$r_s11d20 raw-service-delete-leftover"
fi
if grep -Fq '{reg} delete {subkey} /f' src/platform/windows.rs; then
  r_s11d20="$r_s11d20 raw-uninstall-registry-delete-leftover"
fi
grep -Fq 'Windows EXE elevated batch command postconditions' requirements.html || r_s11d20="$r_s11d20 requirements-disposition-missing"
grep -Fq 'R-S11d-20 — Windows EXE elevated batch command postconditions' HARDENING_STATUS.md || r_s11d20="$r_s11d20 hardening-ledger-missing"
if [ -n "$r_s11d20" ]; then echo "  FAIL R-S11d-20 Windows EXE elevated batch command postconditions:$r_s11d20"; rc=1; else
  echo "  ok  R-S11d-20 Windows elevated EXE batch bodies fail fast for required operations and verify persistent file/service/registry/firewall cleanup state"; fi

echo "== (3b-iii-a5d4e) Windows app-name is a constrained system identifier (R-S11d-26) =="
r_s11d26=
grep -Fq 'const MAX_CUSTOM_CLIENT_APP_NAME_LEN: usize = 64;' src/common.rs || r_s11d26="$r_s11d26 rust:max-len-missing"
grep -Fq 'fn custom_client_app_name_is_valid(app_name: &str) -> bool' src/common.rs || r_s11d26="$r_s11d26 rust:validator-missing"
grep -Fq 'bytes[0].is_ascii_alphabetic()' src/common.rs || r_s11d26="$r_s11d26 rust:first-char-not-alpha"
grep -Fq 'bytes[bytes.len() - 1].is_ascii_alphanumeric()' src/common.rs || r_s11d26="$r_s11d26 rust:last-char-not-alnum"
grep -Fq '*byte == b'\''-'\''' src/common.rs || r_s11d26="$r_s11d26 rust:hyphen-grammar-missing"
custom_app_name_block=$(awk '/data.remove\("app-name"\)/,/APP_NAME.write/' src/common.rs)
echo "$custom_app_name_block" | grep -Fq 'let Some(app_name) = app_name.as_str() else' || r_s11d26="$r_s11d26 rust:non-string-app-name-not-fatal"
echo "$custom_app_name_block" | grep -Fq 'if !custom_client_app_name_is_valid(app_name)' || r_s11d26="$r_s11d26 rust:signed-app-name-not-validated"
echo "$custom_app_name_block" | grep -Fq 'return;' || r_s11d26="$r_s11d26 rust:invalid-app-name-not-rejecting-payload"
[ "$(grep -Fc 'config::APP_NAME.write().unwrap() = app_name.to_owned();' src/common.rs)" -eq 1 ] || r_s11d26="$r_s11d26 rust:unexpected-app-name-write-count"
grep -Fq 'fn custom_client_app_name_identifier_contract()' src/common.rs || r_s11d26="$r_s11d26 rust:validator-test-missing"
grep -Fq 'APP_NAME_IDENTIFIER_RE = re.compile(r"^[A-Za-z](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$")' res/msi/preprocess.py || r_s11d26="$r_s11d26 msi:validator-regex-missing"
grep -Fq 'def app_name_is_valid(app_name):' res/msi/preprocess.py || r_s11d26="$r_s11d26 msi:validator-function-missing"
grep -Fq 'if not app_name_is_valid(app_name):' res/msi/preprocess.py || r_s11d26="$r_s11d26 msi:app-name-not-validated-before-use"
grep -Fq '"invalid --app-name: expected 1-64 ASCII letters, digits, or hyphens; "' res/msi/preprocess.py || r_s11d26="$r_s11d26 msi:error-contract-missing"
grep -Fq 'Windows app-name identity contract' requirements.html || r_s11d26="$r_s11d26 requirements-disposition-missing"
grep -Fq 'R-S11d-26 — Windows app-name identity contract' HARDENING_STATUS.md || r_s11d26="$r_s11d26 hardening-ledger-missing"
if [ -n "$r_s11d26" ]; then echo "  FAIL R-S11d-26 Windows app-name identity contract:$r_s11d26"; rc=1; else
  echo "  ok  R-S11d-26 signed custom-client and MSI app names are constrained ASCII system identifiers before reaching service/protocol/path/batch sinks"; fi

echo "== (3b-iii-a5d4f) Windows custom-client public staging path is absent (R-S11d-27) =="
r_s11d27=
if grep -nE 'prepare_custom_client_update|get_custom_client_staging_dir|remove_custom_client_staging_dir|get_public_base_dir|RustDeskCustomClientStaging' src/platform/windows.rs >/tmp/rd_verify_r_s11d27_staging.$$; then
  r_s11d27="$r_s11d27 windows-public-custom-client-staging-leftover:$(cat /tmp/rd_verify_r_s11d27_staging.$$)"
fi
rm -f /tmp/rd_verify_r_s11d27_staging.$$
if grep -nF 'current_exe_dir.join("custom.txt")' src/platform/windows.rs >/tmp/rd_verify_r_s11d27_copy.$$; then
  r_s11d27="$r_s11d27 executable-dir-custom-txt-copy-leftover:$(cat /tmp/rd_verify_r_s11d27_copy.$$)"
fi
rm -f /tmp/rd_verify_r_s11d27_copy.$$
grep -Fq 'Windows custom-client public staging deletion' requirements.html || r_s11d27="$r_s11d27 requirements-disposition-missing"
grep -Fq 'R-S11d-27 — Windows custom-client public staging deletion' HARDENING_STATUS.md || r_s11d27="$r_s11d27 hardening-ledger-missing"
if [ -n "$r_s11d27" ]; then echo "  FAIL R-S11d-27 Windows custom-client public staging deletion:$r_s11d27"; rc=1; else
  echo "  ok  R-S11d-27 Windows custom-client updates have no public staging directory or executable-dir custom.txt copy loader"; fi

echo "== (3b-iii-a5d4a) Windows MSI service mode is package authority, not caller connection type (R-S11d-21) =="
r_s11d21=
if grep -RInE 'CC_CONNECTION_TYPE|--conn-type|conn_type|gen_conn_type' res/msi >/tmp/rd_verify_r_s11d21_msi.$$; then
  cat /tmp/rd_verify_r_s11d21_msi.$$
  r_s11d21="$r_s11d21 msi:connection-type-service-gate-leftover"
fi
rm -f /tmp/rd_verify_r_s11d21_msi.$$
grep -Fq '<Custom Action="CreateStartService" Before="InstallFinalize" Condition="NOT (Installed AND REMOVE AND NOT UPGRADINGPRODUCTCODE)" />' res/msi/Package/Components/RustDesk.wxs || r_s11d21="$r_s11d21 msi:create-service-not-package-policy"
grep -Fq '<Custom Action="CreateStartService.SetParam" Before="CreateStartService" Condition="NOT (Installed AND REMOVE AND NOT UPGRADINGPRODUCTCODE)" />' res/msi/Package/Components/RustDesk.wxs || r_s11d21="$r_s11d21 msi:create-service-setparam-not-package-policy"
grep -Fq '<Custom Action="LaunchAppTray" After="InstallFinalize" Condition="(LAUNCH_TRAY_APP=&quot;Y&quot; OR LAUNCH_TRAY_APP=&quot;1&quot;) AND (NOT (Installed AND REMOVE AND NOT UPGRADINGPRODUCTCODE))"/>' res/msi/Package/Components/RustDesk.wxs || r_s11d21="$r_s11d21 msi:launch-tray-still-connection-type-gated"
grep -Fq '<Component Id="App.StartupFolder.ShortcutTray" Guid="B1D1E2BB-E53E-E159-DB7C-744D5C726A8C" Condition="STARTUPSHORTCUTS = 1">' res/msi/Package/Components/RustDesk.wxs || r_s11d21="$r_s11d21 msi:startup-tray-still-connection-type-gated"
grep -Fq 'Windows MSI service-mode package authority' requirements.html || r_s11d21="$r_s11d21 requirements-disposition-missing"
grep -Fq 'R-S11d-21 — Windows MSI service-mode package authority' HARDENING_STATUS.md || r_s11d21="$r_s11d21 hardening-ledger-missing"
if [ -n "$r_s11d21" ]; then echo "  FAIL R-S11d-21 Windows MSI service-mode package authority:$r_s11d21"; rc=1; else
  echo "  ok  R-S11d-21 MSI service/tray install state is no longer controlled by connection-type public properties"; fi

echo "== (3b-iii-a5d4b) Windows EXE certificate cleanup reports and enforces completion (R-S11d-22) =="
r_s11d22=
grep -Fq 'extern "C" BOOL DeleteRustDeskTestCertsW()' src/platform/windows_delete_test_cert.cc || r_s11d22="$r_s11d22 cert-helper-not-status-returning"
grep -Fq 'fn DeleteRustDeskTestCertsW() -> BOOL;' src/platform/windows.rs || r_s11d22="$r_s11d22 rust-ffi-not-status-returning"
grep -Fq 'if unsafe { DeleteRustDeskTestCertsW() } == 0 {' src/platform/windows.rs || r_s11d22="$r_s11d22 rust-ffi-status-not-checked"
grep -Fq 'return Err(anyhow!("Failed to delete RustDesk test certificates"));' src/platform/windows.rs || r_s11d22="$r_s11d22 cert-cleanup-error-not-propagated"
grep -Fq 'if let Err(err) = crate::platform::windows::uninstall_cert() {' src/core_main.rs || r_s11d22="$r_s11d22 uninstall-cert-cli-not-error-checked"
grep -Fq 'std::process::exit(1);' src/core_main.rs || r_s11d22="$r_s11d22 uninstall-cert-cli-not-nonzero-on-failure"
grep -Fq 'checked_batch_cmd(format!("{} --uninstall-cert", quoted_batch_path(&exe)?))' src/platform/windows.rs || r_s11d22="$r_s11d22 uninstall-cert-batch-command-not-checked"
grep -Fq 'map_err(|err| anyhow!("Failed to resolve current exe for EXE uninstall helpers: {err}"))?' src/platform/windows.rs || r_s11d22="$r_s11d22 uninstall-cert-current-exe-failure-not-fatal"
grep -Fq 'result = RegQueryValueExW(cert_key.get(), L"Blob", NULL, &value_type, blob.data(), &blob_size);' src/platform/windows_delete_test_cert.cc || r_s11d22="$r_s11d22 cert-blob-read-not-status-checked"
grep -Fq 'return std::memcmp(blob.data() + blob.size() - suffix_size, kWdkTestCertSuffix, suffix_size) == 0;' src/platform/windows_delete_test_cert.cc || r_s11d22="$r_s11d22 cert-blob-match-not-bounded"
grep -Fq 'RegOpenKeyExW(root, base_path.c_str(), 0, KEY_READ, system_certificates.receive())' src/platform/windows_delete_test_cert.cc || r_s11d22="$r_s11d22 cert-store-open-not-read-scoped"
grep -Fq 'const wchar_t kWrongRootStorePrefix[] = {static_cast<wchar_t>(0x4F52), static_cast<wchar_t>(0x544F), L' src/platform/windows_delete_test_cert.cc || r_s11d22="$r_s11d22 wrong-root-prefix-not-wide-explicit"
if grep -Fq 'extern "C" void DeleteRustDeskTestCertsW' src/platform/windows_delete_test_cert.cc src/platform/windows.rs; then
  r_s11d22="$r_s11d22 cert-helper-void-return-leftover"
fi
if grep -Fq 'readResult' src/platform/windows_delete_test_cert.cc; then
  r_s11d22="$r_s11d22 stale-cert-read-result-leftover"
fi
if grep -Fq 'KEY_ALL_ACCESS' src/platform/windows_delete_test_cert.cc; then
  r_s11d22="$r_s11d22 certificate-cleanup-all-access-leftover"
fi
if grep -Fq 'allow_err!(crate::platform::windows::uninstall_cert())' src/core_main.rs; then
  r_s11d22="$r_s11d22 uninstall-cert-cli-ignored-error-leftover"
fi
grep -Fq 'Windows EXE certificate cleanup completion authority' requirements.html || r_s11d22="$r_s11d22 requirements-disposition-missing"
grep -Fq 'R-S11d-22 — Windows EXE certificate cleanup completion authority' HARDENING_STATUS.md || r_s11d22="$r_s11d22 hardening-ledger-missing"
if [ -n "$r_s11d22" ]; then echo "  FAIL R-S11d-22 Windows EXE certificate cleanup completion authority:$r_s11d22"; rc=1; else
  echo "  ok  R-S11d-22 EXE uninstall certificate cleanup returns status, propagates errors, and is fail-fast in the elevated batch"; fi

echo "== (3b-iii-a5d4c) Windows EXE Amyuni cleanup reports and enforces completion (R-S11d-23) =="
r_s11d23=
grep -Fq 'if let Err(err) = crate::virtual_display_manager::amyuni_idd::uninstall_driver() {' src/core_main.rs || r_s11d23="$r_s11d23 amyuni-cli-not-error-checked"
grep -Fq 'log::error!("Failed to uninstall Amyuni IDD: {err}");' src/core_main.rs || r_s11d23="$r_s11d23 amyuni-cli-error-not-logged"
grep -Fq 'std::process::exit(1);' src/core_main.rs || r_s11d23="$r_s11d23 amyuni-cli-not-nonzero-on-failure"
grep -Fq 'if let Err(err) = platform::uninstall_me(true) {' src/core_main.rs || r_s11d23="$r_s11d23 top-level-uninstall-not-error-checked"
grep -Fq 'log::error!("Failed to uninstall: {}", err);' src/core_main.rs || r_s11d23="$r_s11d23 top-level-uninstall-error-not-logged"
if ! rg -U 'if let Err\(err\) = platform::uninstall_me\(true\) \{\s*log::error!\("Failed to uninstall: \{\}", err\);\s*std::process::exit\(1\);' src/core_main.rs >/tmp/rd_verify_r_s11d23_top_uninstall.$$; then
  r_s11d23="$r_s11d23 top-level-uninstall-not-nonzero-on-failure"
fi
rm -f /tmp/rd_verify_r_s11d23_top_uninstall.$$
grep -Fq 'Failed to resolve current exe for EXE uninstall helpers' src/platform/windows.rs || r_s11d23="$r_s11d23 amyuni-current-exe-failure-not-fatal"
grep -Fq 'let uninstall_amyuni_idd = checked_batch_cmd(format!(' src/platform/windows.rs || r_s11d23="$r_s11d23 amyuni-batch-command-not-checked"
grep -Fq '"{} --uninstall-amyuni-idd"' src/platform/windows.rs || r_s11d23="$r_s11d23 amyuni-batch-helper-command-missing"
grep -Fq 'quoted_batch_path(&exe)?' src/platform/windows.rs || r_s11d23="$r_s11d23 amyuni-batch-helper-not-quoted"
grep -Fq 'enum DeviceInstaller64RebootPolicy' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-reboot-policy-missing"
grep -Fq 'DeviceInstaller64RebootPolicy::Accept' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-remove-reboot-policy-missing"
grep -Fq 'DeviceInstaller64RebootPolicy::Reject' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-install-reboot-policy-missing"
grep -Fq 'const DEVICEINSTALLER64_TIMEOUT_MS: u32 = 120_000;' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-timeout-not-pinned"
grep -Fq 'fn deviceinstaller64_command_line(paths: &DeviceInstaller64Paths, args: &str) -> Vec<u16>' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-command-line-not-owned"
grep -Fq 'CreateProcessW(' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-not-createprocess"
grep -Fq 'paths.exe_path.as_ptr(),' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-application-path-not-bound"
grep -Fq 'command_line.as_mut_ptr(),' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-command-line-not-mutable"
grep -Fq 'WaitForSingleObject(process.0, DEVICEINSTALLER64_TIMEOUT_MS)' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-not-waited"
grep -Fq 'GetExitCodeProcess(process.0, &mut exit_code)' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-exit-code-not-read"
grep -Fq 'exit_code == ERROR_SUCCESS_REBOOT_REQUIRED' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-reboot-required-not-accepted"
grep -Fq 'else if exit_code != 0' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-nonzero-not-fatal"
grep -Fq 'bail!("deviceinstaller64.exe requires reboot before the driver can be used");' src/virtual_display_manager.rs || r_s11d23="$r_s11d23 amyuni-helper-install-reboot-required-not-fatal"
if ! rg -U '"remove usbmmidd",\s*DeviceInstaller64RebootPolicy::Accept' src/virtual_display_manager.rs >/tmp/rd_verify_r_s11d23_remove_policy.$$; then
  r_s11d23="$r_s11d23 amyuni-helper-remove-reboot-policy-not-accept"
fi
rm -f /tmp/rd_verify_r_s11d23_remove_policy.$$
if ! rg -U '"install usbmmidd.inf usbmmidd",\s*DeviceInstaller64RebootPolicy::Reject' src/virtual_display_manager.rs >/tmp/rd_verify_r_s11d23_install_policy.$$; then
  r_s11d23="$r_s11d23 amyuni-helper-install-reboot-policy-not-reject"
fi
rm -f /tmp/rd_verify_r_s11d23_install_policy.$$
if grep -Fq 'fn get_uninstall_amyuni_idd()' src/platform/windows.rs; then
  r_s11d23="$r_s11d23 amyuni-skip-on-current-exe-failure-leftover"
fi
if rg -U 'allow_err!\(\s*crate::virtual_display_manager::amyuni_idd::uninstall_driver\(\)\s*\)' src/core_main.rs >/tmp/rd_verify_r_s11d23_allow_err.$$; then
  cat /tmp/rd_verify_r_s11d23_allow_err.$$
  r_s11d23="$r_s11d23 amyuni-cli-ignored-error-leftover"
fi
rm -f /tmp/rd_verify_r_s11d23_allow_err.$$
if grep -Fq 'ShellExecuteW(' src/virtual_display_manager.rs; then
  r_s11d23="$r_s11d23 amyuni-runtime-shellexecute-leftover"
fi
if grep -Fq 'fn str_wide_null' src/virtual_display_manager.rs; then
  r_s11d23="$r_s11d23 amyuni-runtime-open-verb-helper-leftover"
fi
grep -Fq 'Windows EXE Amyuni IDD cleanup completion authority' requirements.html || r_s11d23="$r_s11d23 requirements-disposition-missing"
grep -Fq 'R-S11d-23 — Windows EXE Amyuni IDD cleanup completion authority' HARDENING_STATUS.md || r_s11d23="$r_s11d23 hardening-ledger-missing"
if [ -n "$r_s11d23" ]; then echo "  FAIL R-S11d-23 Windows EXE Amyuni IDD cleanup completion authority:$r_s11d23"; rc=1; else
  echo "  ok  R-S11d-23 EXE uninstall Amyuni cleanup waits for helper completion, propagates errors, and is fail-fast in the elevated batch"; fi

echo "== (3b-iii-a5d4e) Windows stale RustDesk IDD install helper is reject-only (R-S11d-24) =="
r_s11d24=
install_idd_block=$(awk '/args\[0\] == "--install-idd"/,/args\[0\] == "--uninstall-amyuni-idd"/' src/core_main.rs)
printf '%s\n' "$install_idd_block" | grep -Fq 'log::error!("--install-idd is not supported in this build");' || r_s11d24="$r_s11d24 install-idd-rejection-not-logged"
printf '%s\n' "$install_idd_block" | grep -Fq 'std::process::exit(1);' || r_s11d24="$r_s11d24 install-idd-not-nonzero"
if printf '%s\n' "$install_idd_block" | grep -Fq 'rustdesk_idd::install_update_driver()' \
  || printf '%s\n' "$install_idd_block" | grep -Fq 'allow_err!'; then
  r_s11d24="$r_s11d24 install-idd-still-runs-or-masks-driver-install"
fi
grep -Fq 'const IDD_IMPL: &str = IDD_IMPL_AMYUNI;' src/virtual_display_manager.rs || r_s11d24="$r_s11d24 active-idd-impl-not-amyuni"
grep -Fq 'Windows stale RustDesk IDD install helper completion' requirements.html || r_s11d24="$r_s11d24 requirements-disposition-missing"
grep -Fq 'R-S11d-24 — Windows stale RustDesk IDD install helper completion' HARDENING_STATUS.md || r_s11d24="$r_s11d24 hardening-ledger-missing"
if [ -n "$r_s11d24" ]; then echo "  FAIL R-S11d-24 Windows stale RustDesk IDD install helper completion:$r_s11d24"; rc=1; else
  echo "  ok  R-S11d-24 stale --install-idd rejects instead of invoking the inactive RustDesk IDD installer"; fi

echo "== (3b-iii-a5d4f) Windows Amyuni SetupAPI install rejects reboot-required completion (R-S11d-25) =="
r_s11d25=
grep -Fq 'bail!("SetupAPI driver install requires reboot before the driver can be used");' src/virtual_display_manager.rs || r_s11d25="$r_s11d25 setupapi-install-reboot-required-not-fatal"
if rg -U 'let _ =\s*unsafe \{ win_device::install_driver\(&inf_path, HARDWARE_ID, &mut reboot_required\)\? \};' src/virtual_display_manager.rs >/tmp/rd_verify_r_s11d25_setupapi_install.$$; then
  r_s11d25="$r_s11d25 setupapi-install-result-discard-leftover"
fi
rm -f /tmp/rd_verify_r_s11d25_setupapi_install.$$
setupapi_install_block=$(awk '/Installing driver by SetupAPI/,/\*is_async = false;/' src/virtual_display_manager.rs)
printf '%s\n' "$setupapi_install_block" | grep -Fq 'unsafe { win_device::install_driver(&inf_path, HARDWARE_ID, &mut reboot_required)? };' || r_s11d25="$r_s11d25 setupapi-install-call-missing"
printf '%s\n' "$setupapi_install_block" | grep -Fq 'if reboot_required {' || r_s11d25="$r_s11d25 setupapi-install-reboot-branch-missing"
printf '%s\n' "$setupapi_install_block" | grep -Fq 'bail!("SetupAPI driver install requires reboot before the driver can be used");' || r_s11d25="$r_s11d25 setupapi-install-reboot-bail-outside-block"
grep -Fq 'Windows Amyuni SetupAPI install reboot-required completion' requirements.html || r_s11d25="$r_s11d25 requirements-disposition-missing"
grep -Fq 'R-S11d-25 — Windows Amyuni SetupAPI install reboot-required completion' HARDENING_STATUS.md || r_s11d25="$r_s11d25 hardening-ledger-missing"
if [ -n "$r_s11d25" ]; then echo "  FAIL R-S11d-25 Windows Amyuni SetupAPI install reboot-required completion:$r_s11d25"; rc=1; else
  echo "  ok  R-S11d-25 Amyuni direct SetupAPI install rejects reboot-required before using the driver"; fi

echo "== (3b-iii-a5d5) Windows MSI service state and SAS policy are not persistent user-config side effects (R-S11d-16) =="
r_s11d16=
grep -Fq '<Custom Action="CreateStartService" Before="InstallFinalize" Condition="NOT (Installed AND REMOVE AND NOT UPGRADINGPRODUCTCODE)" />' res/msi/Package/Components/RustDesk.wxs || r_s11d16="$r_s11d16 msi:create-service-condition-not-always-service"
grep -Fq '<Custom Action="CreateStartService.SetParam" Before="CreateStartService" Condition="NOT (Installed AND REMOVE AND NOT UPGRADINGPRODUCTCODE)" />' res/msi/Package/Components/RustDesk.wxs || r_s11d16="$r_s11d16 msi:create-service-setparam-condition-not-always-service"
grep -Fq '<Custom Action="LaunchAppTray" After="InstallFinalize" Condition="(LAUNCH_TRAY_APP=&quot;Y&quot; OR LAUNCH_TRAY_APP=&quot;1&quot;) AND (NOT (Installed AND REMOVE AND NOT UPGRADINGPRODUCTCODE))"/>' res/msi/Package/Components/RustDesk.wxs || r_s11d16="$r_s11d16 msi:launch-tray-still-service-stop-gated"
grep -Fq '<Custom Action="TryStopDeleteService" Before="RemoveRuntimeGeneratedFiles.SetParam" Condition="Installed AND (REMOVE=&quot;ALL&quot; OR UPGRADINGPRODUCTCODE)" />' res/msi/Package/Components/RustDesk.wxs || r_s11d16="$r_s11d16 msi:stop-delete-service-not-remove-upgrade-scoped"
grep -Fq '<Custom Action="TryStopDeleteService.SetParam" Before="TryStopDeleteService" Condition="Installed AND (REMOVE=&quot;ALL&quot; OR UPGRADINGPRODUCTCODE)" />' res/msi/Package/Components/RustDesk.wxs || r_s11d16="$r_s11d16 msi:stop-delete-service-setparam-not-remove-upgrade-scoped"
if grep -RInE 'STOP_SERVICE|SetPropertyServiceStop|SetPropertyFromConfig|SetPropertyIsServiceRunning|TryDeleteStartupShortcut|ReadConfig|AddRegSoftwareSASGeneration|SoftwareSASGeneration' res/msi >/tmp/rd_verify_r_s11d16_msi.$$; then
  cat /tmp/rd_verify_r_s11d16_msi.$$
  r_s11d16="$r_s11d16 msi:persistent-service-or-sas-switch-leftover"
fi
rm -f /tmp/rd_verify_r_s11d16_msi.$$
if grep -Eq 'reg[}"]?[[:space:]]+add[^\n]*SoftwareSASGeneration|AddRegSoftwareSASGeneration|RegSetValueExW\(.*SoftwareSASGeneration' src/platform/windows.rs res/msi/CustomActions/CustomActions.cpp; then
  r_s11d16="$r_s11d16 persistent-sas-installer-write-leftover"
fi
grep -Fq 'enum OriginalSasPolicy' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-original-policy-enum-missing"
grep -Fq 'OriginalSasPolicy::Absent' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-absent-state-missing"
grep -Fq 'Present(u32),' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-present-state-missing"
grep -Fq 'static ref SEND_SAS_POLICY_MUTEX: Mutex<()> = Mutex::new(());' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-policy-mutex-missing"
grep -Fq 'let _sas_policy_guard = SEND_SAS_POLICY_MUTEX.lock().unwrap();' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-policy-mutation-not-serialized"
grep -Fq 'SOFTWARE_SAS_GENERATION_SERVICES_AND_EASE_OF_ACCESS' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-known-policy-values-missing"
grep -Fq 'let temporary_value = value | SOFTWARE_SAS_GENERATION_SERVICES;' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-ease-of-access-policy-not-preserved"
grep -Fq 'Ok(value) => bail!("Unsupported SoftwareSASGeneration value: {value}")' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-unknown-policy-not-rejected"
grep -Fq 'pub fn send_sas() -> ResultType<()> {' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-platform-result-missing"
grep -Fq 'Err(err) if err.kind() == io::ErrorKind::NotFound' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-missing-value-not-separated-from-read-error"
grep -Fq 'Err(err) => bail!("Failed to read SoftwareSASGeneration: {err}")' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-read-error-not-fail-closed"
grep -Fq '.map_err(|err| anyhow!("Failed to set SoftwareSASGeneration: {err}"))?' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-set-failure-not-fatal"
grep -Fq '.delete_value("SoftwareSASGeneration")' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-absent-restore-delete-missing"
grep -Fq '.set_value("SoftwareSASGeneration", &original)' src/platform/windows.rs || r_s11d16="$r_s11d16 sas-present-restore-missing"
grep -Fq 'crate::platform::send_sas()?;' src/server/input_service.rs || r_s11d16="$r_s11d16 input-service-sas-error-not-propagated"
if grep -Eq 'pub fn send_sas\(\) \{|original_value: Option<u32>|original == 0|log::error!\("Failed to (set|open|restore|delete) SoftwareSASGeneration' src/platform/windows.rs; then
  r_s11d16="$r_s11d16 sas-hidden-fallback-or-zero-as-absent-leftover"
fi
grep -Fq 'Windows MSI service-state and SAS policy persistence' requirements.html || r_s11d16="$r_s11d16 requirements-disposition-missing"
grep -Fq 'R-S11d-16 — Windows MSI service-state and SAS policy persistence' HARDENING_STATUS.md || r_s11d16="$r_s11d16 hardening-ledger-missing"
if [ -n "$r_s11d16" ]; then echo "  FAIL R-S11d-16 Windows MSI service-state and SAS policy persistence:$r_s11d16"; rc=1; else
  echo "  ok  R-S11d-16 MSI has no per-user stop-service switch or persistent SAS policy writer; runtime SAS uses serialized fail-closed temporary set/restore"; fi

echo "== (3b-iii-a5e) Windows EXE elevated batch binds external tools to System32 (R-S11d-5) =="
r_s11d5=
grep -q 'fn trusted_system_tool_path(tool: &str) -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d5="$r_s11d5 system-tool-resolver-missing"
grep -q 'fn quoted_batch_path(path: &Path) -> ResultType<String>' src/platform/windows.rs || r_s11d5="$r_s11d5 batch-tool-quoting-missing"
grep -q 'struct WindowsSystemTools' src/platform/windows.rs || r_s11d5="$r_s11d5 system-tool-set-missing"
for tool in chcp.com cscript.exe msiexec.exe netsh.exe reg.exe sc.exe taskkill.exe timeout.exe xcopy.exe; do
  grep -q "trusted_system_tool_path(\"$tool\")" src/platform/windows.rs || r_s11d5="$r_s11d5 missing-$tool"
done
grep -q 'let tools = WindowsSystemTools::resolve()?' src/platform/windows.rs || r_s11d5="$r_s11d5 installer-paths-do-not-resolve-tools"
grep -q 'command_with_system_tool(&reg_uninstall_string, "msiexec.exe", &tools.msiexec)' src/platform/windows.rs || r_s11d5="$r_s11d5 prior-msi-uninstall-not-bound"
grep -q 'tools.xcopy' src/platform/windows.rs || r_s11d5="$r_s11d5 xcopy-not-bound"
grep -q 'tools.cscript' src/platform/windows.rs || r_s11d5="$r_s11d5 cscript-not-bound"
grep -q '{taskkill} /F /IM' src/platform/windows.rs || r_s11d5="$r_s11d5 taskkill-not-bound"
grep -q '{netsh} advfirewall' src/platform/windows.rs || r_s11d5="$r_s11d5 netsh-not-bound"
grep -q '{sc} create' src/platform/windows.rs || r_s11d5="$r_s11d5 sc-create-not-bound"
grep -q '{reg} add' src/platform/windows.rs || r_s11d5="$r_s11d5 reg-add-not-bound"
grep -q '{chcp} 65001' src/platform/windows.rs || r_s11d5="$r_s11d5 chcp-not-bound"
if grep -nE '^[[:space:]]*(chcp 65001|reg (add|delete)|netsh advfirewall|sc (create|stop|delete|failure|start)|taskkill /F /IM|cscript "|XCOPY |xcopy |timeout 300)' src/platform/windows.rs >/tmp/rd_verify_r_s11d5_bare.$$; then
  cat /tmp/rd_verify_r_s11d5_bare.$$
  r_s11d5="$r_s11d5 bare-external-tool-in-elevated-batch"
fi
rm -f /tmp/rd_verify_r_s11d5_bare.$$
grep -q 'Windows EXE elevated batch command provenance' requirements.html || r_s11d5="$r_s11d5 requirements-disposition-missing"
grep -q 'R-S11d-5 — Windows EXE elevated batch command provenance' HARDENING_STATUS.md || r_s11d5="$r_s11d5 hardening-ledger-missing"
if [ -n "$r_s11d5" ]; then echo "  FAIL R-S11d-5 Windows EXE elevated batch command provenance:$r_s11d5"; rc=1; else
  echo "  ok  R-S11d-5 Windows EXE elevated batch resolves external tools from System32 and rejects bare tool names in the elevated batch surface"; fi

echo "== (3b-iii-a5f) Windows EXE shortcut finalization avoids temp .lnk staging (R-S11d-6) =="
r_s11d6=
grep -Fq 'FOLDERID_PublicDesktop' src/platform/windows.rs || r_s11d6="$r_s11d6 public-desktop-known-folder-missing"
grep -Fq 'FOLDERID_CommonPrograms' src/platform/windows.rs || r_s11d6="$r_s11d6 common-programs-known-folder-missing"
grep -Fq 'FOLDERID_CommonStartup' src/platform/windows.rs || r_s11d6="$r_s11d6 common-startup-known-folder-missing"
grep -Fq 'fn create_shortcut_command_file(' src/platform/windows.rs || r_s11d6="$r_s11d6 shortcut-command-helper-missing"
grep -Fq 'fn installer_script_literal(value: &str, label: &str) -> ResultType<String>' src/platform/windows.rs || r_s11d6="$r_s11d6 shortcut-script-literal-guard-missing"
grep -Fq 'fn run_shortcut_script_cmd(' src/platform/windows.rs || r_s11d6="$r_s11d6 checked-shortcut-runner-missing"
grep -Fq 'shortcut_path: &Path,' src/platform/windows.rs || r_s11d6="$r_s11d6 shortcut-runner-target-postcondition-missing"
grep -Fq ') -> ResultType<String> {' src/platform/windows.rs || r_s11d6="$r_s11d6 shortcut-runner-not-fallible"
grep -Fq 'fn public_desktop_app_shortcut_path() -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d6="$r_s11d6 desktop-shortcut-helper-missing"
grep -Fq 'Ok(public_desktop_dir()?.join(format!("{}.lnk", crate::get_app_name())))' src/platform/windows.rs || r_s11d6="$r_s11d6 desktop-shortcut-not-final-known-folder"
grep -Fq 'fn common_programs_app_dir() -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d6="$r_s11d6 start-menu-helper-missing"
grep -Fq 'Ok(common_programs_dir()?.join(crate::get_app_name()))' src/platform/windows.rs || r_s11d6="$r_s11d6 start-menu-shortcut-not-final-known-folder"
grep -Fq 'fn common_startup_tray_shortcut_path() -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d6="$r_s11d6 tray-shortcut-helper-missing"
grep -Fq 'Ok(common_startup_dir()?.join(format!("{} Tray.lnk", crate::get_app_name())))' src/platform/windows.rs || r_s11d6="$r_s11d6 tray-shortcut-not-final-known-folder"
grep -Fq 'let desktop_shortcut_path = public_desktop_app_shortcut_path()?;' src/platform/windows.rs || r_s11d6="$r_s11d6 desktop-shortcut-callsite-not-helper"
grep -Fq 'let start_menu = common_programs_app_dir()?;' src/platform/windows.rs || r_s11d6="$r_s11d6 start-menu-shortcut-callsite-not-helper"
grep -Fq 'let tray_shortcut_path = common_startup_tray_shortcut_path()?;' src/platform/windows.rs || r_s11d6="$r_s11d6 tray-shortcut-callsite-not-helper"
grep -Fq 'Path::new(&path).join(format!("Uninstall {app_name}.lnk"))' src/platform/windows.rs || r_s11d6="$r_s11d6 install-dir-uninstall-shortcut-not-final"
grep -Fq 'if errorlevel 1 exit /b 1' src/platform/windows.rs || r_s11d6="$r_s11d6 shortcut-cscript-not-fail-closed"
if grep -nE 'sLinkFile = "\{tmp_path\}|copy /Y .*\.lnk|tmp_path.*\.lnk|fn get_tray_shortcut' src/platform/windows.rs >/tmp/rd_verify_r_s11d6_staging.$$; then
  cat /tmp/rd_verify_r_s11d6_staging.$$
  r_s11d6="$r_s11d6 temp-shortcut-staging-leftover"
fi
rm -f /tmp/rd_verify_r_s11d6_staging.$$
grep -q 'Windows EXE shortcut finalization provenance' requirements.html || r_s11d6="$r_s11d6 requirements-disposition-missing"
grep -q 'R-S11d-6 — Windows EXE shortcut finalization provenance' HARDENING_STATUS.md || r_s11d6="$r_s11d6 hardening-ledger-missing"
if [ -n "$r_s11d6" ]; then echo "  FAIL R-S11d-6 Windows EXE shortcut finalization provenance:$r_s11d6"; rc=1; else
  echo "  ok  R-S11d-6 Windows EXE shortcut finalization writes final protected shortcut paths directly and rejects temp .lnk staging"; fi

echo "== (3b-iii-a6) Windows runtime process probes avoid shell tasklist/taskkill (R-S11d-3) =="
r_s11d3=
grep -q 'struct WinHandleGuard(WinHANDLE)' src/platform/windows.rs || r_s11d3="$r_s11d3 no-windows-handle-guard"
grep -q 'fn process_entry_image_name(entry: &PROCESSENTRY32W) -> String' src/platform/windows.rs || r_s11d3="$r_s11d3 no-process-entry-name-helper"
grep -q 'fn pids_by_exact_process_name(name: &str) -> ResultType<Vec<u32>>' src/platform/windows.rs || r_s11d3="$r_s11d3 no-exact-process-enumerator"
grep -q 'CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)' src/platform/windows.rs || r_s11d3="$r_s11d3 no-toolhelp-snapshot"
grep -q 'Process32FirstW(snapshot.get(), &mut entry)' src/platform/windows.rs || r_s11d3="$r_s11d3 no-process32first"
grep -q 'Process32NextW(snapshot.get(), &mut entry)' src/platform/windows.rs || r_s11d3="$r_s11d3 no-process32next"
grep -q 'process_entry_image_name(&entry).eq_ignore_ascii_case(name)' src/platform/windows.rs || r_s11d3="$r_s11d3 process-match-not-exact"
grep -q 'fn terminate_processes_by_exact_process_name(name: &str) -> ResultType<usize>' src/platform/windows.rs || r_s11d3="$r_s11d3 no-native-terminate-helper"
grep -q 'WinOpenProcess(WIN_PROCESS_TERMINATE, false, pid)' src/platform/windows.rs || r_s11d3="$r_s11d3 no-process-terminate-open"
grep -q 'WinTerminateProcess(process.get(), 0)' src/platform/windows.rs || r_s11d3="$r_s11d3 no-native-terminate"
grep -q 'pids_by_exact_process_name("consent.exe")' src/platform/windows.rs || r_s11d3="$r_s11d3 consent-not-toolhelp-backed"
grep -q 'terminate_processes_by_exact_process_name(WIN_TOPMOST_INJECTED_PROCESS_EXE)' src/platform/windows.rs || r_s11d3="$r_s11d3 broker-not-native-terminate-backed"
grep -q 'Windows runtime process command provenance' requirements.html || r_s11d3="$r_s11d3 requirements-disposition-missing"
grep -q 'R-S11d-3 — Windows runtime process command provenance' HARDENING_STATUS.md || r_s11d3="$r_s11d3 hardening-ledger-missing"
windows_runtime_process_blocks=$(
  awk '/pub fn is_process_consent_running/,/pub struct WakeLock/' src/platform/windows.rs
  awk '/pub fn try_kill_broker/,/pub fn alloc_console/' src/platform/windows.rs
)
if echo "$windows_runtime_process_blocks" | grep -Eq 'Command::new\("cmd"\)|tasklist|findstr|taskkill /F /IM|/c"\)|/C"'; then
  r_s11d3="$r_s11d3 runtime-process-shell-regressed"
fi
if grep -RInE 'stop_main_window_process|try_kill_rustdesk_main_window_process|NtTerminateProcess|PROCESS_ALL_ACCESS|ipc is occupied by another process, try kill it' src/server.rs src/platform/windows.rs >/tmp/rd_verify_r_s11d3_process_kill.$$; then
  r_s11d3="$r_s11d3 main-window-process-kill-fallback-leftover:$(cat /tmp/rd_verify_r_s11d3_process_kill.$$)"
fi
rm -f /tmp/rd_verify_r_s11d3_process_kill.$$
if grep -RInE 'Command::new\("cmd"\)|tasklist \| findstr consent\.exe' src/platform/windows.rs >/tmp/rd_verify_r_s11d3.$$; then
  cat /tmp/rd_verify_r_s11d3.$$
  rm -f /tmp/rd_verify_r_s11d3.$$
  r_s11d3="$r_s11d3 stale-service-adjacent-cmd"
else
  rm -f /tmp/rd_verify_r_s11d3.$$
fi
if [ -n "$r_s11d3" ]; then echo "  FAIL R-S11d-3 Windows runtime process command provenance:$r_s11d3"; rc=1; else
  echo "  ok  R-S11d-3 Windows service-adjacent process probes use ToolHelp/OpenProcess/TerminateProcess, not cmd tasklist/taskkill; IPC bind failure has no process-kill fallback"; fi

echo "== (3b-iii-a6b) Windows dormant diagnostic message-box side effects are absent (R-S11d-28) =="
r_s11d28=
if grep -RInE 'macro_rules![[:space:]]*my_println|my_println!' src >/tmp/rd_verify_r_s11d28_macro.$$; then
  r_s11d28="$r_s11d28 diagnostic-macro-leftover:$(cat /tmp/rd_verify_r_s11d28_macro.$$)"
fi
rm -f /tmp/rd_verify_r_s11d28_macro.$$
if grep -nE 'pub fn message_box|NO_DIALOG|PRINT_OUT|WRITE_TO_FILE|RustDesk Output|Above text has been copied to clipboard' src/platform/windows.rs >/tmp/rd_verify_r_s11d28_msgbox.$$; then
  r_s11d28="$r_s11d28 windows-message-box-diagnostic-leftover:$(cat /tmp/rd_verify_r_s11d28_msgbox.$$)"
fi
rm -f /tmp/rd_verify_r_s11d28_msgbox.$$
grep -Fq 'Windows dormant diagnostic message-box deletion' requirements.html || r_s11d28="$r_s11d28 requirements-disposition-missing"
grep -Fq 'R-S11d-28 — Windows dormant diagnostic message-box deletion' HARDENING_STATUS.md || r_s11d28="$r_s11d28 hardening-ledger-missing"
if [ -n "$r_s11d28" ]; then echo "  FAIL R-S11d-28 Windows dormant diagnostic message-box deletion:$r_s11d28"; rc=1; else
  echo "  ok  R-S11d-28 dormant Windows diagnostic message-box/file/clipboard side effects are absent"; fi

echo "== (3b-iii-a6c) Windows service-adjacent profile and recording paths use known folders (R-S11d-29) =="
r_s11d29=
if grep -RInF 'SystemDrive' src/platform/windows.rs src/ui_interface.rs >/tmp/rd_verify_r_s11d29_systemdrive.$$; then
  r_s11d29="$r_s11d29 systemdrive-path-authority-leftover:$(cat /tmp/rd_verify_r_s11d29_systemdrive.$$)"
fi
rm -f /tmp/rd_verify_r_s11d29_systemdrive.$$
grep -Fq 'FOLDERID_UserProfiles' src/platform/windows.rs || r_s11d29="$r_s11d29 userprofiles-known-folder-missing"
grep -Fq 'FOLDERID_Windows' src/platform/windows.rs || r_s11d29="$r_s11d29 windows-known-folder-missing"
grep -Fq 'fn user_profiles_dir() -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d29="$r_s11d29 userprofiles-helper-missing"
grep -Fq 'fn windows_dir() -> ResultType<PathBuf>' src/platform/windows.rs || r_s11d29="$r_s11d29 windows-dir-helper-missing"
grep -Fq "username.contains(['\\\\', '/', ':'])" src/platform/windows.rs || r_s11d29="$r_s11d29 username-component-guard-missing"
grep -Fq 'username.bytes().any(|byte| byte < 0x20)' src/platform/windows.rs || r_s11d29="$r_s11d29 username-control-guard-missing"
grep -Fq 'let home = user_profiles_dir().ok()?.join(username);' src/platform/windows.rs || r_s11d29="$r_s11d29 active-user-home-not-userprofiles-backed"
grep -Fq 'let windows_temp = windows_dir()?.join("Temp");' src/platform/windows.rs || r_s11d29="$r_s11d29 user-accessible-windows-temp-not-known-folder-backed"
grep -Fq 'return match crate::platform::windows::program_data_dir()' src/ui_interface.rs || r_s11d29="$r_s11d29 root-recording-not-programdata-known-folder-backed"
grep -Fq 'Failed to resolve ProgramData recording directory' src/ui_interface.rs || r_s11d29="$r_s11d29 root-recording-failure-not-logged"
grep -Fq 'Windows service-adjacent path known-folder authority' requirements.html || r_s11d29="$r_s11d29 requirements-disposition-missing"
grep -Fq 'R-S11d-29 — Windows service-adjacent path known-folder authority' HARDENING_STATUS.md || r_s11d29="$r_s11d29 hardening-ledger-missing"
if [ -n "$r_s11d29" ]; then echo "  FAIL R-S11d-29 Windows service-adjacent path known-folder authority:$r_s11d29"; rc=1; else
  echo "  ok  R-S11d-29 Windows service-adjacent profile/recording/installer fallback paths use known folders, not SystemDrive"; fi

# (3b-iii-b) R-S11b-1/R-S11b-2c/R-S11c-1f: Linux/macOS `_service` is a privileged service-control channel,
# not a root<->user Config/Config2 bus. The world-connectable service socket may keep only narrow,
# typed receiver-authorized traffic; it MUST NOT accept/return whole config, and stale-socket probing
# must not read config.
echo "== (3b-iii-b) IPC _service has no whole-config bus (R-S11b-1) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::test::service_channel_rejects_config_bus --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config ipc::test::macos_service_owned_launch_agent_plist_validation --color never
r_s11b=
grep -q 'pub(crate) fn service_channel_admits_message' src/ipc.rs || r_s11b="$r_s11b no-service-message-gate"
grep -q 'Data::Test => true' src/ipc.rs || r_s11b="$r_s11b service-gate-misses-test"
grep -q 'Data::RequestServiceOwnedUnattendedPasswordChange(_) => true' src/ipc.rs || r_s11b="$r_s11b linux-service-password-request-not-typed"
service_message_gate=$(awk '/pub\(crate\) fn service_channel_admits_message/,/^}/' src/ipc.rs)
echo "$service_message_gate" | grep -q 'Data::BeginMacosServiceOwnedUnattendedPasswordChange' || r_s11b="$r_s11b macos-service-password-begin-not-typed"
echo "$service_message_gate" | grep -q 'Data::FinishMacosServiceOwnedUnattendedPasswordChange { .. }' || r_s11b="$r_s11b macos-service-password-finish-not-typed"
echo "$service_message_gate" | grep -q 'Data::MacosServiceOwnedPermanentPasswordSnapshotRequest' || r_s11b="$r_s11b macos-service-password-runtime-snapshot-not-typed"
service_dispatch_block=$(awk '/service_channel_admits_message\(&data\)/,/continue;/' src/ipc.rs)
echo "$service_dispatch_block" | grep -q 'service_channel_admits_message(&data)' || r_s11b="$r_s11b service-loop-not-wired"
if echo "$service_dispatch_block" | grep -q 'Data::SyncConfig'; then
  r_s11b="$r_s11b service-loop-still-admits-syncconfig"
fi
if grep -q 'SyncConfig' src/ipc.rs; then
  r_s11b="$r_s11b whole-config-ipc-variant-present"
fi
if awk '/^async fn handle\(/,/^}/' src/ipc.rs | grep -qE 'Data::SyncConfig\(Some\([^)]*\)\)[[:space:]]*=>'; then
  r_s11b="$r_s11b whole-config-write-handler-present"
fi
if grep -q 'SyncConfig' src/server.rs; then
  r_s11b="$r_s11b server-whole-config-import-present"
fi
if awk '/probe_existing_listener/,/^}/' src/ipc/fs.rs | grep -q 'Data::SyncConfig'; then
  r_s11b="$r_s11b service-probe-reads-config"
fi
grep -q 'stream.send(&Data::Test)' src/ipc/fs.rs                                   || r_s11b="$r_s11b service-probe-not-test-ping"
if grep -q 'connect_service' src/server.rs; then
  r_s11b="$r_s11b server-still-connects-service-channel"
fi
if grep -qE 'wait_initial_config_sync|sync_and_watch_config_dir|CONFIG_SYNC_(INTERVAL|INITIAL)' src/server.rs; then
  r_s11b="$r_s11b service-config-sync-loop-present"
fi
if [ -n "$r_s11b" ]; then echo "  FAIL R-S11b-1 _service whole-config bus removal:$r_s11b"; rc=1; else
  echo "  ok  R-S11b-1/R-S11b-2c/R-S11c-1f _service admits liveness plus typed Linux service-owned password requests and macOS begin/finish/runtime-snapshot service-owned password requests; stale-socket probe uses Test; root/user whole-config sync loop, SyncConfig IPC variant, and whole-config import are absent"; fi

# (3b-iii-c) R-S11b-2a/R-S11b-2c/R-S11c-1a: service-owned unattended passwords are not ordinary config IPC.
# Service launch paths mark their --server child; the receiver uses that marker to deny
# generic config credential writes, typed user-owned password writes, whole-config snapshots, and every
# password storage/salt sync over main IPC. Linux installed-service password changes use a typed `_service`
# request authorized by polkit, then a root-service commit into the service-owned main server. Windows
# installed-service password changes use the same typed request/commit split, but the `_service` receiver
# proves an elevated RustDesk caller by named-pipe client-token impersonation and the main server accepts the
# final commit only from a LocalSystem service peer. macOS installed-service password changes use a typed
# begin/challenge/finish `_service` exchange: the LaunchDaemon stores the proposed password in a one-shot
# same-peer request, enforces a nonshared timeout-zero RustDesk Authorization Services right, verifies the
# external form without interaction, and stores only the authorized pending value in the root LaunchDaemon
# credential store. The service-owned LaunchAgent receives a runtime-only root-credential snapshot only when
# launchd reports the requesting pid as the expected root-installed LaunchAgent job. The user-owned path remains user-owned, and --password
# dispatches to the owner-aware typed operation.
echo "== (3b-iii-c) service-owned permanent password rejects ordinary IPC (R-S11b-2a/R-S11c-1a) =="
r_s11b2=
grep -q 'SERVICE_OWNED_SERVER_ARG' src/common.rs                                      || r_s11b2="$r_s11b2 no-service-owned-arg"
linux_service_start=$(awk '/fn try_start_server_/,/^}/' src/platform/linux.rs)
echo "$linux_service_start" | grep -Fq 'vec!["--server", crate::common::SERVICE_OWNED_SERVER_ARG]' || r_s11b2="$r_s11b2 linux-active-user-service-server-not-marked"
echo "$linux_service_start" | grep -A4 'crate::run_me(vec!\[' | grep -q 'SERVICE_OWNED_SERVER_ARG' || r_s11b2="$r_s11b2 linux-root-service-server-not-marked"
windows_launch_server=$(awk '/async fn launch_server/,/^}/' src/platform/windows.rs)
echo "$windows_launch_server" | grep -q 'SERVICE_OWNED_SERVER_ARG'                    || r_s11b2="$r_s11b2 windows-service-server-not-marked"
grep -q -- '<string>--service-owned-server</string>' src/platform/privileges_scripts/agent.plist || r_s11b2="$r_s11b2 macos-agent-server-not-marked"
grep -q 'MainIpcAuthority::ServiceOwned' src/ipc.rs                                  || r_s11b2="$r_s11b2 service-owned-authority-missing"
grep -q 'Data::SetUserOwnedPermanentPassword(_) => {' src/ipc.rs                    || r_s11b2="$r_s11b2 typed-password-arm-missing"
grep -A3 'Data::SetUserOwnedPermanentPassword(_) => {' src/ipc.rs | grep -q 'authority.allows_main_channel_user_owned_password_write()' || r_s11b2="$r_s11b2 typed-password-write-not-authority-gated"
grep -q 'Data::SetUserOwnedPermanentPasswordResult(false)' src/ipc.rs                || r_s11b2="$r_s11b2 typed-password-reject-nack-missing"
grep -q 'RequestServiceOwnedUnattendedPasswordChange(String)' src/ipc.rs             || r_s11b2="$r_s11b2 service-password-request-missing"
grep -q 'BeginMacosServiceOwnedUnattendedPasswordChange' src/ipc.rs                 || r_s11b2="$r_s11b2 macos-service-password-begin-missing"
grep -q 'MacosServiceOwnedUnattendedPasswordChallenge {' src/ipc.rs                 || r_s11b2="$r_s11b2 macos-service-password-challenge-missing"
grep -q 'FinishMacosServiceOwnedUnattendedPasswordChange {' src/ipc.rs              || r_s11b2="$r_s11b2 macos-service-password-finish-missing"
grep -q 'MacosServiceOwnedPermanentPasswordSnapshotRequest' src/ipc.rs              || r_s11b2="$r_s11b2 macos-service-password-snapshot-request-missing"
grep -q 'MacosServiceOwnedPermanentPasswordSnapshot {' src/ipc.rs                   || r_s11b2="$r_s11b2 macos-service-password-snapshot-response-missing"
grep -q 'CommitServiceOwnedUnattendedPasswordChange(String)' src/ipc.rs              || r_s11b2="$r_s11b2 service-password-commit-missing"
grep -q 'ServiceOwnedUnattendedPasswordChangeResult(bool)' src/ipc.rs                || r_s11b2="$r_s11b2 service-password-result-missing"
grep -q 'Data::RequestServiceOwnedUnattendedPasswordChange(_) => false' src/ipc.rs   || r_s11b2="$r_s11b2 service-password-request-not-denied-on-main"
main_channel_mutation_policy=$(awk '/pub\(crate\) fn main_channel_admits_state_mutation/,/^}/' src/ipc.rs)
echo "$main_channel_mutation_policy" | grep -q 'Data::BeginMacosServiceOwnedUnattendedPasswordChange' || r_s11b2="$r_s11b2 macos-service-password-begin-not-denied-on-main"
echo "$main_channel_mutation_policy" | grep -q 'Data::MacosServiceOwnedUnattendedPasswordChallenge { .. }' || r_s11b2="$r_s11b2 macos-service-password-challenge-not-denied-on-main"
echo "$main_channel_mutation_policy" | grep -q 'Data::FinishMacosServiceOwnedUnattendedPasswordChange { .. }' || r_s11b2="$r_s11b2 macos-service-password-finish-not-denied-on-main"
echo "$main_channel_mutation_policy" | grep -q 'Data::MacosServiceOwnedPermanentPasswordSnapshotRequest => false' || r_s11b2="$r_s11b2 macos-service-password-snapshot-not-denied-on-main"
echo "$main_channel_mutation_policy" | grep -q 'Data::CommitServiceOwnedUnattendedPasswordChange(_) => false' || r_s11b2="$r_s11b2 macos-service-password-commit-not-denied-on-main"
grep -A5 'Data::CommitServiceOwnedUnattendedPasswordChange(_) => {' src/ipc.rs | grep -q 'peer_authority.allows_service_owned_unattended_password_commit()' || r_s11b2="$r_s11b2 service-password-commit-not-root-peer-gated"
grep -q 'current_process_allows_service_owned_unattended_password_commit' src/ipc.rs || r_s11b2="$r_s11b2 service-password-handler-commit-gate-missing"
grep -q 'linux_peer_is_authorized_for_service_owned_password_change' src/ipc.rs      || r_s11b2="$r_s11b2 linux-polkit-authorizer-missing"
grep -q '/usr/bin/pkcheck' src/ipc.rs                                                || r_s11b2="$r_s11b2 linux-pkcheck-missing"
grep -q -- '.arg("--process")' src/ipc.rs                                            || r_s11b2="$r_s11b2 linux-pkcheck-process-subject-missing"
grep -q -- '.arg("--allow-user-interaction")' src/ipc.rs                             || r_s11b2="$r_s11b2 linux-pkcheck-interaction-missing"
grep -q 'rsplit_once(") ")' src/ipc/auth.rs                                          || r_s11b2="$r_s11b2 linux-proc-stat-safe-parse-missing"
grep -q 'peer_pid()' src/ipc.rs                                                      || r_s11b2="$r_s11b2 linux-peer-pid-missing"
grep -q 'peer_uid()' src/ipc.rs                                                      || r_s11b2="$r_s11b2 linux-peer-uid-missing"
grep -q 'UserMainIpcScope::new()' src/ipc.rs                                         || r_s11b2="$r_s11b2 linux-service-commit-not-main-server-scoped"
if ! python3 scripts/verify-polkit-policy.py --repo . >/tmp/rd_verify_polkit_policy.$$ 2>&1; then
  cat /tmp/rd_verify_polkit_policy.$$
  r_s11b2="$r_s11b2 linux-polkit-policy-package-assurance-failed"
fi
rm -f /tmp/rd_verify_polkit_policy.$$
grep -Fq 'R-S11e — Linux polkit policy/package assurance' HARDENING_STATUS.md        || r_s11b2="$r_s11b2 linux-polkit-assurance-ledger-missing"
grep -Fq 'Linux polkit policy/package assurance' requirements.html                   || r_s11b2="$r_s11b2 linux-polkit-assurance-requirements-missing"
grep -q 'windows_peer_is_authorized_for_service_owned_password_change' src/ipc.rs    || r_s11b2="$r_s11b2 windows-service-password-authorizer-missing"
grep -q 'windows_pipe_client_token_is_elevated' src/ipc/auth.rs                     || r_s11b2="$r_s11b2 windows-service-password-token-elevation-missing"
grep -q 'windows_pipe_client_token_is_local_system' src/ipc/auth.rs                  || r_s11b2="$r_s11b2 windows-service-password-localsystem-token-missing"
grep -q 'ImpersonateNamedPipeClient' src/ipc/auth.rs                                || r_s11b2="$r_s11b2 windows-service-password-not-client-token-impersonated"
grep -q 'RevertToSelf' src/ipc/auth.rs                                               || r_s11b2="$r_s11b2 windows-service-password-impersonation-not-reverted"
grep -q 'Self::WindowsLocalSystemPeer => true' src/ipc.rs                            || r_s11b2="$r_s11b2 windows-service-password-commit-not-localsystem-gated"
grep -q 'handle_windows_service_owned_unattended_password_request' src/platform/windows.rs || r_s11b2="$r_s11b2 windows-service-password-service-loop-not-wired"
grep -q 'RequestServiceOwnedUnattendedPasswordChange(value)' src/platform/windows.rs || r_s11b2="$r_s11b2 windows-service-password-request-not-dispatched"
grep -q 'crate::platform::is_elevated(None).unwrap_or(false)' src/ipc.rs             || r_s11b2="$r_s11b2 windows-service-password-ui-not-elevation-gated"
grep -q 'MACOS_SERVICE_OWNED_PASSWORD_PENDING' src/ipc.rs                           || r_s11b2="$r_s11b2 macos-service-password-pending-map-missing"
grep -q 'MACOS_SERVICE_OWNED_PASSWORD_MAX_PENDING' src/ipc.rs                       || r_s11b2="$r_s11b2 macos-service-password-pending-cap-missing"
grep -q 'macos_store_service_owned_password_request' src/ipc.rs                     || r_s11b2="$r_s11b2 macos-service-password-begin-store-missing"
grep -q 'macos_take_service_owned_password_request' src/ipc.rs                      || r_s11b2="$r_s11b2 macos-service-password-finish-consume-missing"
grep -q 'peer_pid()' src/ipc.rs                                                     || r_s11b2="$r_s11b2 macos-service-password-peer-pid-missing"
grep -q 'peer_uid()' src/ipc.rs                                                     || r_s11b2="$r_s11b2 macos-service-password-peer-uid-missing"
grep -q 'BeginMacosServiceOwnedUnattendedPasswordChange(String)' src/ipc.rs        || r_s11b2="$r_s11b2 macos-service-password-begin-does-not-carry-value"
grep -q 'password: Option<String>' src/ipc.rs                                      || r_s11b2="$r_s11b2 macos-service-password-pending-value-missing"
grep -q 'fn take_password(&mut self) -> ResultType<String>' src/ipc.rs             || r_s11b2="$r_s11b2 macos-service-password-pending-value-not-take-only"
grep -q 'impl Drop for MacosServiceOwnedPasswordRequest' src/ipc.rs                || r_s11b2="$r_s11b2 macos-service-password-pending-value-not-zeroed"
grep -q 'MACOS_SERVICE_OWNED_PASSWORD_MAX_BYTES' src/ipc.rs                        || r_s11b2="$r_s11b2 macos-service-password-value-cap-missing"
grep -q 'password.len() > MACOS_SERVICE_OWNED_PASSWORD_MAX_BYTES' src/ipc.rs       || r_s11b2="$r_s11b2 macos-service-password-value-cap-not-enforced"
grep -q 'fn macos_schedule_service_owned_password_request_expiry' src/ipc.rs       || r_s11b2="$r_s11b2 macos-service-password-expiry-task-missing"
grep -q 'macos_schedule_service_owned_password_request_expiry(request_id.clone())' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-expiry-task-not-armed"
grep -q 'tokio::time::sleep(MACOS_SERVICE_OWNED_PASSWORD_REQUEST_TTL).await' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-expiry-task-not-timed"
grep -q 'macos_store_service_owned_password_request(stream, password)' src/ipc.rs  || r_s11b2="$r_s11b2 macos-service-password-begin-not-storing-value"
grep -q 'Config::set_permanent_password(&password)' src/ipc.rs                    || r_s11b2="$r_s11b2 macos-service-password-finish-not-writing-root-store"
if grep -q 'commit_service_owned_unattended_password_change(password).await' src/ipc.rs; then
  r_s11b2="$r_s11b2 macos-service-password-stale-main-server-commit"
fi
if grep -q 'get_preset_password_storage_and_salt' src/ipc.rs; then
  r_s11b2="$r_s11b2 macos-service-password-snapshot-preset-fallback"
fi
grep -q 'handle_macos_service_owned_permanent_password_snapshot_request' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-handler-missing"
grep -q 'macos_peer_is_service_owned_server' src/ipc.rs                            || r_s11b2="$r_s11b2 macos-service-password-snapshot-peer-shape-missing"
grep -q 'macos_launch_agent_owns_service_owned_server_pid' src/ipc.rs              || r_s11b2="$r_s11b2 macos-service-password-snapshot-launchd-pid-proof-missing"
macos_snapshot_peer_block=$(awk '/async fn macos_peer_is_service_owned_server/,/fn macos_service_owned_server_launch_agent_label/' src/ipc.rs)
macos_launch_agent_proof_block=$(awk '/fn macos_launch_agent_owns_service_owned_server_pid/,/async fn handle_macos_service_owned_permanent_password_snapshot_request/' src/ipc.rs)
macos_plist_parser_block=$(awk '/fn macos_service_owned_server_launch_agent_plist_value_is_expected/,/fn macos_service_owned_server_launch_agent_plist_content_is_expected/' src/ipc.rs)
macos_plist_content_block=$(awk '/fn macos_service_owned_server_launch_agent_plist_content_is_expected/,/fn macos_launchctl_print_value/' src/ipc.rs)
macos_snapshot_handler_block=$(awk '/async fn handle_macos_service_owned_permanent_password_snapshot_request/,/async fn permanent_password_is_set_for_current_process/' src/ipc.rs)
grep -q 'MACOS_LAUNCHCTL: &str = "/bin/launchctl"' src/ipc.rs                      || r_s11b2="$r_s11b2 macos-service-password-snapshot-launchctl-fixed-path-missing"
echo "$macos_launch_agent_proof_block" | grep -q 'format!("gui/{peer_uid}/{label}")' || r_s11b2="$r_s11b2 macos-service-password-snapshot-launchd-domain-missing"
echo "$macos_launch_agent_proof_block" | grep -q 'reported_pid != Some(peer_pid)' || r_s11b2="$r_s11b2 macos-service-password-snapshot-launchd-pid-compare-missing"
echo "$macos_launch_agent_proof_block" | grep -q 'reported_path != Some(expected_plist.as_str())' || r_s11b2="$r_s11b2 macos-service-password-snapshot-launchd-path-compare-missing"
echo "$macos_launch_agent_proof_block" | grep -q 'macos_service_owned_server_launch_agent_plist_is_trusted' || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-trust-missing"
grep -q 'macos_service_owned_server_launch_agent_plist_is_trusted' src/ipc.rs      || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-trust-function-missing"
echo "$macos_launch_agent_proof_block" | grep -q 'macos_service_owned_server_launch_agent_plist_content_is_expected' || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-content-proof-not-wired"
grep -q 'macos_root_wheel_path_is_trusted(parent, MacosTrustedPathKind::Directory)' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-parent-trust-missing"
grep -q 'std::fs::symlink_metadata(path)' src/ipc.rs                               || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-symlink-gate-missing"
grep -q 'metadata.uid() == 0' src/ipc.rs                                           || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-root-missing"
grep -q 'metadata.gid() == 0' src/ipc.rs                                           || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-wheel-missing"
grep -q 'metadata.permissions().mode() & 0o022 == 0' src/ipc.rs                    || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-mode-missing"
grep -q 'macos_path_has_no_extended_acl' src/ipc.rs                                || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-acl-missing"
echo "$macos_snapshot_peer_block" | grep -q 'tokio::task::spawn_blocking'          || r_s11b2="$r_s11b2 macos-service-password-snapshot-proof-not-spawn-blocking"
echo "$macos_snapshot_peer_block" | grep -q 'macos_peer_is_service_owned_server_blocking(peer_uid, peer_pid)' || r_s11b2="$r_s11b2 macos-service-password-snapshot-proof-blocking-target-missing"
echo "$macos_snapshot_peer_block" | grep -q 'process.cmd().get(1)'                 || r_s11b2="$r_s11b2 macos-service-password-snapshot-peer-server-argv-missing"
echo "$macos_snapshot_peer_block" | grep -q 'get(2)'                               || r_s11b2="$r_s11b2 macos-service-password-snapshot-peer-service-owned-argv-missing"
grep -q 'macos_service_owned_server_launch_agent_executable' src/ipc.rs            || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-exec-proof-missing"
grep -q 'macos_service_owned_server_launch_agent_plist_content_is_expected' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-content-proof-missing"
grep -q 'macos_service_owned_server_launch_agent_plist_value_is_expected' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-parser-missing"
echo "$macos_plist_content_block" | grep -q 'plist::Value::from_file'             || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-not-parsed"
echo "$macos_plist_parser_block" | grep -q 'ProgramArguments'                     || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-programargs-missing"
echo "$macos_plist_parser_block" | grep -q 'RunAtLoad'                            || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-runatload-missing"
echo "$macos_plist_parser_block" | grep -q 'SuccessfulExit'                       || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-keepalive-successful-exit-missing"
echo "$macos_plist_parser_block" | grep -q 'AfterInitialDemand'                   || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-keepalive-initial-demand-missing"
echo "$macos_plist_parser_block" | grep -q 'keep_alive.len() != 2'                || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-keepalive-exact-shape-missing"
grep -q 'macos_service_owned_launch_agent_plist_validation_rejects_missing_service_arg' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-validation-test-missing"
grep -q 'macos_service_owned_launch_agent_plist_validation_rejects_run_at_load_false' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-runatload-test-missing"
grep -q 'macos_service_owned_launch_agent_plist_validation_rejects_missing_keep_alive' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-keepalive-test-missing"
grep -q 'macos_service_owned_launch_agent_plist_validation_rejects_extra_keep_alive_key' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-snapshot-plist-keepalive-exact-test-missing"
echo "$macos_snapshot_handler_block" | grep -q 'if storage.is_empty()'             || r_s11b2="$r_s11b2 macos-service-password-empty-snapshot-storage-gate-missing"
echo "$macos_snapshot_handler_block" | grep -q '(String::new(), String::new())'    || r_s11b2="$r_s11b2 macos-service-password-empty-snapshot-not-cleared"
grep -q 'refresh_macos_service_owned_permanent_password_snapshot' src/ipc.rs        || r_s11b2="$r_s11b2 macos-service-password-snapshot-client-missing"
grep -q 'Config::set_permanent_password_storage_for_runtime(&storage, &salt)' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-runtime-apply-missing"
grep -q 'RUNTIME_PERMANENT_PASSWORD_PRS' libs/hbb_common/src/config.rs             || r_s11b2="$r_s11b2 macos-service-password-runtime-overlay-missing"
grep -q 'runtime_password_snapshot_does_not_persist' libs/hbb_common/src/config.rs || r_s11b2="$r_s11b2 macos-service-password-runtime-nonpersist-test-missing"
grep -q 'test_set_permanent_password_persists_when_value_matches_preset' libs/hbb_common/src/config.rs || r_s11b2="$r_s11b2 explicit-password-set-preset-noop-test-missing"
grep -q 'effective_permanent_password_prs' src/direct_service.rs                   || r_s11b2="$r_s11b2 macos-service-password-listener-not-effective-prs"
grep -q 'let prs = effective_permanent_password_prs().await' src/server.rs         || r_s11b2="$r_s11b2 macos-service-password-cpace-not-effective-prs"
grep -q 'service_owned_unattended_password_authorization()' src/ipc.rs             || r_s11b2="$r_s11b2 macos-service-password-ui-auth-not-action-only"
grep -q 'authorization: Vec::new()' src/ipc.rs                                     || r_s11b2="$r_s11b2 macos-service-password-ui-auth-failure-not-cancelled"
macos_finish_variant=$(awk '/FinishMacosServiceOwnedUnattendedPasswordChange \{/,/^    \},/' src/ipc.rs)
if echo "$macos_finish_variant" | grep -q 'password:'; then
  r_s11b2="$r_s11b2 macos-service-password-finish-still-carries-value"
fi
if grep -qE 'macos_service_owned_unattended_password_digest|MACOS_SERVICE_OWNED_PASSWORD_REQUEST_CONTEXT|password_digest' src/ipc.rs; then
  r_s11b2="$r_s11b2 macos-service-password-stale-digest-binding"
fi
grep -q 'macos_service_owned_password_authorization_right_is_ready' src/ipc.rs      || r_s11b2="$r_s11b2 macos-service-password-right-readiness-gate-missing"
grep -q 'MacEnsureServiceOwnedUnattendedPasswordAuthorizationRight' src/platform/macos.mm || r_s11b2="$r_s11b2 macos-service-password-right-setup-missing"
grep -q 'AuthorizationRightSet(NULL' src/platform/macos.mm                         || r_s11b2="$r_s11b2 macos-service-password-right-set-missing"
grep -q 'AuthorizationRightGet(RustDeskSetUnattendedPasswordRight()' src/platform/macos.mm || r_s11b2="$r_s11b2 macos-service-password-right-existence-check-missing"
grep -q 'CFSTR("shared")' src/platform/macos.mm                                    || r_s11b2="$r_s11b2 macos-service-password-right-shared-key-missing"
grep -q 'kCFBooleanFalse' src/platform/macos.mm                                    || r_s11b2="$r_s11b2 macos-service-password-right-not-nonshared"
grep -q 'CFSTR("timeout")' src/platform/macos.mm                                   || r_s11b2="$r_s11b2 macos-service-password-right-timeout-key-missing"
grep -q 'const int32_t timeout = 0' src/platform/macos.mm                          || r_s11b2="$r_s11b2 macos-service-password-right-timeout-not-zero"
grep -q 'CFSTR("group")' src/platform/macos.mm                                     || r_s11b2="$r_s11b2 macos-service-password-right-group-key-missing"
grep -q 'CFSTR("admin")' src/platform/macos.mm                                     || r_s11b2="$r_s11b2 macos-service-password-right-admin-group-missing"
grep -q 'MacCreateServiceOwnedUnattendedPasswordAuthorizationExternalForm' src/platform/macos.mm || r_s11b2="$r_s11b2 macos-service-password-auth-create-missing"
grep -q 'AuthorizationMakeExternalForm' src/platform/macos.mm                        || r_s11b2="$r_s11b2 macos-service-password-externalize-missing"
grep -q 'MacVerifyServiceOwnedUnattendedPasswordAuthorizationExternalForm' src/platform/macos.mm || r_s11b2="$r_s11b2 macos-service-password-auth-verify-missing"
grep -q 'AuthorizationCreateFromExternalForm' src/platform/macos.mm                  || r_s11b2="$r_s11b2 macos-service-password-internalize-missing"
grep -q 'kAuthorizationFlagDefaults, NULL' src/platform/macos.mm                     || r_s11b2="$r_s11b2 macos-service-password-daemon-verification-may-interact"
grep -q 'RustDeskSetUnattendedPasswordRight' src/platform/macos.mm                  || r_s11b2="$r_s11b2 macos-service-password-custom-right-missing"
grep -q 'com.carriez.RustDesk.set-unattended-password' src/platform/macos.mm        || r_s11b2="$r_s11b2 macos-service-password-right-name-missing"
if grep -qE 'RequestDigestIsValid|kAuthorizationEnvironmentPrompt|MacCreateAdminAuthorizationExternalFormForRequest|MacVerifyAdminAuthorizationExternalFormForRequest' src/platform/macos.mm; then
  r_s11b2="$r_s11b2 macos-service-password-stale-digest-native-auth"
fi
if grep -q 'request_digest' src/platform/macos.rs; then
  r_s11b2="$r_s11b2 macos-service-password-rust-api-still-digest-bound"
fi
grep -q 'ensure_service_owned_unattended_password_authorization_right' src/platform/macos.rs || r_s11b2="$r_s11b2 macos-service-password-rust-right-setup-missing"
grep -q 'MacCreateServiceOwnedUnattendedPasswordAuthorizationExternalForm' src/platform/macos.rs || r_s11b2="$r_s11b2 macos-service-password-rust-auth-create-missing"
grep -q 'MacVerifyServiceOwnedUnattendedPasswordAuthorizationExternalForm' src/platform/macos.rs || r_s11b2="$r_s11b2 macos-service-password-rust-auth-verify-missing"
grep -q 'handle_macos_service_owned_unattended_password_begin' src/ipc.rs           || r_s11b2="$r_s11b2 macos-service-password-begin-handler-missing"
grep -q 'handle_macos_service_owned_unattended_password_finish' src/ipc.rs          || r_s11b2="$r_s11b2 macos-service-password-finish-handler-missing"
grep -q 'crate::platform::is_installed() && crate::platform::is_installed_daemon(false)' src/ipc.rs || r_s11b2="$r_s11b2 macos-service-password-install-state-gate-missing"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_EXEC: &str =' src/ipc/auth.rs              || r_s11b2="$r_s11b2 macos-service-ipc-helper-const-missing"
grep -Fq '/Library/PrivilegedHelperTools/com.carriez.rustdesk_service' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-helper-path-missing"
grep -Fq 'fn macos_installed_app_executable_path() -> PathBuf' src/ipc/auth.rs      || r_s11b2="$r_s11b2 macos-service-ipc-installed-app-path-missing"
grep -Fq 'fn macos_privileged_helper_is_expected_and_trusted(current_exe: &Path) -> bool' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-helper-trust-missing"
grep -Fq 'fn macos_installed_app_is_expected_and_trusted(peer_exe: &Path) -> bool' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-app-trust-missing"
grep -Fq 'fs::symlink_metadata(path)' src/ipc/auth.rs                            || r_s11b2="$r_s11b2 macos-service-ipc-symlink-metadata-missing"
grep -Fq 'metadata.file_type().is_symlink()' src/ipc/auth.rs                     || r_s11b2="$r_s11b2 macos-service-ipc-symlink-gate-missing"
grep -Fq 'macos_root_wheel_not_group_world_writable(&metadata)' src/ipc/auth.rs  || r_s11b2="$r_s11b2 macos-service-ipc-helper-root-wheel-mode-missing"
grep -Fq 'macos_root_owned_not_group_world_writable(&metadata)' src/ipc/auth.rs  || r_s11b2="$r_s11b2 macos-service-ipc-app-root-owned-mode-missing"
grep -Fq 'fn macos_path_has_no_extended_acl(path: &Path) -> bool' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-runtime-acl-check-missing"
grep -Fq 'acl_get_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED)' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-runtime-acl-not-native"
grep -Fq 'acl_valid_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED, acl)' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-runtime-acl-not-validated"
grep -Fq 'acl_get_entry(acl, MACOS_ACL_FIRST_ENTRY, &mut entry)' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-runtime-acl-entry-check-missing"
grep -Fq 'MacosAclGuard' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-runtime-acl-free-guard-missing"
if grep -Fq 'Command::new(MACOS_LS)' src/ipc/auth.rs \
  || grep -Fq 'const MACOS_LS' src/ipc/auth.rs \
  || grep -Fq 'Command::new("/bin/ls")' src/platform/macos.rs src/ipc.rs src/ipc/auth.rs \
  || grep -Fq 'Command::new("ls")' src/platform/macos.rs src/ipc.rs src/ipc/auth.rs; then
  r_s11b2="$r_s11b2 macos-service-ipc-runtime-acl-ls-parser-present"
fi
grep -Fq 'macos_privileged_helper_satisfies_code_requirement(expected)' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-helper-code-requirement-missing"
grep -Fq 'macos_installed_app_satisfies_code_requirement(&app_bundle)' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-app-code-requirement-missing"
grep -Fq 'macos_service_ipc_allows_installed_app_and_privileged_helper' src/ipc/auth.rs || r_s11b2="$r_s11b2 macos-service-ipc-installed-helper-pair-missing"
macos_service_identity_block=$(awk '/fn macos_service_ipc_allows_installed_app_and_privileged_helper/,/^}/' src/ipc/auth.rs)
echo "$macos_service_identity_block" | grep -Fq 'postfix != crate::POSTFIX_SERVICE' || r_s11b2="$r_s11b2 macos-service-ipc-postfix-gate-missing"
echo "$macos_service_identity_block" | grep -Fq 'macos_privileged_helper_is_expected_and_trusted(current_exe)' || r_s11b2="$r_s11b2 macos-service-ipc-current-helper-not-verified"
echo "$macos_service_identity_block" | grep -Fq 'macos_installed_app_is_expected_and_trusted(peer_exe)' || r_s11b2="$r_s11b2 macos-service-ipc-peer-app-not-verified"
if grep -q 'macos_service_ipc_allows_gui_and_service_binaries' src/ipc/auth.rs; then
  r_s11b2="$r_s11b2 macos-service-ipc-old-gui-service-binary-model-present"
fi
if echo "$macos_service_identity_block" | grep -qE 'peer_dir|current_dir|OsStr::new\("service"\)|executable_paths_match\(peer_dir, current_dir\)'; then
  r_s11b2="$r_s11b2 macos-service-ipc-old-same-directory-model-present"
fi
grep -q 'Self::RootUnixPeer => true' src/ipc.rs                                      || r_s11b2="$r_s11b2 unix-service-password-commit-not-root-gated"
macos_auth_create_block=$(awk '/MacCreateServiceOwnedUnattendedPasswordAuthorizationExternalForm/,/^}/' src/platform/macos.mm)
macos_auth_verify_block=$(awk '/MacVerifyServiceOwnedUnattendedPasswordAuthorizationExternalForm/,/^}/' src/platform/macos.mm)
if echo "$macos_auth_create_block$macos_auth_verify_block" | grep -q 'kAuthorizationRightExecute'; then
  r_s11b2="$r_s11b2 macos-service-password-uses-generic-execute-right"
fi
if echo "$macos_auth_verify_block" | grep -q 'kAuthorizationFlagInteractionAllowed'; then
  r_s11b2="$r_s11b2 macos-service-password-daemon-verification-can-interact"
fi
if grep -q 'RequestMacosServiceOwnedUnattendedPasswordChange' src/ipc.rs; then
  r_s11b2="$r_s11b2 macos-service-password-old-single-message-request-present"
fi
if grep -qE 'extern "C" bool MacCreateAdminAuthorizationExternalForm\(|extern "C" bool MacVerifyAdminAuthorizationExternalForm\(' src/platform/macos.mm; then
  r_s11b2="$r_s11b2 macos-service-password-old-auth-present"
fi
windows_password_authorizer=$(awk '/fn windows_peer_is_authorized_for_service_owned_password_change/,/^}/' src/ipc.rs)
if echo "$windows_password_authorizer" | grep -q 'is_elevated(Some'; then
  r_s11b2="$r_s11b2 windows-service-password-authorizer-uses-pid-elevation"
fi
grep -q '"permanent-password" => authority.allows_main_channel_user_owned_password_write()' src/ipc.rs && r_s11b2="$r_s11b2 password-still-generic-config-key"
grep -q '"permanent-password" => authority.allows_main_channel_password_write()' src/ipc.rs && r_s11b2="$r_s11b2 password-still-generic-config-key"
grep -q 'Data::Config((' src/ipc.rs && r_s11b2="$r_s11b2 generic-config-write-shape-present"
grep -q 'send_config(' src/ipc.rs && r_s11b2="$r_s11b2 generic-send-config-present"
ipc_main_authority=$(awk '/impl MainIpcAuthority/,/^}/' src/ipc.rs)
echo "$ipc_main_authority" | grep -B1 'crate::platform::is_root()' | grep -q 'target_os = "windows"' || r_s11b2="$r_s11b2 windows-system-fallback-not-windows-cfg"
awk '/pub fn is_root\(\)/,/^}/' src/platform/windows.rs | grep -q 'is_local_system'    || r_s11b2="$r_s11b2 windows-root-fallback-not-local-system"
grep -q 'SyncConfig' src/ipc.rs && r_s11b2="$r_s11b2 whole-config-ipc-variant-present"
grep -q 'SyncConfig' src/server.rs && r_s11b2="$r_s11b2 server-whole-config-import-present"
grep -q 'allows_main_channel_password_storage_sync' src/ipc.rs                        || r_s11b2="$r_s11b2 storage-sync-policy-missing"
grep -q 'Rejected permanent password storage sync from service-owned server' src/ipc.rs || r_s11b2="$r_s11b2 handler-storage-sync-not-denied"
grep -q 'Rejected permanent password salt sync from service-owned server' src/ipc.rs   || r_s11b2="$r_s11b2 handler-standalone-salt-sync-not-denied"
grep -q 'send_main_channel_mutation_rejection_ack' src/ipc.rs                         || r_s11b2="$r_s11b2 mutation-reject-nack-missing"
grep -q 'permanent-password-user-owned-writable' src/ipc.rs                            || r_s11b2="$r_s11b2 password-writability-receiver-missing"
grep -q 'permanent-password-user-owned-writable' src/flutter_ffi.rs                    || r_s11b2="$r_s11b2 password-writability-ffi-missing"
grep -q 'permanent-password-writable' src/flutter_ffi.rs                              || r_s11b2="$r_s11b2 owner-aware-password-writability-ffi-missing"
grep -q 'canSetPermanentPassword' flutter/lib/desktop/pages/desktop_home_page.dart    || r_s11b2="$r_s11b2 home-owner-aware-password-writability-ui-missing"
grep -q 'canSetPermanentPassword' flutter/lib/desktop/pages/desktop_setting_page.dart || r_s11b2="$r_s11b2 settings-owner-aware-password-writability-ui-missing"
user_scope_fn=$(awk '/fn is_user_main_ipc_scope_cli_command/,/^}/' src/core_main.rs)
if echo "$user_scope_fn" | grep -q '"--password"'; then
  r_s11b2="$r_s11b2 password-still-root-routes-to-user-main-ipc"
fi
if [ -n "$r_s11b2" ]; then echo "  FAIL R-S11b-2 service-owned password IPC closure:$r_s11b2"; rc=1; else
  echo "  ok  R-S11b-2 service-launched --server is marked; ordinary password config writes are absent; typed user-owned password writes are denied for service-owned receivers; Linux uses polkit/root-service commit with structured policy/package assurance; Windows uses pipe-client token elevation plus LocalSystem service commit; macOS stores the proposed value in a one-shot same-peer request, admits _service only for the installed app executable talking to the trusted PrivilegedHelperTools helper, finishes with authorization only, uses a nonshared timeout-zero custom Authorization Services right, verifies the external form noninteractively, writes the authorized value into the root LaunchDaemon credential store, rejects the old macOS main-server commit fallback, and serves the root credential to the service-owned LaunchAgent only as a launchd-owned runtime snapshot after pid/path and root-owned plist command-shape proof; whole-config IPC is absent; storage/salt sync is denied; --password dispatches through the owner-aware typed operation"; fi

# R-S11b-4: config/PRS secrecy after IPC closure. The balanced-PAKE PRS is
# connect-equivalent at rest, so the code-owned boundary is:
#   * no PRS/key material is exported over main IPC;
#   * service-owned receivers deny generic main-IPC password-storage/salt snapshots;
#   * macOS's service-owned LaunchAgent receives the root credential only through a typed
#     launchd-pid/path-verified _service runtime snapshot that never enters persisted Config;
#   * Unix config writes create owner-only files;
#   * Windows config paths get a protected current-user/SYSTEM DACL instead of inheriting broad parent ACLs.
echo "== R-S11b-4 config/PRS secrecy boundary =="
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::store_path_writes_owner_only_permissions --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::windows_config_acl_sddl_is_protected_owner_system_only --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::runtime_password_snapshot_does_not_persist --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_set_permanent_password_persists_when_value_matches_preset --color never
r_s11b4=""
r_s11b4_storage_block=$(awk '/name == "permanent-password-storage-and-salt"/,/name == "permanent-password-set"/' src/ipc.rs)
r_s11b4_salt_block=$(awk '/name == "salt"/,/name == "hide_cm"/' src/ipc.rs)
r_s11b4_store_path=$(awk '/pub fn store_path/,/^impl Config/' libs/hbb_common/src/config.rs)
r_s11b4_load_path=$(awk '/pub fn load_path/,/match confy::load_path/' libs/hbb_common/src/config.rs)
grep -q 'current_process_allows_main_channel_permanent_password_storage_sync()' <<<"$r_s11b4_storage_block" || r_s11b4="$r_s11b4 storage-sync-not-authority-gated"
grep -q 'Rejected permanent password storage sync from service-owned server' <<<"$r_s11b4_storage_block" || r_s11b4="$r_s11b4 storage-sync-service-deny-log-missing"
grep -q 'current_process_allows_main_channel_permanent_password_storage_sync()' <<<"$r_s11b4_salt_block" || r_s11b4="$r_s11b4 salt-read-not-authority-gated"
grep -q 'Rejected permanent password salt sync from service-owned server' <<<"$r_s11b4_salt_block" || r_s11b4="$r_s11b4 salt-read-service-deny-log-missing"
grep -q 'MacosServiceOwnedPermanentPasswordSnapshotRequest' src/ipc.rs || r_s11b4="$r_s11b4 macos-runtime-snapshot-request-missing"
grep -q 'macos_launch_agent_owns_service_owned_server_pid' src/ipc.rs || r_s11b4="$r_s11b4 macos-runtime-snapshot-launchd-proof-missing"
grep -q 'RUNTIME_PERMANENT_PASSWORD_PRS' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 runtime-prs-overlay-missing"
grep -q 'runtime_password_snapshot_does_not_persist' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 runtime-snapshot-nonpersist-test-missing"
grep -q 'test_set_permanent_password_persists_when_value_matches_preset' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 explicit-password-set-preset-noop-test-missing"
if grep -InE 'password_prs|get_permanent_password_prs|get_existing_key_pair|get_key_pair|key_pair' src/ipc.rs >/tmp/rd_verify_r_s11b4.$$; then
  r_s11b4="$r_s11b4 ipc-exports-prs-or-key-material"
fi
rm -f /tmp/rd_verify_r_s11b4.$$
grep -q 'confy::store_path_perms' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 unix-store-path-perms-wrapper-missing"
grep -q 'fs::Permissions::from_mode(0o600)' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 unix-store-mode-0600-missing"
grep -q 'store_path_writes_owner_only_permissions' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 unix-store-mode-test-missing"
grep -q 'windows_config_acl::prepare_config_path_for_load(&file)' <<<"$r_s11b4_load_path" || r_s11b4="$r_s11b4 windows-load-acl-gate-missing"
grep -q 'windows_config_acl::prepare_config_path_for_store(&path)' <<<"$r_s11b4_store_path" || r_s11b4="$r_s11b4 windows-store-acl-prep-missing"
grep -q 'windows_config_acl::harden_config_file(&path)' <<<"$r_s11b4_store_path" || r_s11b4="$r_s11b4 windows-store-final-file-acl-missing"
grep -q 'ConvertStringSecurityDescriptorToSecurityDescriptorW' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-sddl-conversion-missing"
grep -q 'SetNamedSecurityInfoW' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-setnamedsecurityinfo-missing"
grep -q 'DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-protected-dacl-missing"
grep -q 'OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-current-user-sid-missing"
grep -q 'format!("D:P{}{}", ace("SY"), ace(user_sid))' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-owner-system-sddl-missing"
grep -q 'user_sid.eq_ignore_ascii_case("S-1-5-18")' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-system-sddl-dedupe-missing"
grep -q 'windows_config_acl_sddl_is_protected_owner_system_only' libs/hbb_common/src/config.rs || r_s11b4="$r_s11b4 windows-acl-sddl-test-missing"
for feature in aclapi accctrl errhandlingapi sddl; do
  grep -q "\"$feature\"" libs/hbb_common/Cargo.toml || r_s11b4="$r_s11b4 windows-winapi-feature-$feature-missing"
done
if grep -InE ';;;(BA|BU|AU|WD|CO)' libs/hbb_common/src/config.rs >/tmp/rd_verify_r_s11b4_acl.$$; then
  r_s11b4="$r_s11b4 windows-config-acl-grants-broad-or-inherited-principal"
fi
rm -f /tmp/rd_verify_r_s11b4_acl.$$
if [ -n "$r_s11b4" ]; then echo "  FAIL R-S11b-4 config/PRS secrecy boundary:$r_s11b4"; rc=1; else
  echo "  ok  R-S11b-4 main IPC exports no PRS/key material, generic service-owned storage/salt sync is denied, macOS root credential snapshots are launchd-bound runtime overlays, Unix config writes are behavior-tested owner-only, and Windows config paths use an explicit protected current-user/SYSTEM DACL"; fi

# (3b-iii-d) R-S11b-3a/R-S11b-3d: service-owned machine policy is not an ordinary
# Data::Options write or a UI-side privileged registry write. Options writes use a typed daemon ACK/NACK;
# IPC callers persist only after an accepted ACK and never fall back to hidden local persistence when the
# daemon is unreachable. Windows share_rdp is a typed _service action committed by the LocalSystem service.
echo "== (3b-iii-d) service-owned policy writes reject ordinary IPC (R-S11b-3a/R-S11b-3d) =="
r_s11b3=
grep -q 'allows_main_channel_options_write' src/ipc.rs                                || r_s11b3="$r_s11b3 options-policy-missing"
grep -q 'Data::Options(Some(_)) => authority.allows_main_channel_options_write()' src/ipc.rs || r_s11b3="$r_s11b3 options-main-gate-missing"
grep -q 'current_process_allows_main_channel_options_write()' src/ipc.rs              || r_s11b3="$r_s11b3 options-handler-gate-missing"
grep -q 'Rejected options write over ordinary IPC for service-owned server' src/ipc.rs || r_s11b3="$r_s11b3 options-handler-reject-log-missing"
grep -qF '(OPTION_KEY, "")' libs/hbb_common/src/config.rs                             || r_s11b3="$r_s11b3 trust-anchor-option-not-pinned-empty"
grep -qF '(OPTION_PROXY_USERNAME, "")' libs/hbb_common/src/config.rs                  || r_s11b3="$r_s11b3 proxy-username-not-pinned-empty"
grep -qF '(OPTION_PROXY_PASSWORD, "")' libs/hbb_common/src/config.rs                  || r_s11b3="$r_s11b3 proxy-password-not-pinned-empty"
grep -qF 'overlay_pinned_settings(&mut res);' libs/hbb_common/src/config.rs           || r_s11b3="$r_s11b3 effective-options-read-not-pinned"
grep -qF 'fn overlay_pinned_settings(options: &mut HashMap<String, String>)' libs/hbb_common/src/config.rs || r_s11b3="$r_s11b3 effective-options-overlay-helper-missing"
if rg -n 'RemoveTrustedDevices|ClearTrustedDevices|main(Get|Remove|Clear)TrustedDevices|add_trusted_device|set_key_confirmed\(' src libs --glob '*.rs' >/tmp/r_s11b3_trust_writers.$$; then
  r_s11b3="$r_s11b3 trusted-device-or-key-confirmation-writer-present:$(tr '\n' ';' </tmp/r_s11b3_trust_writers.$$)"
fi
grep -q 'OptionsSetResult(bool)' src/ipc.rs                                           || r_s11b3="$r_s11b3 options-typed-result-missing"
grep -q 'Data::OptionsSetResult(false)' src/ipc.rs                                    || r_s11b3="$r_s11b3 options-reject-nack-missing"
grep -q 'Some(Data::OptionsSetResult(true))' src/ipc.rs                               || r_s11b3="$r_s11b3 caller-accepted-ack-missing"
grep -q 'Some(Data::OptionsSetResult(false))' src/ipc.rs                              || r_s11b3="$r_s11b3 caller-reject-nack-missing"
grep -q 'Options write requires daemon ACK' src/ipc.rs                                || r_s11b3="$r_s11b3 local-fallback-not-blocked"
grep -q 'RequestServiceOwnedShareRdp(bool)' src/ipc.rs                                || r_s11b3="$r_s11b3 windows-share-rdp-request-missing"
grep -q 'ServiceOwnedShareRdpResult(bool)' src/ipc.rs                                 || r_s11b3="$r_s11b3 windows-share-rdp-result-missing"
grep -q 'Data::RequestServiceOwnedShareRdp(_) => false' src/ipc.rs                    || r_s11b3="$r_s11b3 windows-share-rdp-main-gate-missing"
grep -q 'Data::ServiceOwnedShareRdpResult(false)' src/ipc.rs                          || r_s11b3="$r_s11b3 windows-share-rdp-main-reject-nack-missing"
grep -q 'windows_peer_is_authorized_for_service_owned_share_rdp_change' src/ipc.rs     || r_s11b3="$r_s11b3 windows-share-rdp-elevated-peer-gate-missing"
grep -q 'Some(Data::ServiceOwnedShareRdpResult(ok))' src/ipc.rs                       || r_s11b3="$r_s11b3 windows-share-rdp-caller-ack-missing"
grep -q 'RequestServiceOwnedShareRdp(enable)' src/platform/windows.rs                  || r_s11b3="$r_s11b3 windows-service-share-rdp-dispatch-missing"
grep -q 'handle_windows_service_owned_share_rdp_request' src/platform/windows.rs       || r_s11b3="$r_s11b3 windows-service-share-rdp-handler-missing"
grep -q 'open_subkey_with_flags(subkey, KEY_SET_VALUE)' src/platform/windows.rs        || r_s11b3="$r_s11b3 windows-share-rdp-direct-registry-write-missing"
grep -q 'crate::ipc::set_service_owned_share_rdp(_enable)' src/ui_interface.rs         || r_s11b3="$r_s11b3 ui-share-rdp-not-service-typed"
grep -q 'future: bind.mainIsRoot()' flutter/lib/desktop/pages/desktop_setting_page.dart || r_s11b3="$r_s11b3 ui-share-rdp-not-elevation-gated"
if grep -Eq 'reg add .*share_rdp|run_cmds\([^)]*share_rdp|pub fn set_share_rdp' src/platform/windows.rs; then
  r_s11b3="$r_s11b3 windows-share-rdp-direct-shell-writer-present"
fi
set_options_fn=$(awk '/pub async fn set_options/,/^}/' src/ipc.rs)
if echo "$set_options_fn" | grep -q 'crate::platform::is_installed'; then
  r_s11b3="$r_s11b3 options-fallback-uses-install-heuristic"
fi
if [ "$(echo "$set_options_fn" | grep -c 'Config::set_options(value)')" -ne 1 ]; then
  r_s11b3="$r_s11b3 options-caller-persistence-not-ack-only"
fi
grep -q 'Ok(()) => \*OPTIONS.lock().unwrap() = m' src/ui_interface.rs                 || r_s11b3="$r_s11b3 ui-cache-accepted-branch-missing"
grep -q 'Ok(()) => {' src/ui_interface.rs                                             || r_s11b3="$r_s11b3 ui-set-option-ack-branch-missing"
rm -f /tmp/r_s11b3_trust_writers.$$
if [ -n "$r_s11b3" ]; then echo "  FAIL R-S11b-3 service-owned policy IPC closure:$r_s11b3"; rc=1; else
  echo "  ok  R-S11b-3 service-owned --server rejects Data::Options(Some) before privacy/config side effects; IPC options writes require typed ACK before caller persistence; trust-anchor/proxy credential option keys are pinned empty; trusted-device/key-confirmation writers are absent; Windows share_rdp is a typed elevated _service action with no UI-side shell writer"; fi

# (3b-iii-e) R-S11c-2/R-S11c-3: Windows `_service` is not a raw privileged-action bus.
# Session switching and SAS/HKLM-touching actions require a receiver-authorized capability API; until that
# exists, the raw local service messages are absent and the caller-side request paths fail closed.
echo "== (3b-iii-e) Windows _service raw privileged commands absent (R-S11c-2/R-S11c-3) =="
r_s11c23=
if rg -n 'Data::SAS|Data::UserSid|connect_to_user_session|UserSid\(Option' src/ipc.rs src/platform/windows.rs src/server >/tmp/r_s11c23_hits.txt; then
  r_s11c23="$r_s11c23 raw-service-message-symbol-present:$(tr '\n' ';' </tmp/r_s11c23_hits.txt)"
fi
ipc_data_enum=$(awk '/pub enum Data {/,/^}/' src/ipc.rs)
if echo "$ipc_data_enum" | grep -Eq '^[[:space:]]*(SAS|UserSid)[[:space:]]*(,|\(|\{)'; then
  r_s11c23="$r_s11c23 raw-service-message-enum-variant-present"
fi
windows_service_loop=$(awk '/async fn run_service/,/^async fn launch_server/' src/platform/windows.rs)
echo "$windows_service_loop" | grep -q 'ipc::new_listener(crate::POSTFIX_SERVICE)' || r_s11c23="$r_s11c23 service-loop-range-missed-listener"
echo "$windows_service_loop" | grep -q 'authorize_service_scoped_ipc_connection' || r_s11c23="$r_s11c23 service-loop-range-missed-auth"
if echo "$windows_service_loop" | grep -Eq 'Data::(SAS|UserSid)|send_sas|SoftwareSASGeneration'; then
  r_s11c23="$r_s11c23 service-loop-still-dispatches-raw-session-or-sas"
fi
grep -q 'service-owned session switching requires a receiver-authorized capability' src/server/connection.rs || r_s11c23="$r_s11c23 selected-sid-not-fail-closed"
grep -q 'SAS in the physical console session requires a receiver-authorized service capability' src/server/input_service.rs || r_s11c23="$r_s11c23 sas-not-fail-closed"
if [ -n "$r_s11c23" ]; then echo "  FAIL R-S11c-2/R-S11c-3 Windows _service raw privileged command closure:$r_s11c23"; rc=1; else
  echo "  ok  R-S11c-2/R-S11c-3 Windows _service has no raw UserSid/SAS commands; session-switch and SAS requests fail closed pending a typed capability API"; fi

# (3b-iii-f) R-S11c-4a/R-S11c-4b: `_cm` is a helper authority boundary. Desktop CM accepts
# filesystem work only after the main server validates the CM stream's connection id/type/token
# against an active authenticated connection, and only through AuthorizedFS carrying that token.
# Plain desktop Data::FS is a reject-only legacy shape. Android remains in-process but shares the
# file-capability derivation.
echo "== (3b-iii-f) CM filesystem IPC requires connection-bound authority (R-S11c-4a/R-S11c-4b) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config cm_file_authority --color never
r_s11c4=
grep -q 'struct CmFileAuthority' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 no-cm-file-authority-type"
grep -q 'file_authority: CmFileAuthority' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 desktop-runner-has-no-authority-state"
grep -q 'let file_authority = CmFileAuthority::from_login' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 desktop-login-does-not-derive-authority"
grep -Eq '^[[:space:]]*file_authority = CmFileAuthority::from_login' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 android-login-does-not-derive-authority"
grep -q 'authorize_cm_ipc_connection(&stream)' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 desktop-cm-peer-auth-not-wired"
grep -q 'pub(crate) fn authorize_cm_ipc_connection' src/ipc/auth.rs || r_s11c4="$r_s11c4 cm-peer-auth-helper-missing"
grep -Fq 'cm_auth_token: crate::encode64(hbb_common::rand::random::<[u8; 32]>())' src/server/connection.rs || r_s11c4="$r_s11c4 cm-token-not-randomly-minted-in-connection"
grep -Fq 'cm_auth_token: self.cm_auth_token.clone()' src/server/connection.rs || r_s11c4="$r_s11c4 cm-token-not-sent-from-connection"
grep -q 'AuthorizedFS {' src/ipc.rs || r_s11c4="$r_s11c4 authorized-fs-variant-missing"
grep -q 'ValidateCmConnection {' src/ipc.rs || r_s11c4="$r_s11c4 cm-validation-message-missing"
grep -q 'pub(crate) async fn validate_cm_connection_authority' src/ipc.rs || r_s11c4="$r_s11c4 cm-validation-client-helper-missing"
grep -q 'pub(crate) fn validate_cm_connection_authority' src/server/connection.rs || r_s11c4="$r_s11c4 cm-validation-server-helper-missing"
grep -q 'conn.cm_auth_token == cm_auth_token' src/server/connection.rs || r_s11c4="$r_s11c4 cm-validation-not-bound-to-server-token"
grep -q 'conn_type.allows_file_authority()' src/server/connection.rs || r_s11c4="$r_s11c4 cm-validation-not-bound-to-conn-type"
grep -q 'cm_file: bool' src/server/connection.rs || r_s11c4="$r_s11c4 cm-server-file-capability-not-recorded"
grep -Fq 'pub enum CmAuthConnType' src/ipc.rs || r_s11c4="$r_s11c4 cm-auth-conn-type-missing"
cm_auth_type_block=$(awk '/impl CmAuthConnType/,/^}/' src/ipc.rs)
echo "$cm_auth_type_block" | grep -Fq 'Self::Remote' || r_s11c4="$r_s11c4 cm-auth-conn-type-not-keyed-to-remote"
echo "$cm_auth_type_block" | grep -Fq 'Self::FileTransfer' || r_s11c4="$r_s11c4 cm-auth-conn-type-not-keyed-to-filetransfer"
cm_file_authority_block=$(awk '/fn from_login/,/fn allows_fs/' src/ui_cm_interface.rs)
echo "$cm_file_authority_block" | grep -Fq 'conn_type.allows_file_authority()' || r_s11c4="$r_s11c4 cm-file-authority-not-keyed-to-conn-type"
echo "$cm_file_authority_block" | grep -Fq 'authority.valid' || r_s11c4="$r_s11c4 cm-file-authority-not-bound-to-validated-connection"
echo "$cm_file_authority_block" | grep -Fq 'authority.file' || r_s11c4="$r_s11c4 cm-file-authority-not-bound-to-server-file-capability"
grep -q 'Rejected CM login without matching authorized server connection' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 desktop-invalid-login-reject-log-missing"
grep -q 'Rejected CM AuthorizedFS without matching authorized file-capable login' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 desktop-authorizedfs-reject-log-missing"
grep -q 'Rejected unauthenticated CM Data::FS on desktop IPC' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 desktop-plain-fs-reject-log-missing"
grep -q 'Rejected Android CM Data::FS before authorized file-capable login' src/ui_cm_interface.rs || r_s11c4="$r_s11c4 android-reject-log-missing"
desktop_cm_login_block=$(awk '/Data::Login{id/,/self.cm.add_connection/' src/ui_cm_interface.rs)
desktop_validate_line=$(echo "$desktop_cm_login_block" | grep -n 'validate_cm_connection_authority' | head -1 | cut -d: -f1)
desktop_add_line=$(echo "$desktop_cm_login_block" | grep -n 'self.cm.add_connection' | head -1 | cut -d: -f1)
if [ -z "$desktop_validate_line" ] || [ -z "$desktop_add_line" ] || [ "$desktop_validate_line" -ge "$desktop_add_line" ]; then
  r_s11c4="$r_s11c4 desktop-login-validation-not-before-add_connection"
fi
desktop_cm_fs_block=$(awk '/Data::AuthorizedFS/,/Data::FS\(_\)/' src/ui_cm_interface.rs)
desktop_gate_line=$(echo "$desktop_cm_fs_block" | grep -n 'if !self.file_authority.allows_fs(cm_auth_token == self.cm_auth_token)' | head -1 | cut -d: -f1)
desktop_handle_line=$(echo "$desktop_cm_fs_block" | grep -n 'handle_fs' | head -1 | cut -d: -f1)
if [ -z "$desktop_gate_line" ] || [ -z "$desktop_handle_line" ] || [ "$desktop_gate_line" -ge "$desktop_handle_line" ]; then
  r_s11c4="$r_s11c4 desktop-fs-gate-not-before-handle_fs"
fi
android_cm_fs_block=$(awk '/Some\(Data::FS\(fs\)\)/,/Some\(Data::Close\)/' src/ui_cm_interface.rs)
android_gate_line=$(echo "$android_cm_fs_block" | grep -n 'if !file_authority.allows_fs(true)' | head -1 | cut -d: -f1)
android_handle_line=$(echo "$android_cm_fs_block" | grep -n 'handle_fs' | head -1 | cut -d: -f1)
if [ -z "$android_gate_line" ] || [ -z "$android_handle_line" ] || [ "$android_gate_line" -ge "$android_handle_line" ]; then
  r_s11c4="$r_s11c4 android-fs-gate-not-before-handle_fs"
fi
if [ -n "$r_s11c4" ]; then echo "  FAIL R-S11c-4 CM file IPC authority closure:$r_s11c4"; rc=1; else
  echo "  ok  R-S11c-4 CM rejects forged desktop login/FS unless the main server validates the active connection id/type/token; Android in-process FS remains login-gated"; fi

# (3b-iii-f2) R-S11c-11: fixed-path Unix _cm selection must prove the endpoint before
# Data::Login/cm_auth_token/file/chat/voice authority is disclosed.
echo "== (3b-iii-f2) Unix CM endpoint selection requires launch-bound proof (R-S11c-11) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config cm_endpoint_proof --color never
r_s11c11=
grep -q 'CmEndpointChallenge {' src/ipc.rs || r_s11c11="$r_s11c11 no-cm-endpoint-challenge"
grep -q 'CmEndpointProof {' src/ipc.rs || r_s11c11="$r_s11c11 no-cm-endpoint-proof"
grep -q 'CmServerChallenge {' src/ipc.rs || r_s11c11="$r_s11c11 no-cm-server-challenge"
grep -q 'CmServerProof {' src/ipc.rs || r_s11c11="$r_s11c11 no-cm-server-proof"
grep -q 'hmacsha256::authenticate' src/ipc.rs || r_s11c11="$r_s11c11 no-hmac-proof"
grep -q 'hmacsha256::verify' src/ipc.rs || r_s11c11="$r_s11c11 no-hmac-verify"
grep -q 'CM_SERVER_PROOF_CONTEXT' src/ipc.rs || r_s11c11="$r_s11c11 no-directional-server-proof-context"
grep -q 'verify_cm_server_proof' src/ipc.rs || r_s11c11="$r_s11c11 no-cm-server-proof-verify"
grep -q 'authenticate_cm_endpoint_launch_proof(&mut stream, cm_launch_token()).await' src/server/connection.rs || r_s11c11="$r_s11c11 server-does-not-authenticate-cm-launch-proof"
grep -q 'answer_cm_endpoint_challenge(&mut stream).await' src/ui_cm_interface.rs || r_s11c11="$r_s11c11 cm-listener-does-not-answer-launch-proof"
grep -q 'authenticate_macos_cm_endpoint(&stream, expected_arg)' src/server/connection.rs || r_s11c11="$r_s11c11 macos-cm-process-shape-not-checked"
grep -q 'pub(crate) fn authenticate_macos_cm_endpoint' src/ipc/auth.rs || r_s11c11="$r_s11c11 macos-cm-auth-helper-missing"
grep -q 'peer_process_is_current_exe_with_first_arg(peer_pid, "--server")' src/ipc/auth.rs || r_s11c11="$r_s11c11 cm-listener-peer-not-server-arg-bound"
grep -q 'run_as_user_with_env(args.clone(), cm_launch_env())' src/server/connection.rs || r_s11c11="$r_s11c11 macos-run-as-user-token-env-not-wired"
grep -q 'pub fn run_as_user_with_env' src/platform/macos.rs || r_s11c11="$r_s11c11 macos-token-env-launcher-missing"
grep -q 'CM_LAUNCH_TOKEN_ENV' src/common.rs || r_s11c11="$r_s11c11 cm-launch-token-env-constant-missing"
cm_listener_auth_block=$(awk '/authorize_cm_ipc_connection\(&stream\)/,/tokio::spawn/' src/ui_cm_interface.rs)
cm_listener_proof_line=$(echo "$cm_listener_auth_block" | grep -n 'answer_cm_endpoint_challenge(&mut stream).await' | head -1 | cut -d: -f1)
cm_listener_spawn_line=$(echo "$cm_listener_auth_block" | grep -n 'tokio::spawn' | head -1 | cut -d: -f1)
if [ -z "$cm_listener_proof_line" ] || [ -z "$cm_listener_spawn_line" ] || [ "$cm_listener_proof_line" -ge "$cm_listener_spawn_line" ]; then
  r_s11c11="$r_s11c11 cm-listener-proof-not-before-normal-ipc-loop"
fi
answer_fn_line=$(grep -n 'pub(crate) async fn answer_cm_endpoint_challenge' src/ipc.rs | head -1 | cut -d: -f1)
cm_server_challenge_line=$(awk -v start="$answer_fn_line" 'NR > start && /Data::CmServerChallenge/ { print NR; exit }' src/ipc.rs)
cm_server_verify_line=$(awk -v start="$answer_fn_line" 'NR > start && /verify_cm_server_proof/ { print NR; exit }' src/ipc.rs)
cm_endpoint_challenge_line=$(awk -v start="$answer_fn_line" 'NR > start && /Data::CmEndpointChallenge/ { print NR; exit }' src/ipc.rs)
if [ -z "$answer_fn_line" ] || [ -z "$cm_server_challenge_line" ] || [ -z "$cm_server_verify_line" ] || [ -z "$cm_endpoint_challenge_line" ] || [ "$cm_server_challenge_line" -ge "$cm_server_verify_line" ] || [ "$cm_server_verify_line" -ge "$cm_endpoint_challenge_line" ]; then
  r_s11c11="$r_s11c11 cm-listener-server-proof-not-before-endpoint-proof"
fi
server_auth_fn_line=$(grep -n 'pub(crate) async fn authenticate_cm_endpoint_launch_proof' src/ipc.rs | head -1 | cut -d: -f1)
server_proof_send_line=$(awk -v start="$server_auth_fn_line" 'NR > start && /Data::CmServerProof/ { print NR; exit }' src/ipc.rs)
server_endpoint_challenge_line=$(awk -v start="$server_auth_fn_line" 'NR > start && /Data::CmEndpointChallenge/ { print NR; exit }' src/ipc.rs)
if [ -z "$server_auth_fn_line" ] || [ -z "$server_proof_send_line" ] || [ -z "$server_endpoint_challenge_line" ] || [ "$server_proof_send_line" -ge "$server_endpoint_challenge_line" ]; then
  r_s11c11="$r_s11c11 server-peer-proof-not-before-endpoint-challenge"
fi
macos_process_line=$(grep -n 'authenticate_macos_cm_endpoint(&stream, expected_arg)' src/server/connection.rs | head -1 | cut -d: -f1)
macos_proof_line=$(awk -v start="$macos_process_line" 'NR > start && /authenticate_cm_endpoint_launch_proof\(&mut stream, cm_launch_token\(\)\)\.await/ { print NR; exit }' src/server/connection.rs)
if [ -z "$macos_process_line" ] || [ -z "$macos_proof_line" ] || [ "$macos_process_line" -ge "$macos_proof_line" ]; then
  r_s11c11="$r_s11c11 macos-cm-proof-not-after-process-shape-check"
fi
for line in $(grep -n 'crate::ipc::connect(1000, "_cm")' src/server/connection.rs | cut -d: -f1); do
  if ! sed -n "$((line-3)),$((line-1))p" src/server/connection.rs | grep -q '#\[cfg(not(any(target_os = "linux", target_os = "macos")))\]'; then
    r_s11c11="$r_s11c11 raw-unix-cm-connect-reintroduced"
    break
  fi
done
if [ -n "$r_s11c11" ]; then echo "  FAIL R-S11c-11 Unix CM endpoint-selection authority:$r_s11c11"; rc=1; else
  echo "  ok  R-S11c-11 Unix CM selection proves launch-bound endpoint authority before disclosing CM connection tokens; raw fixed-path _cm connects remain Windows-only"; fi

echo "== R-S11b/R-S11c ledger consistency =="
r_s11_docs=
grep -q 'status: CLOSED / GATED (2026-07-09)' HARDENING_STATUS.md || r_s11_docs="$r_s11_docs hardening-status-not-closed"
grep -q 'Release-blocking items .*closed' HARDENING_STATUS.md || r_s11_docs="$r_s11_docs release-blocking-heading-not-closed"
grep -q 'Current implementation is compliant with this R-S11b/R-S11c stronger requirement' HARDENING_STATUS.md || r_s11_docs="$r_s11_docs compliance-summary-missing"
grep -q 'R-S11c-11 closes the remaining fixed-path <code>_cm</code> endpoint-selection class' requirements.html || r_s11_docs="$r_s11_docs appendix-c28-r-s11c11-closure-missing"
if grep -q 'status: OPEN / RELEASE-BLOCKING' HARDENING_STATUS.md; then
  r_s11_docs="$r_s11_docs stale-open-status"
fi
if grep -q 'p-block">OPEN</span> R-S11c-11' requirements.html; then
  r_s11_docs="$r_s11_docs stale-r-s11c11-open-in-requirements"
fi
if [ -n "$r_s11_docs" ]; then echo "  FAIL R-S11b/R-S11c ledger consistency:$r_s11_docs"; rc=1; else
  echo "  ok  R-S11b/R-S11c ledger and Appendix C match the gated service-authority closure"; fi

# (3b-iii-f3) R-S11c-8: whiteboard is a helper authority boundary. It must not accept
# bare same-UID events, stale fixed-path listeners, caller-supplied display keys, or arbitrary Exit.
echo "== (3b-iii-f3) Whiteboard helper IPC requires launch and connection authority (R-S11c-8) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config whiteboard_endpoint_proof --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config whiteboard_authority --color never
r_s11c8=
grep -q 'WhiteboardEndpointChallenge {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-endpoint-challenge"
grep -q 'WhiteboardEndpointProof {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-endpoint-proof"
grep -q 'WhiteboardServerChallenge {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-server-challenge"
grep -q 'WhiteboardServerProof {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-server-proof"
grep -q 'WhiteboardBind {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-bind-message"
grep -q 'WhiteboardEvent {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-event-message"
grep -q 'WhiteboardClose {' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-close-message"
grep -q 'WhiteboardShutdown' src/ipc.rs || r_s11c8="$r_s11c8 no-whiteboard-shutdown-message"
grep -q 'WHITEBOARD_LAUNCH_TOKEN_ENV' src/common.rs || r_s11c8="$r_s11c8 no-whiteboard-launch-token-env"
grep -q 'WHITEBOARD_LAUNCH_PARENT_ENV' src/common.rs || r_s11c8="$r_s11c8 no-whiteboard-launch-parent-env"
grep -q 'whiteboard_endpoint_postfix(&launch_token)' src/whiteboard/client.rs || r_s11c8="$r_s11c8 client-does-not-use-launch-scoped-endpoint"
grep -q 'authenticate_whiteboard_endpoint_launch_proof(&mut stream, launch_token)' src/whiteboard/client.rs || r_s11c8="$r_s11c8 client-does-not-authenticate-whiteboard-endpoint"
grep -q 'authorize_whiteboard_ipc_connection(&stream, expected_parent_pid)' src/whiteboard/server.rs || r_s11c8="$r_s11c8 helper-does-not-check-parent-pid"
grep -q 'answer_whiteboard_endpoint_challenge(&mut stream).await' src/whiteboard/server.rs || r_s11c8="$r_s11c8 helper-does-not-prove-launch-token"
grep -q 'WhiteboardIpcState' src/whiteboard/server.rs || r_s11c8="$r_s11c8 helper-state-machine-missing"
grep -q 'super::client::get_key_cursor(conn_id)' src/whiteboard/server.rs || r_s11c8="$r_s11c8 helper-does-not-derive-render-key"
grep -q 'register_whiteboard(self.inner.id)' src/server/connection.rs || r_s11c8="$r_s11c8 connection-register-not-id-based"
grep -q 'unregister_whiteboard(self.inner.id)' src/server/connection.rs || r_s11c8="$r_s11c8 connection-unregister-not-id-based"
grep -q 'run_as_user_with_env' src/whiteboard/client.rs || r_s11c8="$r_s11c8 whiteboard-launch-env-not-wired"
grep -q 'pub fn run_as_user_with_env' src/platform/windows.rs || r_s11c8="$r_s11c8 windows-env-launcher-missing"
grep -q 'LPCWSTR extraEnvironment' src/platform/windows.cc || r_s11c8="$r_s11c8 windows-createprocess-env-missing"
grep -q 'environment_entry_key' src/platform/windows.cc || r_s11c8="$r_s11c8 windows-env-key-helper-missing"
grep -q 'environment_keys_equal' src/platform/windows.cc || r_s11c8="$r_s11c8 windows-env-key-compare-missing"
grep -q 'compare_environment_text(left, right, TRUE)' src/platform/windows.cc || r_s11c8="$r_s11c8 windows-env-key-compare-not-case-insensitive"
grep -q 'baseEntries.erase' src/platform/windows.cc || r_s11c8="$r_s11c8 windows-env-extra-vars-do-not-override-base"
grep -q 'std::sort(entries.begin(), entries.end(), environment_entry_less)' src/platform/windows.cc || r_s11c8="$r_s11c8 windows-env-block-not-sorted"
grep -q 'Windows helper launch environment authority' requirements.html || r_s11c8="$r_s11c8 windows-env-requirements-disposition-missing"
grep -q 'R-S11c-15 — Windows helper launch environment authority' HARDENING_STATUS.md || r_s11c8="$r_s11c8 windows-env-hardening-ledger-missing"
if awk '/^extern "C"[[:space:]]*$/,/end of extern "C"/' src/platform/windows.cc | grep -q 'std::vector<wchar_t> merge_environment_blocks'; then
  r_s11c8="$r_s11c8 windows-env-helper-has-c-linkage"
fi
if grep -RIn 'Whiteboard((String' src/ipc.rs src/whiteboard 2>/dev/null | grep -v 'grep' >/tmp/rd_verify_whiteboard_tuple.$$; then
  r_s11c8="$r_s11c8 legacy-whiteboard-tuple-message-present"
fi
if grep -RIn 'Data::Whiteboard((' src/whiteboard src/server 2>/dev/null >/tmp/rd_verify_whiteboard_tuple_send.$$; then
  r_s11c8="$r_s11c8 legacy-whiteboard-tuple-send-present"
fi
if grep -q 'ipc::connect(1000, "_whiteboard")' src/whiteboard/client.rs; then
  r_s11c8="$r_s11c8 raw-fixed-whiteboard-connect-present"
fi
if grep -q 'new_listener("_whiteboard")' src/whiteboard/server.rs; then
  r_s11c8="$r_s11c8 fixed-whiteboard-listener-present"
fi
if grep -q 'send_event(("".to_string(), CustomEvent::Exit))' src/whiteboard/server.rs; then
  r_s11c8="$r_s11c8 unconditional-whiteboard-global-exit-present"
fi
if grep -RIn 'get_key_cursor(conn)' src/server src/whiteboard/client.rs 2>/dev/null >/tmp/rd_verify_whiteboard_keys.$$; then
  r_s11c8="$r_s11c8 caller-derived-whiteboard-key-present"
fi
whiteboard_register_context=$(grep -B4 -A2 'register_whiteboard(self.inner.id)' src/server/connection.rs || true)
echo "$whiteboard_register_context" | grep -q 'if self.is_authed_remote_conn()' || r_s11c8="$r_s11c8 register-not-remote-auth-type-gated"
if [ -n "$r_s11c8" ]; then echo "  FAIL R-S11c-8 whiteboard helper authority:$r_s11c8"; rc=1; else
  echo "  ok  R-S11c-8 whiteboard helper uses launch-scoped endpoint proof plus parent-pid admission and per-connection event tokens; fixed-path tuple events and arbitrary Exit are absent"; fi
rm -f /tmp/rd_verify_whiteboard_tuple.$$ /tmp/rd_verify_whiteboard_tuple_send.$$ /tmp/rd_verify_whiteboard_keys.$$

# (3b-iii-g) R-S11c-5: macOS source-conformance for the privileged LaunchDaemon packaging.
# The daemon may not shell-launch root code, write logs through /tmp, execute from an app bundle,
# or adopt active-user app/config state as root-owned service state. apple-conform-check.sh mirrors
# this with the full Apple source gate.
echo "== (3b-iii-g) macOS privileged service packaging source invariants (R-S11c-5) =="
r_s11c5=
daemon_plist=src/platform/privileges_scripts/daemon.plist
install_scpt=src/platform/privileges_scripts/install.scpt
update_scpt=src/platform/privileges_scripts/update.scpt
uninstall_scpt=src/platform/privileges_scripts/uninstall.scpt
macos_rs=src/platform/macos.rs
macos_helper_command_sources=(src/platform/macos.rs src/ipc.rs src/ipc/auth.rs)
daemon_args_block=$(awk '/<key>ProgramArguments<\/key>/,/<\/array>/' "$daemon_plist")
echo "$daemon_args_block" | grep -q '<string>/Library/PrivilegedHelperTools/com.carriez.rustdesk_service</string>' || r_s11c5="$r_s11c5 daemon-not-privileged-helper-exec"
if echo "$daemon_args_block" | grep -qE '<string>/(bin|usr/bin)/(sh|bash)</string>|<string>-c</string>'; then
  r_s11c5="$r_s11c5 daemon-shell-launch"
fi
grep -q '<string>/Library/Application Support/RustDesk</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-working-dir-not-root-support"
grep -q '<string>/Library/Logs/RustDesk/rustdesk_service.err</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-stderr-not-library-log"
grep -q '<string>/Library/Logs/RustDesk/rustdesk_service.out</string>' "$daemon_plist" || r_s11c5="$r_s11c5 daemon-stdout-not-library-log"
[ ! -e "$update_scpt" ] || r_s11c5="$r_s11c5 update-scpt-present"
if grep -RInE 'update_daemon_agent|update_source_dir|\.rustdeskupdate|get_update_temp_dir|try_remove_temp_update_dir|update\.scpt' \
  src/platform/macos.rs src/core_main.rs src/flutter_ffi.rs src/ui_interface.rs src/platform/privileges_scripts 2>/dev/null >/tmp/rd_verify_macos_update.$$; then
  r_s11c5="$r_s11c5 macos-privileged-update-surface-present"
fi
rm -f /tmp/rd_verify_macos_update.$$
for command in osascript launchctl open ls ioreg codesign; do
  if grep -F "Command::new(\"$command\")" "${macos_helper_command_sources[@]}" >/dev/null; then
    r_s11c5="$r_s11c5 macos-path-selected-$command"
  fi
done
for system_path in /usr/bin/osascript /bin/launchctl /usr/bin/open /usr/sbin/ioreg /usr/bin/codesign; do
  grep -F "\"$system_path\"" "${macos_helper_command_sources[@]}" >/dev/null || r_s11c5="$r_s11c5 macos-absolute-${system_path##*/}-missing"
done
grep -Fq 'const MACOS_OPEN: &str = "/usr/bin/open";' src/ipc.rs || r_s11c5="$r_s11c5 macos-ipc-open-absolute-missing"
grep -Fq 'Command::new(MACOS_OPEN)' src/ipc.rs || r_s11c5="$r_s11c5 macos-ipc-reopen-not-absolute"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_EXEC: &str =' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-service-ipc-helper-const-missing"
grep -Fq '/Library/PrivilegedHelperTools/com.carriez.rustdesk_service' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-service-ipc-helper-path-missing"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_DIR: &str = "/Library/PrivilegedHelperTools";' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-service-ipc-helper-dir-const-missing"
grep -Fq 'const MACOS_CODESIGN: &str = "/usr/bin/codesign";' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-codesign-absolute-missing"
grep -Fq 'const MACOS_PRIVILEGED_HELPER_REQUIREMENT: &str =' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-code-requirement-const-missing"
grep -Fq 'certificate leaf[subject.OU] = "HZF9JMC8YN"' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-teamid-requirement-missing"
grep -Fq 'identifier "service" or identifier "com.carriez.rustdesk_service"' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-identifier-requirement-missing"
grep -Fq 'const MACOS_INSTALLED_APP_REQUIREMENT: &str =' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-app-code-requirement-const-missing"
grep -Fq 'identifier "com.carriez.rustdesk"' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-app-identifier-requirement-missing"
grep -Fq 'fn macos_installed_app_bundle_path() -> PathBuf' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-app-bundle-path-helper-missing"
grep -Fq 'fn macos_privileged_helper_is_expected_and_trusted(current_exe: &Path) -> bool' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-service-ipc-helper-trust-missing"
grep -Fq 'fn macos_installed_app_is_expected_and_trusted(peer_exe: &Path) -> bool' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-service-ipc-app-trust-missing"
grep -Fq 'fn macos_path_has_no_extended_acl(path: &Path) -> bool' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-acl-check-missing"
grep -Fq 'CString::new(path.as_os_str().as_bytes().to_vec())' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-acl-cstring-missing"
grep -Fq 'acl_get_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-acl-get-link-missing"
grep -Fq 'acl_valid_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED, acl)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-acl-valid-link-missing"
grep -Fq 'acl_get_entry(acl, MACOS_ACL_FIRST_ENTRY, &mut entry)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-acl-entry-missing"
grep -Fq 'acl_free(self.0)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-acl-free-missing"
grep -Fq 'macOS runtime service ACL inspection provenance' requirements.html || r_s11c5="$r_s11c5 macos-runtime-acl-requirements-missing"
grep -Fq 'R-S11c-17 — macOS runtime service ACL inspection provenance' HARDENING_STATUS.md || r_s11c5="$r_s11c5 macos-runtime-acl-ledger-missing"
grep -Fq 'fn macos_path_has_expected_type_and_permissions(' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-mode-check-helper-missing"
grep -Fq 'fn macos_privileged_helper_satisfies_code_requirement(path: &Path) -> bool' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-codesign-check-missing"
grep -Fq 'fn macos_installed_app_satisfies_code_requirement(path: &Path) -> bool' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-app-codesign-check-missing"
grep -Fq 'Command::new(MACOS_CODESIGN)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-codesign-not-absolute"
if grep -Fq 'Command::new(MACOS_LS)' src/ipc/auth.rs \
  || grep -Fq 'const MACOS_LS' src/ipc/auth.rs \
  || grep -Fq 'Command::new("/bin/ls")' "${macos_helper_command_sources[@]}" \
  || grep -Fq 'Command::new("ls")' "${macos_helper_command_sources[@]}"; then
  r_s11c5="$r_s11c5 macos-runtime-acl-ls-parser-present"
fi
grep -Fq 'MACOS_PRIVILEGED_HELPER_REQUIREMENT' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-requirement-not-used"
grep -Fq 'MACOS_INSTALLED_APP_REQUIREMENT' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-app-requirement-not-used"
grep -Fq 'fs::symlink_metadata(path)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-symlink-metadata-missing"
grep -Fq 'metadata.file_type().is_symlink()' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-symlink-gate-missing"
grep -Fq 'macos_root_wheel_not_group_world_writable(&metadata)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-helper-root-wheel-mode-gate-missing"
grep -Fq 'macos_root_owned_not_group_world_writable(&metadata)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-app-root-owned-mode-gate-missing"
grep -Fq 'require_executable && metadata.permissions().mode() & 0o111 == 0' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-runtime-exec-mode-gate-missing"
grep -Fq 'macos_privileged_helper_satisfies_code_requirement(expected)' src/ipc/auth.rs || r_s11c5="$r_s11c5 macos-service-ipc-helper-code-requirement-not-enforced"
macos_service_identity_block=$(awk '/fn macos_service_ipc_allows_installed_app_and_privileged_helper/,/^}/' src/ipc/auth.rs)
echo "$macos_service_identity_block" | grep -Fq 'macos_privileged_helper_is_expected_and_trusted(current_exe)' || r_s11c5="$r_s11c5 macos-service-ipc-current-helper-not-verified"
echo "$macos_service_identity_block" | grep -Fq 'macos_installed_app_is_expected_and_trusted(peer_exe)' || r_s11c5="$r_s11c5 macos-service-ipc-peer-app-not-verified"
macos_app_trust_block=$(awk '/fn macos_installed_app_is_expected_and_trusted/,/^}/' src/ipc/auth.rs)
echo "$macos_app_trust_block" | grep -Fq 'macos_installed_app_executable_path()' || r_s11c5="$r_s11c5 macos-app-executable-path-not-checked"
echo "$macos_app_trust_block" | grep -Fq 'macos_path_has_expected_type_and_permissions(&app_executable, false, true, false)' || r_s11c5="$r_s11c5 macos-app-executable-permissions-not-checked"
echo "$macos_app_trust_block" | grep -Fq 'macos_installed_app_satisfies_code_requirement(&app_bundle)' || r_s11c5="$r_s11c5 macos-app-code-requirement-not-enforced"
line_app_check=$(grep -n 'macos_installed_app_is_expected_and_trusted(peer_exe)' src/ipc/auth.rs | tail -n 1 | cut -d: -f1)
line_helper_check=$(grep -n 'macos_privileged_helper_is_expected_and_trusted(current_exe)' src/ipc/auth.rs | tail -n 1 | cut -d: -f1)
if [ -z "$line_app_check" ] || [ -z "$line_helper_check" ] || [ "$line_app_check" -ge "$line_helper_check" ]; then
  r_s11c5="$r_s11c5 macos-service-ipc-helper-checked-before-app-peer"
fi
if grep -q 'macos_service_ipc_allows_gui_and_service_binaries' src/ipc/auth.rs; then
  r_s11c5="$r_s11c5 macos-service-ipc-old-gui-service-binary-model-present"
fi
if echo "$macos_service_identity_block" | grep -qE 'peer_dir|current_dir|OsStr::new\("service"\)|executable_paths_match\(peer_dir, current_dir\)'; then
  r_s11c5="$r_s11c5 macos-service-ipc-old-same-directory-model-present"
fi
grep -q 'pub(crate) fn console_owner_uid' "$macos_rs" || r_s11c5="$r_s11c5 macos-console-owner-uid-missing"
grep -Fq 'std::fs::metadata("/dev/console")' "$macos_rs" || r_s11c5="$r_s11c5 macos-console-owner-not-dev-console-backed"
grep -q 'hbb_common::libc::getpwuid_r' "$macos_rs" || r_s11c5="$r_s11c5 macos-active-user-not-passwd-r-backed"
grep -Fq 'bail!("No valid active console uid")' "$macos_rs" || r_s11c5="$r_s11c5 macos-launch-asuser-no-empty-uid-gate"
if grep -q 'fn get_active_user(t: &str)' "$macos_rs" || grep -q 'split_whitespace().nth(2)' "$macos_rs"; then
  r_s11c5="$r_s11c5 macos-active-user-ls-parser-present"
fi
if grep -q '/tmp/rustdesk_service' "$daemon_plist" "$install_scpt" "$uninstall_scpt"; then
  r_s11c5="$r_s11c5 tmp-daemon-log-path"
fi
if grep -q '/Applications/RustDesk.app/Contents/MacOS/service' "$daemon_plist" "$install_scpt"; then
  r_s11c5="$r_s11c5 app-bundle-root-service-path"
fi
grep -Fq 'bundled_service_exec: PathBuf' "$macos_rs" || r_s11c5="$r_s11c5 macos-install-context-no-bundled-helper"
grep -Fq 'fn bundled_service_executable() -> Option<PathBuf>' "$macos_rs" || r_s11c5="$r_s11c5 macos-bundled-helper-resolver-missing"
grep -Fq '.arg(&context.bundled_service_exec)' "$macos_rs" || r_s11c5="$r_s11c5 macos-install-does-not-pass-bundled-helper"
script="$install_scpt"
script_sh_line=$(grep 'set sh to' "$script")
grep -q 'on run {daemon_file, agent_file, bundled_service_exec}' "$script" || r_s11c5="$r_s11c5 install-does-not-take-bundled-helper"
grep -q 'set temp_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-temp-helper-missing"
grep -q 'set cleanup_temp to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-temp-helper-cleanup-missing"
grep -q 'set reject_symlinks to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-symlink-reject"
grep -q 'set helper_requirement to "=anchor apple generic' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-requirement-missing"
grep -q 'certificate leaf\[subject.OU\] = \\"HZF9JMC8YN\\"' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-teamid-requirement-missing"
grep -q 'identifier \\"service\\" or identifier \\"com.carriez.rustdesk_service\\"' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-identifier-requirement-missing"
grep -q 'quoted form of helper_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-dir-symlink-not-checked"
grep -q 'quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-symlink-not-checked"
grep -q 'quoted form of bundled_service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-bundled-helper-not-checked"
grep -q 'set verify_bundled_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-bundled-helper-verifier"
grep -q 'set install_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-helper-installer"
grep -q 'set verify_service_exec to' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-service-exec-verifier"
grep -q '/usr/bin/codesign --verify --strict -R " & quoted form of helper_requirement' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-codesign-check-missing"
grep -q '/usr/bin/install -o root -g wheel -m 0755 " & quoted form of bundled_service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-not-installed-from-bundle"
grep -q '/usr/bin/cmp -s " & quoted form of bundled_service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-copy-not-byte-checked"
grep -q '/Library/PrivilegedHelperTools' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-dir-not-used"
grep -q '/Library/PrivilegedHelperTools/com.carriez.rustdesk_service' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-exec-not-used"
grep -q "/usr/bin/stat -f '%Su:%Sg'" "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-owner-not-statted"
grep -q 'root:wheel' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-root-wheel-not-required"
grep -q -- '-perm +022' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-write-bit-not-rejected"
grep -q '/bin/ls -lde' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-acl-not-inspected"
grep -q "NR > 1 {exit 1}" "$script" || r_s11c5="$r_s11c5 $(basename "$script")-helper-acl-not-rejected"
grep -qF '[ ! -f " & quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-file-not-required"
grep -qF '[ ! -x " & quoted form of service_exec' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-service-exec-executable-not-required"
grep -q '/usr/bin/install -d -o root -g wheel -m 0755' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-root-dir-install"
grep -q 'quoted form of log_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-log-dir"
grep -q 'quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-stderr-log-path"
grep -q 'quoted form of log_stdout' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-stdout-log-path"
grep -q 'quoted form of support_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-support-dir"
grep -q 'quoted form of root_prefs_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-no-root-prefs-dir"
grep -q '/bin/chmod -N " & quoted form of log_dir' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-dirs-acl-not-cleared"
grep -q '/bin/rm -f " & quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-logs-not-recreated"
grep -q '/bin/chmod -N " & quoted form of log_stderr' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-log-acl-not-cleared"
grep -q '/usr/bin/printf %s " & quoted form of daemon_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-not-printf-written"
grep -q '/usr/bin/printf %s " & quoted form of agent_file' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-not-printf-written"
grep -q '/bin/chmod -N " & quoted form of daemon_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-acl-not-cleared"
grep -q '/bin/chmod -N " & quoted form of agent_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-acl-not-cleared"
grep -q '/bin/chmod 0644 " & quoted form of daemon_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-daemon-plist-mode-missing"
grep -q '/bin/chmod 0644 " & quoted form of agent_plist' "$script" || r_s11c5="$r_s11c5 $(basename "$script")-agent-plist-mode-missing"
echo "$script_sh_line" | grep -q 'reject_symlinks.*verify_bundled_service_exec.*create_helper_dir.*secure_helper_dir.*install_service_exec.*verify_service_exec.*write_daemon_plist.*write_agent_plist.*verify_service_exec.*load_service' || r_s11c5="$r_s11c5 install-helper-not-installed-and-reverified-before-load"
grep -q 'set remove_service_exec to "/bin/rm -f " & quoted form of service_exec' "$uninstall_scpt" || r_s11c5="$r_s11c5 uninstall-does-not-remove-helper"
grep -q 'quoted form of temp_service_exec' "$uninstall_scpt" || r_s11c5="$r_s11c5 uninstall-does-not-remove-temp-helper"
grep -q 'quoted form of service_exec' "$uninstall_scpt" || r_s11c5="$r_s11c5 uninstall-helper-path-not-quoted"
if grep -qE 'verify_app_bundle_tree|secure_app|copy_user_prefs|user_home|root_prefs_file|root_prefs2_file|/bin/cp -f|/usr/sbin/chown -R root:wheel " & quoted form of app_bundle' "$install_scpt"; then
  r_s11c5="$r_s11c5 install-adopts-app-or-user-config"
fi
if grep -qE 'chown -R .*:staff|quoted form of user & ":staff"|/Users/" & user|echo " & quoted form of (daemon|agent)_file' "$install_scpt"; then
  r_s11c5="$r_s11c5 user-owned-or-echo-plist-install"
fi
if grep -qE '> " & (daemon|agent)_plist|launchctl unload -w " & daemon_plist|/bin/rm /Library/Launch' "$install_scpt" "$uninstall_scpt"; then
  r_s11c5="$r_s11c5 unquoted-privileged-path"
fi
if grep -qE 'let active_user_home|arg\(active_user_home\)|arg\(&active_user_home\)' src/platform/macos.rs; then
  r_s11c5="$r_s11c5 macos-install-imports-active-user-home"
fi
if [ -n "$r_s11c5" ]; then echo "  FAIL R-S11c-5 macOS privileged service packaging:$r_s11c5"; rc=1; else
  echo "  ok  R-S11c-5 macOS LaunchDaemon uses a signed root-owned PrivilegedHelperTools executable, and _service IPC identity matches that deployed helper model; dormant updater and active-user config import are absent"; fi

echo "== (3b-iii-g2) desktop service lifecycle completion authority (R-S11c-16) =="
r_s11c16=
core_install_block=$(awk '/args\[0\] == "--install-service"/,/args\[0\] == "--uninstall-service"/' src/core_main.rs)
core_uninstall_block=$(awk '/args\[0\] == "--uninstall-service"/,/args\[0\] == "--service"/' src/core_main.rs)
echo "$core_install_block" | grep -Fq 'if !crate::platform::install_service()' || r_s11c16="$r_s11c16 core-install-return-ignored"
echo "$core_install_block" | grep -Fq 'std::process::exit(1);' || r_s11c16="$r_s11c16 core-install-no-nonzero-exit"
echo "$core_uninstall_block" | grep -Fq 'if !crate::platform::uninstall_service(false, true)' || r_s11c16="$r_s11c16 core-uninstall-return-ignored"
echo "$core_uninstall_block" | grep -Fq 'std::process::exit(1);' || r_s11c16="$r_s11c16 core-uninstall-no-nonzero-exit"
if grep -Fq 'crate::platform::install_service();' src/core_main.rs || grep -Fq 'crate::platform::uninstall_service(false, true);' src/core_main.rs; then
  r_s11c16="$r_s11c16 stale-core-service-call-discard"
fi
linux_systemctl_body=$(awk '/fn systemctl_service\(action: &str, app_name: &str\) -> bool/,/^}/' src/platform/linux.rs)
linux_install_body=$(awk '/pub fn install_service\(\) -> bool/,/^}/' src/platform/linux.rs)
linux_uninstall_body=$(awk '/pub fn uninstall_service\(show_new_window: bool, _: bool\) -> bool/,/^}/' src/platform/linux.rs)
echo "$linux_systemctl_body" | grep -Fq 'Ok(status) if status.success() => true' || r_s11c16="$r_s11c16 linux-systemctl-success-not-explicit"
echo "$linux_systemctl_body" | grep -Fq 'log::error!("systemctl {action} {app_name} failed with status {status}")' || r_s11c16="$r_s11c16 linux-systemctl-nonzero-not-logged"
echo "$linux_systemctl_body" | grep -Fq 'Err(err)' || r_s11c16="$r_s11c16 linux-systemctl-spawn-error-not-handled"
if echo "$linux_install_body" | grep -Eq 'copy_user_config_to_root_service_config|copy_service_config_files|copy_service_config_file|fs::copy'; then
  r_s11c16="$r_s11c16 linux-install-imports-user-config"
fi
echo "$linux_install_body" | grep -Fq 'if !systemctl_service("enable", &app_name)' || r_s11c16="$r_s11c16 linux-install-enable-not-fatal"
echo "$linux_install_body" | grep -Fq 'if !systemctl_service("start", &app_name)' || r_s11c16="$r_s11c16 linux-install-start-not-fatal"
echo "$linux_uninstall_body" | grep -Fq 'if !systemctl_service("disable", &app_name)' || r_s11c16="$r_s11c16 linux-uninstall-disable-not-fatal"
echo "$linux_uninstall_body" | grep -Fq 'if !systemctl_service("stop", &app_name)' || r_s11c16="$r_s11c16 linux-uninstall-stop-not-fatal"
if echo "$linux_uninstall_body" | grep -Fq 'copy_user_config_to_root_service_config()'; then
  r_s11c16="$r_s11c16 linux-uninstall-runs-config-migration"
fi
if grep -Fq 'let _ = systemctl_service' src/platform/linux.rs; then
  r_s11c16="$r_s11c16 linux-systemctl-result-discard"
fi
grep -q 'fn run_checked_command(command: &mut Command, description: &str) -> bool' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-no-checked-command-helper"
grep -q 'Ok(status) if status.success() => true' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-status-success-not-explicit"
grep -q 'fn launchctl_label_loaded(label: &str) -> Option<bool>' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-no-launchctl-label-query"
grep -q 'fn ensure_launchctl_label_removed(label: &str) -> bool' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-no-launchctl-remove-verifier"
grep -q 'fn restart_launch_agent(agent_plist_file: &str, label: &str) -> bool' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-no-launch-agent-restart-verifier"
macos_install_service_body=$(awk '/pub fn install_service\(\) -> bool/,/^}/' src/platform/macos.rs)
echo "$macos_install_service_body" | grep -Fq 'run_service_install(context)' || r_s11c16="$r_s11c16 macos-install-wrapper-not-checked-install"
if echo "$macos_install_service_body" | grep -Fq 'service_plists_exist'; then
  r_s11c16="$r_s11c16 macos-install-wrapper-plist-only-success"
fi
grep -q 'restart_launch_agent(&context.agent_plist_file, &server_launch_agent_label())' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-install-agent-load-not-authoritative"
grep -q 'return func();' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-sync-uninstall-return-not-propagated"
grep -q 'if !ensure_launchctl_label_removed(&server_launch_agent_label())' src/platform/macos.rs || r_s11c16="$r_s11c16 macos-uninstall-agent-remove-not-authoritative"
if perl -0ne 'exit(/\.status\(\)\s*\.ok\(\)/ ? 0 : 1)' src/platform/macos.rs; then
  r_s11c16="$r_s11c16 macos-status-result-discard"
fi
grep -q 'set unload_existing_service to "if /bin/launchctl list " & quoted form of service_label' "$install_scpt" || r_s11c16="$r_s11c16 macos-install-no-existing-daemon-unload"
grep -q '&& /bin/launchctl list " & quoted form of service_label' "$install_scpt" || r_s11c16="$r_s11c16 macos-install-daemon-load-not-verified"
grep -q 'unload_existing_service.*load_service' "$install_scpt" || r_s11c16="$r_s11c16 macos-install-order-not-pinned"
grep -q 'set unload_service to "if /bin/launchctl list " & quoted form of service_label' "$uninstall_scpt" || r_s11c16="$r_s11c16 macos-uninstall-no-daemon-loaded-branch"
grep -q 'set verify_unloaded to "if /bin/launchctl list " & quoted form of service_label' "$uninstall_scpt" || r_s11c16="$r_s11c16 macos-uninstall-daemon-unload-not-verified"
grep -q 'set verify_removed to "if \[ -e " & quoted form of daemon_plist' "$uninstall_scpt" || r_s11c16="$r_s11c16 macos-uninstall-plist-removal-not-verified"
grep -q 'set sh to "set -e;"' "$uninstall_scpt" || r_s11c16="$r_s11c16 macos-uninstall-not-set-e"
if grep -qF '|| true' "$uninstall_scpt"; then
  r_s11c16="$r_s11c16 macos-uninstall-masks-launchctl-failure"
fi
grep -q 'R-S11c-16 and R-S11c-10j make service lifecycle completion status-authoritative' requirements.html || r_s11c16="$r_s11c16 requirements-disposition-missing"
grep -q 'R-S11c-16 — Desktop service lifecycle completion authority' HARDENING_STATUS.md || r_s11c16="$r_s11c16 hardening-ledger-missing"
if [ -n "$r_s11c16" ]; then echo "  FAIL R-S11c-16 desktop service lifecycle completion authority:$r_s11c16"; rc=1; else
  echo "  ok  R-S11c-16 service lifecycle wrappers propagate CLI failure, Linux service install does not import user config, and macOS AppleScript/launchctl/plist completion is checked"; fi

# (3b-iii-h) R-S11c-10a: Linux root-context desktop discovery must not build passwd/proc
# lookups through a shell. This is a narrow sub-slice: env/home/Xorg/subprocess discovery
# only. Lifecycle kill/service commands and display-tool invocations remain separate R-S11c-10 work.
echo "== (3b-iii-h) Linux desktop discovery avoids root shell interpolation (R-S11c-10a) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_ --color never
r_s11c10a=
grep -q 'fn matching_process_cmdlines' src/platform/linux.rs || r_s11c10a="$r_s11c10a no-proc-cmdline-helper"
grep -q 'fn proc_environ_value' src/platform/linux.rs || r_s11c10a="$r_s11c10a no-proc-environ-parser"
grep -q 'is_non_login_shell(user.shell())' src/platform/linux.rs || r_s11c10a="$r_s11c10a prelogin-not-passwd-api-backed"
grep -q 'matching_process_cmdlines(&self.uid, "Xorg")' src/platform/linux.rs || r_s11c10a="$r_s11c10a xorg-discovery-not-proc-backed"
grep -q 'any_process_cmdline_contains(&format!' src/platform/linux.rs || r_s11c10a="$r_s11c10a subprocess-discovery-not-proc-backed"
linux_discovery_blocks=$(
  awk '/pub fn is_prelogin/,/fn is_non_login_shell/' src/platform/linux.rs
  awk '/fn get_env\(/,/fn get_env_from_pid/' src/platform/linux.rs
  awk '/fn get_env_from_pid/,/#\[link/' src/platform/linux.rs
  awk '/fn get_home\(&mut self\)/,/fn get_xauth_from_xorg/' src/platform/linux.rs
  awk '/fn get_xauth_from_xorg/,/fn get_xauth_x11/' src/platform/linux.rs
  awk '/fn set_is_subprocess/,/pub fn refresh/' src/platform/linux.rs
)
if echo "$linux_discovery_blocks" | grep -Eq 'run_cmds|run_cmds_trim_newline|getent passwd|ps -[uef]|cat /proc|grep |awk |sed |xargs|CMD_SH'; then
  r_s11c10a="$r_s11c10a shell-shaped-discovery-regressed"
fi
if [ -n "$r_s11c10a" ]; then echo "  FAIL R-S11c-10a Linux desktop discovery shell interpolation:$r_s11c10a"; rc=1; else
  echo "  ok  R-S11c-10a Linux prelogin/home/env/Xorg/subprocess discovery uses users+/proc helpers, not shell pipelines"; fi

echo "== (3b-iii-h2) Linux service lifecycle process cleanup avoids shell pipelines (R-S11c-10b) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_process_kill --color never
r_s11c10b=
grep -q 'fn all_process_cmdlines' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-proc-process-enumerator"
grep -q 'fn current_exe_process_cmdlines' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-current-exe-process-enumerator"
grep -q 'fn proc_exe_matches_path' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-proc-exe-identity-check"
grep -q 'fn process_has_exact_arg' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-exact-argv-matcher"
grep -q 'fn kill_process' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-direct-kill-helper"
grep -q 'hbb_common::libc::kill' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-kill-syscall"
grep -q 'kill_current_exe_processes_with_arg("--server", "--server")' src/platform/linux.rs || r_s11c10b="$r_s11c10b server-cleanup-not-argv-backed"
grep -q 'kill_xorg_processes_with_config(&xorg_config)' src/platform/linux.rs || r_s11c10b="$r_s11c10b xorg-cleanup-not-argv-backed"
grep -q 'kill_current_exe_processes_with_arg("--cm-no-ui", "--cm-no-ui")' src/platform/linux.rs || r_s11c10b="$r_s11c10b cm-cleanup-not-argv-backed"
grep -q 'fn signal_current_exe_processes_with_arg' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-direct-signal-helper"
grep -q 'pub fn stop_tray_processes()' src/platform/linux.rs || r_s11c10b="$r_s11c10b no-tray-cleanup-helper"
grep -q 'crate::platform::stop_tray_processes();' src/core_main.rs || r_s11c10b="$r_s11c10b core-server-not-using-tray-cleanup-helper"
tray_cleanup_block=$(awk '/pub fn stop_tray_processes\(\)/,/^}/' src/platform/linux.rs)
if ! echo "$tray_cleanup_block" | grep -q 'signal_current_exe_processes_with_arg'; then
  r_s11c10b="$r_s11c10b tray-cleanup-not-proc-helper-backed"
fi
if ! echo "$tray_cleanup_block" | grep -q 'hbb_common::libc::SIGTERM'; then
  r_s11c10b="$r_s11c10b tray-cleanup-not-sigterm"
fi
if [ "$(echo "$tray_cleanup_block" | grep -c '"--tray"')" -lt 2 ]; then
  r_s11c10b="$r_s11c10b tray-cleanup-not-exact-tray-argv"
fi
linux_process_cleanup_blocks=$(
  awk '/fn stop_rustdesk_servers/,/fn should_start_server/' src/platform/linux.rs
  awk '/fn all_process_cmdlines/,/fn any_process_cmdline_contains/' src/platform/linux.rs
)
if echo "$linux_process_cleanup_blocks" | grep -Eq 'run_cmds|ps -[ef]|grep |awk |sed |xargs|kill -9|CMD_SH'; then
  r_s11c10b="$r_s11c10b shell-shaped-process-cleanup-regressed"
fi
if grep -RInE 'Command::new\("pkill"\)|pkill -f' src/core_main.rs src/platform/linux.rs >/tmp/rd_verify_r_s11c10b_tray.$$; then
  cat /tmp/rd_verify_r_s11c10b_tray.$$
  rm -f /tmp/rd_verify_r_s11c10b_tray.$$
  r_s11c10b="$r_s11c10b pkill-tray-cleanup-regressed"
else
  rm -f /tmp/rd_verify_r_s11c10b_tray.$$
fi
if [ -n "$r_s11c10b" ]; then echo "  FAIL R-S11c-10b Linux service lifecycle process cleanup:$r_s11c10b"; rc=1; else
  echo "  ok  R-S11c-10b Linux service/tray cleanup verifies /proc exe identity, uses exact argv matches plus kill(2), and avoids ps/grep/awk/xargs/pkill shell pipelines"; fi

echo "== (3b-iii-h3) Linux xrandr resolution discovery avoids shell pipelines (R-S11c-10c) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_xrandr --color never
r_s11c10c=
grep -q 'fn xrandr_query() -> ResultType<String>' src/platform/linux.rs || r_s11c10c="$r_s11c10c no-xrandr-query-helper"
grep -q 'const XRANDR_PATHS' src/platform/linux.rs || r_s11c10c="$r_s11c10c no-fixed-xrandr-paths"
grep -q 'let Some(xrandr) = xrandr_path()' src/platform/linux.rs || r_s11c10c="$r_s11c10c xrandr-not-fixed-path-resolved"
grep -q 'Command::new(xrandr).arg("--query").output()' src/platform/linux.rs || r_s11c10c="$r_s11c10c xrandr-query-not-argv-only"
grep -q 'normalize_xrandr_query_output' src/platform/linux.rs || r_s11c10c="$r_s11c10c no-rust-space-normalizer"
grep -q 'match xrandr_query()' src/platform/linux.rs || r_s11c10c="$r_s11c10c resolutions-not-using-helper"
grep -q 'let xrandr_output = xrandr_query()?' src/platform/linux.rs || r_s11c10c="$r_s11c10c current-resolution-not-using-helper"
xrandr_blocks=$(
  awk '/fn xrandr_query\(\)/,/^}/' src/platform/linux.rs
  awk '/pub fn resolutions\(name: &str\)/,/pub fn change_resolution_directly/' src/platform/linux.rs
)
if echo "$xrandr_blocks" | grep -Eq 'run_cmds|CMD_SH|sh -c|Command::new\("xrandr"\)|xrandr --query[[:space:]]*\||tr -s'; then
  r_s11c10c="$r_s11c10c shell-shaped-xrandr-query-regressed"
fi
if [ -n "$r_s11c10c" ]; then echo "  FAIL R-S11c-10c Linux xrandr resolution discovery:$r_s11c10c"; rc=1; else
  echo "  ok  R-S11c-10c Linux xrandr resolution discovery executes a trusted fixed xrandr path with argv and normalizes whitespace in Rust, with no shell pipeline"; fi

echo "== (3b-iii-h4) Linux process discovery avoids pgrep shell probes (R-S11c-10d) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_process_discovery --color never
"${RUN[@]}" cargo test -p hbb_common --lib r_s11c10_kde_session --color never
r_s11c10d=
grep -q 'fn process_is_xwayland(args: \&\[String\]) -> bool' src/platform/linux.rs || r_s11c10d="$r_s11c10d no-xwayland-argv-matcher"
grep -q 'pub(crate) fn xwayland_display_from_proc() -> Option<String>' src/platform/linux.rs || r_s11c10d="$r_s11c10d no-xwayland-proc-display-helper"
grep -q 'crate::platform::linux::xwayland_display_from_proc()' src/whiteboard/linux.rs || r_s11c10d="$r_s11c10d whiteboard-not-using-proc-helper"
grep -q 'fn process_basename_is_kded(args: \&\[String\]) -> bool' libs/hbb_common/src/platform/linux.rs || r_s11c10d="$r_s11c10d no-kded-basename-matcher"
process_discovery_blocks=$(
  awk '/fn process_is_xwayland/,/^}/' src/platform/linux.rs
  awk '/fn xwayland_display_arg/,/^}/' src/platform/linux.rs
  awk '/xwayland_display_from_proc/,/^}/' src/platform/linux.rs
  awk '/pub fn is_xwayland_running/,/^}/' src/platform/linux.rs
  awk '/fn get_display_from_xwayland/,/^}/' src/whiteboard/linux.rs
  awk '/fn process_basename_is_kded/,/^}/' libs/hbb_common/src/platform/linux.rs
  awk '/pub fn is_kde_session/,/^}/' libs/hbb_common/src/platform/linux.rs
)
if echo "$process_discovery_blocks" | grep -Eq 'run_cmds|CMD_SH|sh -c|pgrep|grep '; then
  r_s11c10d="$r_s11c10d shell-shaped-process-discovery-regressed"
fi
if grep -RInE 'pgrep[[:space:]-].*(Xwayland|kded)|run_cmds\("pgrep' src/platform/linux.rs src/whiteboard/linux.rs libs/hbb_common/src/platform/linux.rs >/tmp/rd_verify_r_s11c10d.$$; then
  cat /tmp/rd_verify_r_s11c10d.$$
  rm -f /tmp/rd_verify_r_s11c10d.$$
  r_s11c10d="$r_s11c10d pgrep-shell-probe-present"
else
  rm -f /tmp/rd_verify_r_s11c10d.$$
fi
if [ -n "$r_s11c10d" ]; then echo "  FAIL R-S11c-10d Linux process discovery:$r_s11c10d"; rc=1; else
  echo "  ok  R-S11c-10d Linux Xwayland/whiteboard/KDE process discovery reads /proc argv and avoids pgrep/sh -c"; fi

echo "== (3b-iii-h5) Linux os-release parsing avoids shell probes (R-S11c-10e) =="
"${RUN[@]}" cargo test -p hbb_common --lib r_s11c10_os_release --color never
r_s11c10e=
grep -q 'fn parse_os_release_field' libs/hbb_common/src/platform/linux.rs || r_s11c10e="$r_s11c10e no-os-release-parser"
grep -q 'std::fs::read_to_string("/etc/os-release")' libs/hbb_common/src/platform/linux.rs || r_s11c10e="$r_s11c10e no-etc-os-release-read"
grep -q 'std::fs::read_to_string("/usr/lib/os-release")' libs/hbb_common/src/platform/linux.rs || r_s11c10e="$r_s11c10e no-usr-lib-os-release-fallback"
os_release_blocks=$(
  awk '/impl Distro/,/fn trusted_fixed_executable/' libs/hbb_common/src/platform/linux.rs
)
if echo "$os_release_blocks" | grep -Eq 'run_cmds|run_cmds_trim_newline|CMD_SH|sh -c|awk|grep |cat /etc/os-release'; then
  r_s11c10e="$r_s11c10e shell-shaped-os-release-parser-regressed"
fi
if grep -RInE 'cat /etc/os-release|awk .* /etc/os-release|run_cmds\(".*os-release|is_opensuse|fn elevate|fn exec_privileged' src/platform/linux.rs libs/hbb_common/src/platform/linux.rs >/tmp/rd_verify_r_s11c10e.$$; then
  cat /tmp/rd_verify_r_s11c10e.$$
  rm -f /tmp/rd_verify_r_s11c10e.$$
  r_s11c10e="$r_s11c10e stale-os-release-shell-or-elevation-residue"
else
  rm -f /tmp/rd_verify_r_s11c10e.$$
fi
if [ -n "$r_s11c10e" ]; then echo "  FAIL R-S11c-10e Linux os-release parsing:$r_s11c10e"; rc=1; else
  echo "  ok  R-S11c-10e Linux distro metadata is parsed from os-release files as data, with no awk/cat/grep shell path"; fi

echo "== (3b-iii-h6) Linux desktop-manager headless detection avoids shell probes (R-S11c-10f) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_desktop_manager --color never
r_s11c10f=
grep -q 'const XORG_CANDIDATE_PATHS' src/platform/linux_desktop_manager.rs || r_s11c10f="$r_s11c10f no-fixed-xorg-candidates"
grep -q 'fn find_xorg_path() -> Option' src/platform/linux_desktop_manager.rs || r_s11c10f="$r_s11c10f no-direct-xorg-path-check"
grep -q 'fn has_xsession_desktop_entry_in' src/platform/linux_desktop_manager.rs || r_s11c10f="$r_s11c10f no-direct-xsession-dir-check"
desktop_manager_blocks=$(
  awk '/fn detect_headless/,/pub fn try_start_desktop/' src/platform/linux_desktop_manager.rs
  awk '/fn find_xorg_path/,/fn has_xsession_desktop_entry_in/' src/platform/linux_desktop_manager.rs
  awk '/fn has_xsession_desktop_entry_in/,/^}/' src/platform/linux_desktop_manager.rs
)
if echo "$desktop_manager_blocks" | grep -Eq 'run_cmds|run_cmds_trim_newline|CMD_SH|sh -c|ls /usr/share/xsessions|Command::new\("(which|ls|grep|awk|sed|xargs)"'; then
  r_s11c10f="$r_s11c10f shell-shaped-desktop-manager-probe-regressed"
fi
if grep -RInE 'run_cmds\([^)]*(which|/usr/share/xsessions)|which[[:space:]]+Xorg|ls[[:space:]]+/usr/share/xsessions|DesktopManager::get_xorg|fn get_xorg\(' src/platform/linux_desktop_manager.rs >/tmp/rd_verify_r_s11c10f.$$; then
  cat /tmp/rd_verify_r_s11c10f.$$
  rm -f /tmp/rd_verify_r_s11c10f.$$
  r_s11c10f="$r_s11c10f stale-shell-desktop-manager-probe"
else
  rm -f /tmp/rd_verify_r_s11c10f.$$
fi
if [ -n "$r_s11c10f" ]; then echo "  FAIL R-S11c-10f Linux desktop-manager headless detection:$r_s11c10f"; rc=1; else
  echo "  ok  R-S11c-10f Linux desktop-manager headless detection uses fixed Xorg paths and direct xsession directory reads, with no shell command probe"; fi

echo "== (3b-iii-h7) Linux SELinux status avoids shell probes (R-S11c-10g) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_selinux --color never
r_s11c10g=
grep -q 'const SELINUX_ENFORCE_PATHS' src/platform/linux.rs || r_s11c10g="$r_s11c10g no-fixed-selinux-enforce-paths"
grep -q '"/sys/fs/selinux/enforce"' src/platform/linux.rs || r_s11c10g="$r_s11c10g no-sysfs-selinux-enforce-read"
grep -q '"/selinux/enforce"' src/platform/linux.rs || r_s11c10g="$r_s11c10g no-legacy-selinux-enforce-read"
grep -q 'selinux_enforcing_from_paths(&SELINUX_ENFORCE_PATHS)' src/platform/linux.rs || r_s11c10g="$r_s11c10g no-ordered-selinux-path-reader"
grep -q 'fn selinux_enforce_file_is_enforcing(path: &Path) -> bool' src/platform/linux.rs || r_s11c10g="$r_s11c10g no-selinux-file-reader"
grep -q 'fn parse_selinux_enforce(contents: &str) -> Option<bool>' src/platform/linux.rs || r_s11c10g="$r_s11c10g no-selinux-enforce-parser"
grep -q '"1" => Some(true)' src/platform/linux.rs || r_s11c10g="$r_s11c10g parser-missing-enforcing-value"
grep -q '"0" => Some(false)' src/platform/linux.rs || r_s11c10g="$r_s11c10g parser-missing-permissive-value"
selinux_status_blocks=$(
  awk '/const SELINUX_ENFORCE_PATHS/,/fn parse_selinux_enforce/' src/platform/linux.rs
  awk '/fn parse_selinux_enforce/,/^}/' src/platform/linux.rs
)
if echo "$selinux_status_blocks" | grep -Eq 'run_cmds|run_cmds_trim_newline|CMD_SH|sh -c|Command::new\("(getenforce|sestatus)"'; then
  r_s11c10g="$r_s11c10g shell-shaped-selinux-status-regressed"
fi
if grep -RInE 'getenforce|sestatus|run_cmds\("getenforce"|run_cmds\("sestatus"' src/platform/linux.rs >/tmp/rd_verify_r_s11c10g.$$; then
  cat /tmp/rd_verify_r_s11c10g.$$
  rm -f /tmp/rd_verify_r_s11c10g.$$
  r_s11c10g="$r_s11c10g stale-selinux-shell-probe"
else
  rm -f /tmp/rd_verify_r_s11c10g.$$
fi
if [ -n "$r_s11c10g" ]; then echo "  FAIL R-S11c-10g Linux SELinux status probing:$r_s11c10g"; rc=1; else
  echo "  ok  R-S11c-10g Linux SELinux status reads selinuxfs enforce files as data, with no getenforce/sestatus shell probe"; fi

echo "== (3b-iii-h8) Linux config home correction avoids shell probes (R-S11c-10h) =="
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::config_patch_root_home_uses_passwd_home --color never
r_s11c10h=
grep -q 'crate::platform::linux::get_home_dir_trusted()' libs/hbb_common/src/config.rs || r_s11c10h="$r_s11c10h config-patch-not-passwd-api-backed"
config_patch_block=$(awk '/^fn patch\(/,/^}/' libs/hbb_common/src/config.rs)
if echo "$config_patch_block" | grep -Eq 'run_cmds|run_cmds_trim_newline|whoami|getent passwd|awk |grep |sed |xargs|CMD_SH'; then
  r_s11c10h="$r_s11c10h shell-shaped-config-home-correction-regressed"
fi
if grep -RInE 'run_cmds_trim_newline\("whoami"\)|getent passwd.*awk|run_cmds_trim_newline\(&cmd\)' libs/hbb_common/src/config.rs >/tmp/rd_verify_r_s11c10h.$$; then
  cat /tmp/rd_verify_r_s11c10h.$$
  rm -f /tmp/rd_verify_r_s11c10h.$$
  r_s11c10h="$r_s11c10h stale-config-home-shell-probe"
else
  rm -f /tmp/rd_verify_r_s11c10h.$$
fi
if [ -n "$r_s11c10h" ]; then echo "  FAIL R-S11c-10h Linux config home correction:$r_s11c10h"; rc=1; else
  echo "  ok  R-S11c-10h Linux config home correction uses getpwuid-backed home lookup and avoids whoami/getent/awk shell probes"; fi

echo "== (3b-iii-h9) Linux service lifecycle systemctl avoids shell command construction (R-S11c-10i) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11c10_service --color never
r_s11c10i=
grep -q 'const SYSTEMCTL_PATHS' src/platform/linux.rs || r_s11c10i="$r_s11c10i no-fixed-systemctl-paths"
grep -q 'fn systemctl_service(action: &str, app_name: &str) -> bool' src/platform/linux.rs || r_s11c10i="$r_s11c10i no-systemctl-argv-helper"
grep -q 'Command::new(systemctl)' src/platform/linux.rs || r_s11c10i="$r_s11c10i systemctl-not-argv-only"
if grep -qE 'copy_user_config_to_root_service_config|copy_service_config_files|copy_service_config_file|prepare_service_config_dir|fs::copy\(.*toml|/root/\.config' src/platform/linux.rs; then
  r_s11c10i="$r_s11c10i service-install-imports-user-config"
fi
if grep -qE 'fn run_cmds_status|fn has_cmd' src/platform/linux.rs; then
  r_s11c10i="$r_s11c10i stale-shell-lifecycle-helper"
fi
service_lifecycle_blocks=$(
  awk '/fn trusted_fixed_executable/,/pub fn check_autostart_config/' src/platform/linux.rs
)
if echo "$service_lifecycle_blocks" | grep -Eq 'run_cmds|CMD_SH|sh -c|cp -f|Command::new\("which"\)|systemctl (enable|disable|start|stop)'; then
  r_s11c10i="$r_s11c10i shell-shaped-service-lifecycle-regressed"
fi
if [ -n "$r_s11c10i" ]; then echo "  FAIL R-S11c-10i Linux service lifecycle systemctl/no-config-import:$r_s11c10i"; rc=1; else
  echo "  ok  R-S11c-10i Linux service lifecycle uses fixed systemctl paths, argv-only start/stop/enable/disable, and no user-config import into root service state"; fi

echo "== (3b-iii-h9b) Linux privileged helper command provenance is fixed-path (R-S11c-10k) =="
r_s11c10k=
grep -q 'const SUDO_PATHS' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-fixed-sudo-paths"
grep -q 'const ENV_PATHS' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-fixed-env-paths"
grep -q 'const W_PATHS' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-fixed-w-paths"
grep -q 'const XDG_SCREENSAVER_PATHS' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-fixed-xdg-screensaver-paths"
grep -q 'fn trusted_command_path' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-trusted-command-resolver"
grep -q 'fn sudo_path() -> Option' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-sudo-resolver"
grep -q 'fn valid_sudo_envs' src/platform/linux.rs || r_s11c10k="$r_s11c10k no-sudo-env-validator"
grep -q 'Command::new(sudo_path)' src/platform/linux.rs || r_s11c10k="$r_s11c10k sudo-not-fixed-path"
grep -q 'Command::new(w).arg(user).output()' src/platform/linux.rs || r_s11c10k="$r_s11c10k w-not-fixed-path"
grep -q 'display_from_x11_socket_dir_for_user(user, Path::new("/tmp/.X11-unix"))' src/platform/linux.rs || r_s11c10k="$r_s11c10k x11-socket-fallback-not-native"
grep -q 'current_exe_process_cmdlines()' src/platform/linux.rs || r_s11c10k="$r_s11c10k cm-detection-not-proc-backed"
if grep -RInE 'Command::new\("(sudo|ps|w|ls|xrandr|xdg-screensaver)"\)|Command::new\(CMD_(PS|SH)\.as_str\(\)\)|Command::new\("which"\)' src/platform/linux.rs >/tmp/rd_verify_r_s11c10k.$$; then
  cat /tmp/rd_verify_r_s11c10k.$$
  rm -f /tmp/rd_verify_r_s11c10k.$$
  r_s11c10k="$r_s11c10k path-selected-linux-helper-command"
else
  rm -f /tmp/rd_verify_r_s11c10k.$$
fi
if [ -n "$r_s11c10k" ]; then echo "  FAIL R-S11c-10k Linux privileged helper command provenance:$r_s11c10k"; rc=1; else
  echo "  ok  R-S11c-10k Linux root/service helper commands use trusted fixed paths or native /proc/filesystem reads"; fi

echo "== (3b-iii-h9c) Linux shared helper command provenance has no shell/path fallback (R-S11c-10m) =="
"${RUN[@]}" cargo test -p hbb_common --lib r_s11c10m --color never
r_s11c10m=
grep -q 'const LOGINCTL_PATHS' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m no-fixed-loginctl-paths"
grep -q 'const NOTIFY_SEND_PATHS' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m no-fixed-notify-send-paths"
grep -q 'fn trusted_fixed_executable(path: &Path) -> bool' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m no-shared-trusted-exec-check"
grep -q 'path.is_absolute()' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m shared-command-resolver-allows-relative"
grep -q 'metadata.uid() == 0' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m shared-command-resolver-not-root-owned"
grep -q 'metadata.mode() & 0o022 == 0' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m shared-command-resolver-allows-writable"
grep -q 'Command::new(loginctl)' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m loginctl-not-fixed-path-argv"
grep -q 'fn spawn_message_command' libs/hbb_common/src/platform/linux.rs || r_s11c10m="$r_s11c10m system-message-not-fixed-path-helper"
grep -q 'pub const REOPEN_AFTER_SERVICE_STOP_ARG' src/platform/linux.rs || r_s11c10m="$r_s11c10m no-delayed-reopen-argv-mode"
grep -q 'schedule_reopen_after_service_stop(2)' src/platform/linux.rs || r_s11c10m="$r_s11c10m uninstall-reopen-not-argv-mode"
grep -q 'reopen_after_service_stop(secs)' src/core_main.rs || r_s11c10m="$r_s11c10m delayed-reopen-arg-not-handled"
grep -q 'Linux shared helper command provenance' requirements.html || r_s11c10m="$r_s11c10m requirements-disposition-missing"
grep -q 'R-S11c-10m closes the shared Linux helper command-provenance residue' HARDENING_STATUS.md || r_s11c10m="$r_s11c10m hardening-ledger-missing"
shared_linux_helper_blocks=$(
  awk '/const LOGINCTL_PATHS/,/pub fn get_wayland_displays/' libs/hbb_common/src/platform/linux.rs
  awk '/pub fn schedule_reopen_after_service_stop/,/fn trusted_fixed_executable/' src/platform/linux.rs
)
if echo "$shared_linux_helper_blocks" | grep -Eq 'find_cmd_path|CMD_PS|CMD_SH|Command::new\("which"\)|flatpak-spawn|pub fn run_cmds|pub fn run_cmds_trim_newline|fn shell_quote|pub fn shell_quote|sh -c|sleep \{secs\}|exec \{exe'; then
  r_s11c10m="$r_s11c10m shared-helper-shell-or-path-fallback-regressed"
fi
if grep -RInE 'find_cmd_path|CMD_PS|CMD_SH|Command::new\("which"\)|flatpak-spawn|pub fn run_cmds|pub fn run_cmds_trim_newline|fn shell_quote|pub fn shell_quote|sleep \{secs\}; exec' libs/hbb_common/src/platform/linux.rs src/platform/linux.rs >/tmp/rd_verify_r_s11c10m.$$; then
  cat /tmp/rd_verify_r_s11c10m.$$
  rm -f /tmp/rd_verify_r_s11c10m.$$
  r_s11c10m="$r_s11c10m stale-shared-helper-shell-api"
else
  rm -f /tmp/rd_verify_r_s11c10m.$$
fi
if [ -n "$r_s11c10m" ]; then echo "  FAIL R-S11c-10m Linux shared helper command provenance:$r_s11c10m"; rc=1; else
  echo "  ok  R-S11c-10m Linux shared helpers use trusted fixed command paths and delayed reopen is argv-only"; fi

echo "== (3b-iii-h9c2) Linux headless CM uid lookup avoids PATH-selected id (R-S11c-10n) =="
r_s11c10n=
grep -q 'async fn uid_for_username(username: &str) -> ResultType<String>' src/server/connection.rs || r_s11c10n="$r_s11c10n no-headless-cm-uid-helper"
grep -q 'hbb_common::tokio::task::spawn_blocking' src/server/connection.rs || r_s11c10n="$r_s11c10n uid-lookup-not-spawn-blocking"
grep -q 'hbb_common::users::get_user_by_name(&lookup_name)' src/server/connection.rs || r_s11c10n="$r_s11c10n uid-lookup-not-structured-account-data"
grep -q 'user.uid()' src/server/connection.rs || r_s11c10n="$r_s11c10n uid-lookup-not-user-uid"
grep -q 'uid_for_username(&username).await?' src/server/connection.rs || r_s11c10n="$r_s11c10n headless-cm-not-using-uid-helper"
grep -q 'Linux headless CM uid lookup' requirements.html || r_s11c10n="$r_s11c10n requirements-disposition-missing"
grep -q 'R-S11c-10n closes the Linux headless CM uid lookup' HARDENING_STATUS.md || r_s11c10n="$r_s11c10n hardening-ledger-missing"
headless_cm_uid_blocks=$(
  awk '/async fn uid_for_username/,/fn cm_launch_token/' src/server/connection.rs
  awk '/if headless_cm/,/user = Some/' src/server/connection.rs
)
if echo "$headless_cm_uid_blocks" | grep -Eq 'Command::new\("id"\)|id -u|uid_cmd|timeout\(10_000, uid_cmd\.output'; then
  r_s11c10n="$r_s11c10n headless-cm-id-command-regressed"
fi
if grep -RInE 'Command::new\("id"\)|id -u|uid_cmd' src/server/connection.rs >/tmp/rd_verify_r_s11c10n.$$; then
  cat /tmp/rd_verify_r_s11c10n.$$
  rm -f /tmp/rd_verify_r_s11c10n.$$
  r_s11c10n="$r_s11c10n stale-headless-cm-id-command"
else
  rm -f /tmp/rd_verify_r_s11c10n.$$
fi
if [ -n "$r_s11c10n" ]; then echo "  FAIL R-S11c-10n Linux headless CM uid lookup:$r_s11c10n"; rc=1; else
  echo "  ok  R-S11c-10n Linux headless CM uid lookup uses structured account data, not PATH-selected id"; fi

echo "== (3b-iii-h9c3) Linux clipboard FUSE stale unmount avoids PATH-selected umount (R-S11c-10o) =="
r_s11c10o=
grep -qF 'fn unmount_stale_fuse_mount(mount_point: &Path)' libs/clipboard/src/platform/unix/fuse/mod.rs || r_s11c10o="$r_s11c10o no-stale-unmount-helper"
grep -qF 'fn fuse_mount_path_cstring(mount_point: &Path) -> Result<CString, CliprdrError>' libs/clipboard/src/platform/unix/fuse/mod.rs || r_s11c10o="$r_s11c10o no-mount-path-cstring-helper"
grep -qF 'CString::new(mount_point.as_os_str().as_bytes())' libs/clipboard/src/platform/unix/fuse/mod.rs || r_s11c10o="$r_s11c10o mount-path-not-cstring-checked"
grep -qF 'libc::umount2(mount_c.as_ptr(), libc::UMOUNT_NOFOLLOW)' libs/clipboard/src/platform/unix/fuse/mod.rs || r_s11c10o="$r_s11c10o stale-unmount-not-syscall-nofollow"
grep -qF 'unmount_stale_fuse_mount(mount_point);' libs/clipboard/src/platform/unix/fuse/mod.rs || r_s11c10o="$r_s11c10o prepare-does-not-use-stale-unmount-helper"
grep -qF 'fuse_mount_path_cstring_rejects_nul' libs/clipboard/src/platform/unix/fuse/mod.rs || r_s11c10o="$r_s11c10o no-nul-path-regression-test"
grep -q 'Linux clipboard FUSE stale unmount provenance' requirements.html || r_s11c10o="$r_s11c10o requirements-disposition-missing"
grep -q 'R-A6 helper-provenance companion' requirements.html || r_s11c10o="$r_s11c10o requirements-helper-provenance-missing"
grep -q 'R-S11c-10o closes the Linux clipboard FUSE stale-unmount provenance path' HARDENING_STATUS.md || r_s11c10o="$r_s11c10o hardening-ledger-missing"
grep -qF 'direct no-follow' libs/clipboard/README.md || r_s11c10o="$r_s11c10o clipboard-readme-not-updated"
grep -qF 'umount2()' libs/clipboard/README.md || r_s11c10o="$r_s11c10o clipboard-readme-not-updated"
if grep -RInE 'Command::new\("umount"\)|std::process::Command::new\("umount"\)|process::Command::new\("umount"\)' libs/clipboard/src/platform/unix/fuse/mod.rs >/tmp/rd_verify_r_s11c10o.$$; then
  cat /tmp/rd_verify_r_s11c10o.$$
  rm -f /tmp/rd_verify_r_s11c10o.$$
  r_s11c10o="$r_s11c10o stale-path-selected-umount-command"
else
  rm -f /tmp/rd_verify_r_s11c10o.$$
fi
if [ -n "$r_s11c10o" ]; then echo "  FAIL R-S11c-10o Linux clipboard FUSE stale unmount provenance:$r_s11c10o"; rc=1; else
  echo "  ok  R-S11c-10o Linux clipboard FUSE stale unmount uses direct umount2(UMOUNT_NOFOLLOW), not PATH-selected umount"; fi

echo "== (3b-iii-h9c4) Linux self-relaunch avoids AppImage APPDIR/AppRun fallback (R-S11c-10p) =="
r_s11c10p=
grep -qF 'pub fn run_me_with_env<T, I, K, V>' src/common.rs || r_s11c10p="$r_s11c10p no-self-relaunch-helper"
grep -qF 'let cmd = std::env::current_exe()?;' src/common.rs || r_s11c10p="$r_s11c10p self-relaunch-not-current-exe"
grep -qF 'let mut cmd = std::process::Command::new(cmd);' src/common.rs || r_s11c10p="$r_s11c10p self-relaunch-not-current-exe-command"
grep -qF 'cmd.envs(envs.iter().map(|(k, v)| (k, v)));' src/common.rs || r_s11c10p="$r_s11c10p self-relaunch-env-forwarding-lost"
grep -q 'Linux self-relaunch AppImage fallback' requirements.html || r_s11c10p="$r_s11c10p requirements-disposition-missing"
grep -q 'R-S11c-10p closes the Linux self-relaunch AppImage fallback' HARDENING_STATUS.md || r_s11c10p="$r_s11c10p hardening-ledger-missing"
self_relaunch_block=$(awk '/pub fn run_me_with_env/,/let result = cmd.args/' src/common.rs)
if echo "$self_relaunch_block" | grep -Eq 'APPDIR|AppRun|AppImage|appimage_cmd|std::env::var\("APPDIR"\)'; then
  r_s11c10p="$r_s11c10p stale-appimage-relaunch-branch"
fi
if grep -RInE 'APPDIR|AppRun|appimage_cmd|std::env::var\("APPDIR"\)' src/common.rs >/tmp/rd_verify_r_s11c10p.$$; then
  cat /tmp/rd_verify_r_s11c10p.$$
  rm -f /tmp/rd_verify_r_s11c10p.$$
  r_s11c10p="$r_s11c10p stale-appimage-runtime-relaunch"
else
  rm -f /tmp/rd_verify_r_s11c10p.$$
fi
if [ -n "$r_s11c10p" ]; then echo "  FAIL R-S11c-10p Linux self-relaunch AppImage fallback:$r_s11c10p"; rc=1; else
  echo "  ok  R-S11c-10p Linux self-relaunch uses current_exe only, with no APPDIR/AppRun fallback"; fi

echo "== (3b-iii-h10) Debian package lifecycle uses service-manager helpers (R-S11c-10j/R-T9) =="
r_s11c10j=
for maintscript in res/DEBIAN/preinst res/DEBIAN/postinst res/DEBIAN/prerm res/DEBIAN/postrm; do
  grep -qE '^#!/bin/sh$' "$maintscript" || r_s11c10j="$r_s11c10j ${maintscript##*/}:not-posix-sh"
  grep -qE '^set -e$' "$maintscript" || r_s11c10j="$r_s11c10j ${maintscript##*/}:not-set-e"
done
grep -q 'deb-systemd-invoke stop "$unit"' res/DEBIAN/preinst  || r_s11c10j="$r_s11c10j preinst:no-helper-stop"
grep -q '\[ -e "/etc/systemd/system/$unit" \] || \[ -e "/usr/lib/systemd/system/$unit" \] || \[ -e "/lib/systemd/system/$unit" \]' res/DEBIAN/preinst || r_s11c10j="$r_s11c10j preinst:no-old-unit-predicate"
grep -q 'deb-systemd-helper enable "$unit"' res/DEBIAN/postinst || r_s11c10j="$r_s11c10j postinst:no-helper-enable"
grep -q 'deb-systemd-invoke daemon-reload >/dev/null' res/DEBIAN/postinst || r_s11c10j="$r_s11c10j postinst:no-helper-daemon-reload"
grep -q 'deb-systemd-invoke start "$unit"' res/DEBIAN/postinst || r_s11c10j="$r_s11c10j postinst:no-helper-start"
grep -q 'deb-systemd-invoke stop "$unit"' res/DEBIAN/prerm     || r_s11c10j="$r_s11c10j prerm:no-helper-stop"
grep -q 'deb-systemd-helper disable "$unit"' res/DEBIAN/prerm  || r_s11c10j="$r_s11c10j prerm:no-helper-disable"
grep -q 'deb-systemd-invoke daemon-reload >/dev/null' res/DEBIAN/prerm || r_s11c10j="$r_s11c10j prerm:no-helper-daemon-reload"
grep -q 'deb-systemd-helper purge "$unit"' res/DEBIAN/postrm   || r_s11c10j="$r_s11c10j postrm:no-helper-purge"
grep -q 'pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk".to_owned());' libs/hbb_common/src/config.rs || r_s11c10j="$r_s11c10j config:stock-app-name-not-rustdesk"
grep -q 'directories_next::ProjectDirs::from("", &org, &APP_NAME.read().unwrap())' libs/hbb_common/src/config.rs || r_s11c10j="$r_s11c10j config:no-projectdirs-app-name-path"
grep -q 'rm -rf -- /root/.config/RustDesk /root/.config/rustdesk' res/DEBIAN/postrm || r_s11c10j="$r_s11c10j postrm:no-stock-root-config-purge"
if grep -q 'rm -rf /root/.config/rustdesk' res/DEBIAN/postrm; then
  r_s11c10j="$r_s11c10j postrm:lowercase-only-root-config-purge"
fi
grep -q 'init-system-helpers' build.py                         || r_s11c10j="$r_s11c10j deb-control:no-init-system-helpers-dep"
grep -qE '^KillMode=control-group$' res/rustdesk.service       || r_s11c10j="$r_s11c10j unit:not-control-group"
if grep -qE '^ExecStop=|pkill|KillMode=mixed' res/rustdesk.service; then
  r_s11c10j="$r_s11c10j unit:legacy-execstop-or-mixed-killmode"
fi
if grep -RInE 'INITSYS|/proc/1/exe|ps -ef|grep -E|awk|sed -i|service rustdesk|systemctl|--machine=' res/DEBIAN >/tmp/rd_verify_r_s11c10j_pkg.$$; then
  cat /tmp/rd_verify_r_s11c10j_pkg.$$
  r_s11c10j="$r_s11c10j maintscript:raw-service-discovery-or-systemctl"
fi
rm -f /tmp/rd_verify_r_s11c10j_pkg.$$
if grep -RInE '\|\|[[:space:]]*true|deb-systemd-(invoke|helper).*\|\|' res/DEBIAN >/tmp/rd_verify_r_s11c10j_mask.$$; then
  cat /tmp/rd_verify_r_s11c10j_mask.$$
  r_s11c10j="$r_s11c10j maintscript:masked-lifecycle-failure"
fi
rm -f /tmp/rd_verify_r_s11c10j_mask.$$
if grep -n 'os.system(' build.py | grep -v 'exit_code = os.system(cmd)' >/tmp/rd_verify_r_s11c10j_build_os_system.$$; then
  cat /tmp/rd_verify_r_s11c10j_build_os_system.$$
  r_s11c10j="$r_s11c10j build.py:unchecked-os-system"
fi
rm -f /tmp/rd_verify_r_s11c10j_build_os_system.$$
grep -q "system2('/bin/rm -rf tmpdeb')" build.py || r_s11c10j="$r_s11c10j build.py:no-clean-staging-root"
if grep -nE 'tmpdeb/usr/bin/rustdesk[^\n]*\|\|[[:space:]]*true|dpkg-deb -b tmpdeb rustdesk\.deb;[[:space:]]*/bin/rm -rf tmpdeb' build.py >/tmp/rd_verify_r_s11c10j_build_mask.$$; then
  cat /tmp/rd_verify_r_s11c10j_build_mask.$$
  r_s11c10j="$r_s11c10j build.py:masked-debian-build-failure"
fi
rm -f /tmp/rd_verify_r_s11c10j_build_mask.$$
grep -q 'const SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(8)' src/platform/linux.rs || r_s11c10j="$r_s11c10j linux:no-child-drain-timeout"
grep -q 'fn terminate_child(mut child: Child, label: &str)' src/platform/linux.rs || r_s11c10j="$r_s11c10j linux:no-child-terminate-helper"
grep -q 'hbb_common::libc::SIGTERM' src/platform/linux.rs || r_s11c10j="$r_s11c10j linux:no-child-sigterm"
grep -q 'wait_child_exit(&mut child, SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT, label)' src/platform/linux.rs || r_s11c10j="$r_s11c10j linux:no-bounded-child-wait"
linux_child_stop_block=$(
  awk '/fn stop_server/,/fn set_x11_env/' src/platform/linux.rs
  awk '/if should_kill/,/if let Some\(ps\) = server.as_mut/' src/platform/linux.rs
  awk '/if let Some\(ps\) = user_server.take/,/log::info!\("Exit"\)/' src/platform/linux.rs
)
if echo "$linux_child_stop_block" | grep -q 'allow_err!(ps.kill())'; then
  r_s11c10j="$r_s11c10j linux:managed-server-child-sigkill-regressed"
fi
if [ -n "$r_s11c10j" ]; then echo "  FAIL R-S11c-10j/R-T9 Debian package lifecycle/systemd stop:$r_s11c10j"; rc=1; else
  echo "  ok  R-S11c-10j/R-T9 Debian scripts use checked deb-systemd helpers with no masked lifecycle failures and purge the stock root RustDesk config tree; build.py stages checked control scripts; unit has cgroup-scoped SIGTERM/TimeoutStopSec with no pkill ExecStop; Linux supervisor SIGTERMs child servers before forced stop"; fi

# (3b-iv) R-S11/R-A6 config-write REACHABILITY tripwire (the audit's "positive AST reachability" gap):
# the is_option_can_save-BYPASSING config writes inside handle() are now only typed password
# operations: user-owned direct commit and Linux/Windows service-owned service commit. set_socks /
# set_id / set_salt and generic Config writes are absent, not denied. The main-channel policy table has no
# wildcard arm, so any NEW Data variant must be classified before the code compiles; this count catches a
# newly classified bypassing write that reaches Config unguarded on the main channel — the exact regression.
# set_options is EXCLUDED (it self-filters via is_option_can_save, R-S16, including trust-anchor/proxy
# credential option keys). Pin the count: a new bypassing write trips this, forcing the author to deny
# its Data variant in main_channel_admits.
hb_cfg_writes=$(awk '/^async fn handle\(/,/^}/' src/ipc.rs | grep -cE '\bConfig::set_socks|\bConfig::set_permanent_password|\bConfig::set_id|\bConfig::set_salt|\bConfig::set\(|\bConfig2::set\(')
# I-1 (2026-07-03): was 9; the id-write arm's set_key_confirmed(false) was excised with the dead
# rendezvous key_confirmed cluster (the setter no longer exists), 9->8.
# I-2 (2026-07-07): was 8; T2/b1c243c excised the local unlock-PIN subsystem end-to-end, removing the
# Config::set_unlock_pin write from handle() (and the --set-unlock-pin CLI arm), so the count is 8->7.
# I-3 (2026-07-08): was 7; R-S11b-1 removed the whole-config SyncConfig(Some) receiver write arm,
# deleting Config::set + Config2::set from handle(), so the count is 7->5.
# I-4 (2026-07-09): was 5; R-S11b-3c deleted Data::Socks and the generic Data::Config write arm,
# removing Config::set_socks, Config::set_id, and Config::set_salt from handle(), so the count is 5->1.
# I-5 (2026-07-09): was 1; R-S11b-2c/R-S11b-2d added the service-owned password commit arm with
# receiver-side service-owned + root/LocalSystem service-peer authority, so the count is 1->2.
if [ "$hb_cfg_writes" != "2" ]; then
  echo "  FAIL R-S11/R-A6: handle() now has $hb_cfg_writes is_option_can_save-bypassing config-writes (expected 2). A config-write was added/removed — make it a typed operation with explicit authority or keep it outside IPC, then update this count."; rc=1
else
  echo "  ok  R-S11/R-A6 handle() has only typed permanent-password config writes with explicit authority; generic Config writes, Socks IPC, and whole-config IPC are absent"
fi

# R-D8/R-S11b: the --password CLI remains a typed headless automation path, but path/root checks are not
# authority. It dispatches to the same owner-aware permanent-password operation as the GUI: user-owned servers
# accept the user-owned typed request; Linux installed-service mode goes through polkit + root-service commit;
# Windows installed-service mode goes through elevated pipe-client proof + LocalSystem service commit.
pw_arm=$(awk '/args\[0\] == "--password"/,/args\[0\] == "--get-id"/' src/core_main.rs | grep -vE '^[[:space:]]*//')
if echo "$pw_arm" | grep -q 'set_permanent_password' && ! echo "$pw_arm" | grep -q 'is_root' && ! echo "$pw_arm" | grep -q 'is_installed'; then
  echo "  ok  R-D8/R-S11b --password uses the owner-aware typed password operation, not root-gated or install-path-gated"
else
  echo "  FAIL R-D8/R-S11b: the --password arm is missing set_permanent_password or still uses root/install-path authority"; rc=1
fi

# (3c) File-transfer write-path safety (R-S8/R-A5): the receive-write opens are NO-FOLLOW
# (open_recv_write_no_follow / O_NOFOLLOW) so a local symlink swapped in at the target after the
# path-validation fails the open rather than redirecting root's write (the §4.3 symlink TOCTOU).
# These hbb_common fs tests were previously UN-RUNNABLE on the pinned 1.75 (a dead webrtc dev-dep
# pulled sdp/webrtc-util which need a newer rustc) — now runnable after that excision (R-SV4).
echo "== (3c) file-transfer no-follow write + path-traversal tests (R-S8/R-A5) =="
"${RUN[@]}" cargo test -p hbb_common --lib fs::tests --color never

# (3c-i) IPC service-path sharing (R-S11a / R-X13): the `_service` cross-user socket path MUST resolve
# the SAME under root and the active user (shared `-service/` parent dir) so the user `--server`/UI
# process can reach the root service, while non-service channels stay per-uid. After R-X13 collapsed
# is_service_ipc_postfix to `_service`-only (the `_uinput_*` channels excised with the uinput module),
# this guards that the surviving service channel still shares correctly. (Classification is separately
# gated by config_it/ipc_socket_mode.rs; this is the path-resolution consequence.)
echo "== (3c-i) IPC _service path-sharing across uids (R-S11a/R-X13) =="
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_service_ipc_path_is_shared_across_uids --color never

# (3c-i-b) Permanent-password PRS credential durability (R-S9): config.password (the storage
# envelope) and config.password_prs (the live CPace PRS) BOTH encode the same 32 PRS bytes, so a
# credential snapshot carrying only `storage` rebuilds password_prs from it. This keeps a set/rotate
# durable: password_prs stays in step with `storage`, so the headless --server reads a live PRS and
# listens (R-S9) with the current password on restart. This pins the reconstruction:
# base64(decode(storage)) == derive_cpace_prs(password), and the rebuilt at-rest PRS decrypts back to it.
# Its complement — re-syncing an already-consistent credential is a NO-OP (idempotent, so no needless
# config rewrite), and the "unchanged" decision compares the DECRYPTED PRS, never the ciphertext bytes
# (symmetric_crypt uses a random nonce, so those bytes are unstable) — is pinned by the third test.
echo "== (3c-i-b) permanent-password PRS credential durability (R-S9) =="
"${RUN[@]}" cargo test -p hbb_common --lib config::permanent_password::tests::prs_storage_reconstructs_from_password_storage --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::sync_rebuilds_password_prs_from_storage --color never
"${RUN[@]}" cargo test -p hbb_common --lib config::tests::test_permanent_password_sync_treats_same_encrypted_hash_as_unchanged --color never

# (3c-i-c) At-rest config-load robustness (R-S9/R-P1 residuals — data-loss + coherence, all
# fail-closed at the CPace boundary). Four defensive invariants on the shared at-rest state
# machine (config.rs), each secure-by-assertion:
#   F1  a PRESENT-but-corrupt/empty config file is PRESERVED for recovery, never silently reset
#       and overwritten by a fresh default that would discard the key_pair/permanent credential
#       (load_path distinguishes NotFound=first-run from unparseable=corruption; Config::load
#       refuses to store over a present file it read as default);
#   F2  the "a permanent password is set" signal (has_permanent_password -> is_permanent_password_set,
#       the IPC status, peer_has_password) keys on the LIVE PRS the auth boundary actually consumes,
#       so a password-set/prs-empty half-state or an undecryptable 01 blob no longer reports "set"
#       on a box that refuses every connection;
#   F3  a coincident store() during a TRANSIENT machine-UUID read failure preserves a well-formed
#       legacy 00 credential (clears only a definitively-malformed one), never wiping a
#       possibly-valid password on an environment blip;
#   F4  a current-format 01 credential is stored verbatim, never spuriously re-wrapped in a 00 envelope.
# Count-asserted (exactly 9) so a renamed/removed regression test fails the gate instead of
# passing silently on a zero-match cargo filter.
echo "== (3c-i-c) at-rest config-load robustness (F1 preserve-corrupt / F2 prs-coherent set-signal / F3 transient-safe / F4 no double-wrap) =="
atrest_out=$("${RUN[@]}" cargo test -p hbb_common --lib --color never -- \
  config::tests::test_load_path_first_run_returns_default_without_creating_file \
  config::tests::test_load_path_valid_file_loads_unchanged \
  config::tests::test_load_path_present_but_corrupt_is_preserved_not_overwritten \
  config::tests::test_has_permanent_password_reflects_live_prs_not_stale_storage \
  config::tests::test_validate_or_decrypt_preserves_undecryptable_wellformed_00_storage \
  config::tests::test_validate_or_decrypt_clears_malformed_00_storage \
  config::tests::test_prepare_config_for_store_preserves_transient_00_credential \
  config::tests::test_prepare_config_for_store_clears_malformed_00_credential \
  config::tests::test_store_does_not_double_wrap_current_format_credential 2>&1) || true
echo "$atrest_out" | grep -E 'test result:' || true
# This gate runs in the pre-`rc=0` phase (line ~308 resets rc), so it enforces by aborting
# under `set -e` on failure — exactly like the (3c-i-b) direct cargo-test gate above — rather
# than via the rc accumulator that only the later static-grep gates use.
if echo "$atrest_out" | grep -qE 'test result: ok\. 9 passed; 0 failed'; then
  echo "  ok  F1/F2/F3/F4 at-rest robustness (9 regression tests: preserve-corrupt+not-overwrite, prs-coherent set-signal, transient-safe/malformed-clear, no 01 double-wrap)"
else
  echo "  FAIL F1/F2/F3/F4 at-rest robustness: expected exactly 9 passed / 0 failed (a regression test was renamed/removed or a fix regressed)"
  echo "$atrest_out" | tail -20
  exit 1
fi

# (3c-ii-a) Viewer peer media admission bounds (Appendix C #2b/R-T0): a
# hostile peer controls VideoFrame.display and keyframe/audio cadence, so the
# viewer must cap display-thread creation and use bounded media queues.
echo "== (3c-ii-a) viewer peer media display/thread + queue bounds (Appendix C #2b/R-T0) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config client::tests::media_data_queue_is_bounded --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config client::tests::native_opus_format_admission_pins_first_format --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config client::tests::native_video_unsupported_guard_blocks_marked_format --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config client::tests::peer_info_does_not_choose_saved_keyboard_mode --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config client::tests::peer_info_does_not_rewrite_saved_keyboard_mode --color never
"${RUN[@]}" cargo test --lib --features linux-pkg-config client::io_loop::tests --color never
"${RUN[@]}" cargo test -p scrap --lib --features linux-pkg-config common::codec::tests::encoder_negotiation --color never
grep -qF 'native_video_format_locally_unsupported(&lc.mark_unsupported, format)' src/client.rs ||
  { echo "  FAIL Appendix C #2b/R-T0: video receive loop must drop locally-unsupported peer codecs before recreating a native decoder worker"; rc=1; }
grep -qF 'local decoder is marked unsupported' src/client.rs ||
  { echo "  FAIL Appendix C #2b/R-T0: missing locally-unsupported video-frame drop marker"; rc=1; }
grep -qF 'dropping repeated peer Opus format without recreating native decoder' src/client.rs ||
  { echo "  FAIL Appendix C #2b/R-T0: viewer audio handler must not recreate native Opus decoders on repeated peer AudioFormat"; rc=1; }
grep -qF 'dropping repeated peer Opus format without recreating controlled audio thread' src/server/connection.rs ||
  { echo "  FAIL Appendix C #2b/R-T0: controlled side must not recreate audio decoder threads on repeated peer AudioFormat"; rc=1; }
grep -qF 'audio_decode_failed = true' src/client.rs ||
  { echo "  FAIL Appendix C #2b/R-T0: native Opus decode failure must be sticky for the audio thread"; rc=1; }

# (3c-ii-b) Peer UI text admission (R-T0): a password-correct hostile peer can
# send chat/messages/notification details repeatedly after keying. Bound text
# before UI/CM handoff and rate-gate the repeated UI event classes.
echo "== (3c-ii-b) peer UI text length/rate admission (R-T0) =="
"${RUN[@]}" cargo test --lib --features linux-pkg-config peer_text::tests --color never

# (3c-iii-a) macOS paste parent filesystem use must re-normalize and contain
# hostile-peer FILEDESCRIPTOR names after the worker parse, before mkdir/temp
# download/final rename state touches the parent process filesystem.
echo "== (3c-iii-a) unix file-copy descriptor relative-name sanitizer (Appendix C #2b) =="
"${RUN[@]}" cargo test -p clipboard --features unix-file-copy-paste --lib relative_name_sanitizer_rejects_escape_paths --color never

# (3c-iii-b) Linux FUSE clipboard mount points live under /tmp, but must not
# adopt symlinked/foreign-owned temp state or recreate upstream's 0777 chmod.
echo "== (3c-iii-b) Linux FUSE clipboard mount-point component validation (R-S11a/R-S8) =="
"${RUN[@]}" cargo test -p clipboard --features unix-file-copy-paste --lib fuse_mount_component --color never

# (3c-iii-c) Linux FUSE FileContentsResponse delivery is peer-driven after
# PAKE. Each response is byte-capped before protobuf conversion, but the local
# handoff queue must also be bounded so many capped blobs cannot accumulate.
echo "== (3c-iii-c) Linux FUSE file-content response queue bound (R-T0/R-S7) =="
"${RUN[@]}" cargo test -p clipboard --features unix-file-copy-paste --lib fuse_response_queue --color never

# (3c-iii-d) the CLIPRDR file-contents SERVE read clamps the peer-requested length to the file's
# remaining bytes via min() — NOT `offset + length > file.size`, which WRAPS for a peer cb_requested=-1
# (i32 -> length=u64::MAX), selecting `length` and over-allocating vec![0u8; length] (§20 DoS).
echo "== (3c-iii-d) CLIPRDR file-contents read_size overflow guard (§20) =="
"${RUN[@]}" cargo test -p clipboard --features unix-file-copy-paste --lib clamp_file_read_size --color never

echo "== (4) main crate compile check (hardening is UNCONDITIONAL — one binary, R-R2b) =="
"${RUN[@]}" cargo check --features linux-pkg-config --color never

# (4a) the SHIPPED release ALSO enables unix-file-copy-paste (build.py --flutter --unix-file-copy-paste,
# flutter-build.yml) — the clipboard-FILE Cliprdr arm (connection.rs, R-A2 capability gate at (5)) is
# compiled ONLY under that feature, so (4) above never compiles it. Compile-check it too so the arm + its
# can_sub_file_clipboard_service() gate stay buildable (this feature pulls the FUSE clipboard-file path).
echo "== (4a) unix-file-copy-paste feature compile check (the shipped clipboard-file arm) =="
"${RUN[@]}" cargo check --features linux-pkg-config,unix-file-copy-paste --color never

echo "== (5) R-A6 forbidden-token greps =="
# Greps run over the Rust source only, never requirements.html / the status docs
# (which legitimately name the tokens). A non-comment hit is a failure.
ra6_clean() { # token, human label
  local tok="$1" label="$2" hits
  hits=$(grep -RInE "$tok" src libs --include='*.rs' 2>/dev/null \
           | grep -v '//' | grep -v 'libs/pake' | grep -v 'libs/cpace_it' \
           | grep -v 'bridge_generated' || true)  # bridge_generated.rs(.io.rs) are gitignored FRB
                                                   # output regenerated from flutter_ffi.rs; a gate
                                                   # validates source, never a derived artifact.
  if [ -n "$hits" ]; then
    echo "  FAIL R-A6: '$label' must be absent but is present:"; echo "$hits" | sed 's/^/      /'
    return 1
  fi
  echo "  ok  $label absent"
}

# R1(a) DoS hardening (regression gate): the responder's FIRST pre-key step (WAIT_1) — the ONLY recv an
# unauthenticated internet attacker drives — MUST use a SHORTER deadline (5s) than the 18s of later steps,
# so a silent-hold flood costs ~3.6x less per R-T1 handshake permit. A real viewer's step ① is immediate,
# so 5s never rejects it. Guards against a silent revert to the full 18s.
r1a=
grep -qF 'const HANDSHAKE_FIRST_STEP_TIMEOUT_MS: u64 = 5_000;' libs/hbb_common/src/cpace.rs || r1a="$r1a no-5s-const"
grep -qF 'recv_cpace(stream, HANDSHAKE_FIRST_STEP_TIMEOUT_MS)' libs/hbb_common/src/cpace.rs   || r1a="$r1a WAIT_1-not-short"
if [ -n "$r1a" ]; then echo "  FAIL R1(a) pre-key first-step short deadline:$r1a"; rc=1; else
  echo "  ok  R1(a) responder WAIT_1 uses the 5s first-step deadline (vs 18s later) — pre-key silent-hold DoS hardening"; fi

# fork versioning (release identity) gate — docs/VERSIONING.md. The single source of truth is the
# FORK_VERSION file; assert (a) it exists + is well-formed + its base equals Cargo.toml's version (no
# drift between the fork release string and the app/wire/package version), (b) CHANGELOG.md's top
# '## <version>' entry names it, (c) the binary can report it (build.rs emits RUSTDESK_FORK_VERSION and
# --fork-version prints it; --version stays the numeric app version), and (d) the scheme doc exists.
ver_gate=
fork_ver="$(fork_version 2>/dev/null)" || ver_gate="$ver_gate FORK_VERSION-missing-or-malformed"
[ -f CHANGELOG.md ] || ver_gate="$ver_gate CHANGELOG.md-missing"
if [ -n "$fork_ver" ] && [ -f CHANGELOG.md ]; then
  changelog_top="$(awk '/^## /{print; exit}' CHANGELOG.md 2>/dev/null)"
  case "$changelog_top" in
    *"$fork_ver"*) : ;;
    *) ver_gate="$ver_gate CHANGELOG-top-entry-does-not-name-$fork_ver" ;;
  esac
fi
grep -qF 'RUSTDESK_FORK_VERSION' build.rs           || ver_gate="$ver_gate build.rs-no-fork-version-env"
grep -qF 'RUSTDESK_FORK_VERSION' src/core_main.rs   || ver_gate="$ver_gate --fork-version-not-wired"
# res/msi/preprocess.py runs `rustdesk --version` and needs a NUMERIC version embedded in the binary
# (it becomes the WiX ProductVersion); so --version MUST print crate::VERSION verbatim (the app
# version), never the fork string. The MSI packaging depends on this numeric --version; the fork
# identity lives on the separate `--fork-version` so the two never collide.
grep -qF 'println!("{}", crate::VERSION);' src/core_main.rs || ver_gate="$ver_gate --version-not-numeric"
[ -f docs/VERSIONING.md ]                           || ver_gate="$ver_gate docs/VERSIONING.md-missing"
if [ -n "$ver_gate" ]; then
  echo "  FAIL fork-versioning (docs/VERSIONING.md):$ver_gate"; rc=1
else
  echo "  ok  fork versioning: FORK_VERSION=$fork_ver (base==Cargo, CHANGELOG names it, --fork-version wired, --version numeric, docs present)"
fi

# Direct-listener invariant gates: assert the bind-retry + runtime-password-recheck invariants stay
# structurally in place so a future edit cannot silently revert them (the process-scoped socket surface
# has the R-A4 gate above; the PRS sync durability has a config.rs behavioral test).
la_gate=
# The direct-listener bind-error arm RETRIES with a bounded backoff, and the pinned-port
# constant means it always rebinds the same v4 address after a transient failure.
grep -qF 'bind_err_streak' src/direct_service.rs || la_gate="$la_gate no-bind-retry-counter"
grep -qF 'retrying in' src/direct_service.rs      || la_gate="$la_gate no-bounded-bind-retry"
# The accept loop re-checks the permanent password at RUNTIME and drops the listener if it
# was cleared — so "listen on 0.0.0.0 iff a password is set" holds at runtime, not only at startup.
grep -qF 'permanent password cleared at runtime — dropping the direct listener' src/direct_service.rs \
  || la_gate="$la_gate no-runtime-password-recheck"
if [ -n "$la_gate" ]; then
  echo "  FAIL listener-audit regression:$la_gate"; rc=1
else
  echo "  ok  direct-listener invariant gates present (bounded bind-retry + runtime password re-check)"
fi

# Completed excisions — these MUST stay at zero (hard gate).
ra6_clean 'crate::updater|mod updater|"download-new-version"|"update-me"' 'R-X1 auto-updater RCE'    || rc=1
# R-X1 / R-SV2 / R-A6 — the self-updater FUNCTION surface the string-key gate above missed: the
# platform fetch-and-run re-install (macOS update_me/update_from_dmg/update_to/extract_update_dmg,
# Windows update_me/update_to/update_me_msi) + the main_update_me FFI that drove them. R-A6 names
# update_me/update_from_dmg/extract_update_dmg in its Apple-cfg pass; all must be absent on EVERY
# source (these clusters are cfg(macos)/cfg(windows), invisible to the Linux cargo check below).
ra6_clean 'fn update_me\b|main_update_me|update_from_dmg|extract_update_dmg|update_me_msi|fn update_to\b' 'R-X1 self-updater fns (macOS DMG / Windows MSI / FFI)' || rc=1
# R-B6/R-R2 (§19): the legacy Sciter UI is DELETED, not merely cfg-gated out of the shipped (--flutter)
# artifacts — R-R2's "MUST delete the Sciter fork" + the §5 Excise bar ("cannot be re-enabled") outweigh
# §19's lenient cfg-gated parenthetical. Flutter is the sole front-end. Previously ~9 gates here each
# checked an individual sciter .tis control was excised; the whole stack is now gone, so this ONE gate
# asserts the deletion and the per-control .tis gates are retired with it (their flutter/.rs halves stay).
r_b6=
[ -e src/ui.rs ]                && r_b6="$r_b6 src/ui.rs-present"
[ -d src/ui ]                   && r_b6="$r_b6 src/ui/.tis-tree-present"
[ -e res/inline-sciter.py ]     && r_b6="$r_b6 inline-sciter.py-present"
[ -e src/platform/delegate.rs ] && r_b6="$r_b6 macos-sciter-delegate-present"
grep -qE '^\s*sciter-rs\s*=' Cargo.toml  && r_b6="$r_b6 sciter-rs-dep-in-Cargo.toml"
grep -q 'name = "sciter-rs"' Cargo.lock && r_b6="$r_b6 sciter-rs-in-Cargo.lock"
grep -qE '^\s*pub mod ui;' src/lib.rs   && r_b6="$r_b6 mod-ui-still-declared"
{ grep -rInE 'sciter::|crate::ui::' src/ libs/ --include='*.rs' 2>/dev/null | grep -v '//' | grep -q . ; } && r_b6="$r_b6 sciter/mod-ui-rust-ref-remains"
if [ -n "$r_b6" ]; then echo "  FAIL R-B6/R-R2 Sciter UI not fully deleted:$r_b6"; rc=1; else
  echo "  ok  R-B6/R-R2 Sciter UI fully DELETED (src/ui.rs + src/ui/*.tis + res/inline-sciter.py + macOS delegate + sciter-rs dep/lock + mod ui + all sciter::/crate::ui:: refs gone — Flutter is the sole front-end)"
fi
# R-X1/R-SV3/§8: the self-update-CHECK backend is now EXCISED (previously only NEUTERED). With the
# UpdateMe/UpgradeMe widgets gone (their sole consumers), the whole chain is dead and removed "not
# disabled": the SOFTWARE_UPDATE_URL static + check_software_update() (which only set it empty) + the
# version/store-path helpers (get_new_version / get_software_store_path / get_software_ext /
# get_software_update_url) + the flutter FFIs (main_get_software_update_url / main_get_new_version) +
# the index.tis software_update_url var+poll. (The fork ships SHA-pinned releases, R-B2; never checks.)
r_sv3_upd=
{ grep -rE 'SOFTWARE_UPDATE_URL|fn check_software_update|fn main_get_software_update_url|fn main_get_new_version|fn get_software_store_path' --include='*.rs' src libs 2>/dev/null | grep -v '//' | grep -q . ; } && r_sv3_upd="$r_sv3_upd rs-chain"
if [ -n "$r_sv3_upd" ]; then
  echo "  FAIL R-X1/R-SV3: self-update-check chain still present:$r_sv3_upd"; rc=1
else
  echo "  ok  R-X1/R-SV3 self-update-check chain excised (SOFTWARE_UPDATE_URL + check_software_update + version/store-path helpers + flutter FFIs; the sciter var is gone with the Sciter UI, R-B6)"
fi
ra6_clean 'plugin_framework|install_plugin_with_url|"--plugin-install"'    'R-X2 native-plugin loader' || rc=1
# R-X2 (extended, post-excision lock-in): the plugin framework is fully REMOVED, not merely the
# loader token above. The proto wire messages (2f201b6), the 13 flutter_ffi no-op stubs, and the
# 9-file flutter/lib/plugin/ Dart tree are all gone. Assert they stay absent. (PrvOnFailedPlugin is
# a LIVE back_notification::PrivacyModeState, NOT the framework — deliberately not matched here.)
rx2_bad=
[ -n "$(find flutter/lib/plugin flutter/lib/web/plugin -name '*.dart' 2>/dev/null)" ] && rx2_bad="$rx2_bad dart-plugin-tree"
grep -rqE 'pub fn plugin_' src/flutter_ffi.rs && rx2_bad="$rx2_bad flutter_ffi-stubs"
grep -qE 'message PluginRequest|message PluginFailure' libs/hbb_common/protos/message.proto && rx2_bad="$rx2_bad proto-plugin-messages"
if [ -n "$rx2_bad" ]; then
  echo "  FAIL R-X2: plugin framework residue (MUST be fully excised):$rx2_bad"; rc=1
else
  echo "  ok  R-X2 plugin framework fully excised (no Dart tree, no flutter_ffi plugin_* stubs, no proto Plugin messages)"
fi
# GD (web-stub orphan sweep, §19 no-leftovers): flutter/lib/web/bridge.dart is the WEB build's
# hand-maintained FFI shim that mirrors the generated RustdeskImpl. After the excisions it carried inert
# stubs whose Rust flutter_ffi.rs backend is GONE (confirmed absent from the freshly-regenerated
# generated_bridge.dart) and which had 0 callers tree-wide -- swept here. Assert they stay absent from the
# web shim so a reintroduced stub (or a caller of one) is caught; the earlier R-X1/R-SV3/R-X2 gates check
# the Rust/flutter_ffi side, this one covers the web-only shim they did not reach. Mapping:
#   R-X1/R-SV2 self-updater FFI     : mainUpdateMe
#   R-X1/R-SV3 self-update-CHECK    : mainGetSoftwareUpdateUrl, mainGetNewVersion
#   R-R2b hwcodec/vram/ffmpeg-HW    : mainSupportedHwdecodings   (only ever reported {} -> dead)
#   R-X2 native-plugin loader       : plugin{Event,RegisterEventStream,GetSessionOption,SetSessionOption,
#                                     GetSharedOption,SetSharedOption,Reload,Enable,IsEnabled,SyncUi,
#                                     ListReload,Install}
#   R-X7 2FA / trusted-device       : mainGetTrustedDevices, mainRemoveTrustedDevices, mainClearTrustedDevices
#   R-X7 temporary-password         : mainGetTemporaryPassword, mainUpdateTemporaryPassword
#   rendezvous change-id / status   : mainChangeId, mainGetAsyncStatus
#   pre-existing web-only stubs     : mainGetDefaultSoundInput, mainLoadRecentPeersSync, sessionSelectFiles
#                                     (never an FFI fn upstream either; swept for completeness)
gd_web='flutter/lib/web/bridge.dart'
gd_tok='mainUpdateMe|mainGetSoftwareUpdateUrl|mainGetNewVersion|mainSupportedHwdecodings|mainGetTrustedDevices|mainRemoveTrustedDevices|mainClearTrustedDevices|mainGetTemporaryPassword|mainUpdateTemporaryPassword|mainChangeId|mainGetAsyncStatus|mainGetDefaultSoundInput|mainLoadRecentPeersSync|sessionSelectFiles|pluginEvent|pluginRegisterEventStream|pluginGetSessionOption|pluginSetSessionOption|pluginGetSharedOption|pluginSetSharedOption|pluginReload|pluginEnable|pluginIsEnabled|pluginSyncUi|pluginListReload|pluginInstall'
if [ -f "$gd_web" ]; then
  # match a declaration or call (name immediately followed by "("), skipping comment lines
  gd_hits=$(grep -nE "\b(${gd_tok})[[:space:]]*\(" "$gd_web" 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*(//|\*)' || true)
  if [ -n "$gd_hits" ]; then
    echo "  FAIL GD web-stub sweep: an excised-backend/no-FFI stub reappeared in web/bridge.dart:"; echo "$gd_hits" | sed 's/^/      /'; rc=1
  else
    echo "  ok  GD web/bridge.dart orphan-stub sweep holds (26 excised-backend/no-FFI stubs absent: self-updater+update-check R-X1/R-SV3, hwdecodings R-R2b, 12 plugin* R-X2, 2FA+trusted-device+temp-password R-X7, change-id/async-status, 3 pre-existing web-only)"
  fi
fi
ra6_clean '"--import-config"|"--remove"|fn import_config'                  'R-X4 trust-anchor CLI gadgets' || rc=1
# R-X5: the LAN-discovery UDP listener/querier (the 0.0.0.0:RENDEZVOUS_PORT+3=21119 responder that
# disclosed MAC/ID/hostname/active-username/platform, removed in 322aebb) MUST stay absent — §8's
# "removed not disabled" bar + R-A4's zero-UDP runtime check.
ra6_clean 'start_lan_listening|spawn_wait_responses|handle_received_peers|RENDEZVOUS_PORT *\+ *3' 'R-X5 LAN-discovery listener/querier/bind' || rc=1
# R-X5 / R-D7a (full cross-harness excision): the lan module + its UI + config store are now ENTIRELY
# gone — `mod lan` (the discover()/send_wol() no-op stubs), the flutter FFIs (62cb593), the sciter
# Discovered-tab (ab.tis) + ui.rs trait/decls, ui_interface::get_lan_peers/remove_discovered, and the
# config::LanPeers/DiscoveryPeer `_lan_peers` store + deserialize_vec_discoverypeer. None may return.
ra6_clean 'crate::lan::|mod lan;|LanPeers|DiscoveryPeer|fn get_lan_peers|fn remove_discovered|deserialize_vec_discoverypeer' 'R-X5 lan module/UI/config cluster fully excised' || rc=1
# R-SV4(c)/R-SV10 / §18: Wake-on-LAN is DROPPED. The inherited lan::send_wol broadcast WoL magic
# packets (UDP) over EVERY LAN interface (`wol::send_wol`, iterating default_net interfaces × the
# stored LanPeer MACs) — a live viewer-side LAN egress at odds with the direct-IP-only/sovereign
# posture (R-SV5). The whole send_wol path (and lan.rs itself) is now excised; assert the
# wol::send_wol broadcast call stays absent.
ra6_clean 'wol::send_wol' 'R-SV4(c) Wake-on-LAN UDP-broadcast egress (lan::send_wol)' || rc=1
# R-SV4/R-D6 / §18: the nip.io NAT64 helper (query_nip_io — a DNS lookup to the external *.nip.io
# wildcard resolver) and its ipv4_to_ipv6 string builder are EXCISED. Their only production reach was
# connect_tcp_local's IPv6-local+IPv4-target branch, dead because every viewer connect passes
# local=None (client.rs) — so the whole inert NAT64 chain (helpers + IsResolvedSocketAddr scaffold) is
# removed at the source rather than gated. Assert the nip.io DNS-egress helper stays absent.
ra6_clean 'query_nip_io|fn ipv4_to_ipv6|\.nip\.io' 'R-SV4/R-D6 nip.io NAT64 DNS-egress residue' || rc=1
# R-SV1 / R-X1 / §18: the hbbs_http::downloader reqwest-GET fetch-to-buffer subsystem is EXCISED. It was
# orphaned by the R-X1 updater excision — its sole starter (the `download-new-version` Flutter key +
# updater::get_download_file_from_url) was already gone, leaving `download_file` caller-less and the
# `download-data-`/`remove-downloader`/`cancel-downloader` Dart keys unreachable. Removed wholesale (the
# module file + the flutter_ffi key handlers) so the binary cannot perform that GET — the code is gone.
if [ -e src/hbbs_http/downloader.rs ]; then
  echo "  FAIL R-SV1: the excised hbbs_http/downloader.rs reappeared"; rc=1
else
  echo "  ok  R-SV1 hbbs_http/downloader.rs module file absent"
fi
ra6_clean 'hbbs_http::downloader|mod downloader|fn do_download' 'R-SV1 downloader call-path/module/worker' || rc=1
# R-SV1 / R-D6 / §18: peer-avatar remote-image egress is CLOSED. A CPace-authenticated peer's
# LoginRequest.avatar (src/server/connection.rs -> CM Client) is rendered by buildAvatarWidget; its
# former http(s) branch issued an unconditioned remote GET (Flutter NetworkImage) to a peer-NAMED
# host — a first-party, attacker-influenceable outbound fetch at odds with "dial nobody / defensible
# with no firewall" (deanonymization / SSRF-lite). The network branch is removed; only inline
# `data:image/` (base64, no egress) renders. NetworkImage is the sole such sink, so we gate it to zero
# across the whole flutter UI (not just common.dart) — any reintroduction anywhere is an egress vector.
if grep -RIn 'NetworkImage' flutter/lib --include='*.dart' >/dev/null 2>&1; then
  echo "  FAIL R-SV1: NetworkImage (peer-avatar / remote-image egress) present in flutter/lib:"
  grep -RIn 'NetworkImage' flutter/lib --include='*.dart' | sed 's/^/      /'; rc=1
else
  echo "  ok  R-SV1 no NetworkImage egress in flutter UI (peer avatar renders inline data: only)"
fi
if grep -q "startsWith('data:image/')" flutter/lib/common.dart && grep -q 'Widget? buildAvatarWidget' flutter/lib/common.dart; then
  echo "  ok  R-SV1 buildAvatarWidget still renders inline data:image/ avatars (not silently deleted)"
else
  echo "  FAIL R-SV1: buildAvatarWidget/data:image inline handling missing (unexpected regression)"; rc=1
fi
# R-SV1 / R-D6 / §18: peer-fed msgbox text must NOT be auto-linkified into a tappable launchUrl.
# A peer's MessageBox.text / LoginResponse.error reaches createDialogContent (common.dart); its former
# http(s) linkifier wrapped any URL in a TapGestureRecognizer -> launchUrl(peer_url) — a one-tap outbound
# GET to a peer-NAMED host (deanonymization/phishing) that BYPASSED the HELPER_URL allowlist which
# already blanks MessageBox.link for exactly this reason. Fixed: createDialogContent renders plain
# SelectableText. (launchUrl itself has legit LOCAL uses — Uri.file folder-open, the gated JumpLink — so
# we gate the DIALOG-TEXT URL-linkifier regex, not launchUrl globally.)
if grep -RIn -F 'https?://[^' flutter/lib --include='*.dart' >/dev/null 2>&1; then
  echo "  FAIL R-SV1: dialog-text URL linkifier (peer text -> tappable launchUrl) present in flutter/lib:"
  grep -RIn -F 'https?://[^' flutter/lib --include='*.dart' | sed 's/^/      /'; rc=1
else
  echo "  ok  R-SV1 no dialog-text URL linkifier (peer msgbox text stays plain, never one-tap launchUrl)"
fi
if grep -A12 'Widget createDialogContent' flutter/lib/common.dart | grep -q 'return SelectableText(text'; then
  echo "  ok  R-SV1 createDialogContent renders plain SelectableText (peer msgbox text not linkified)"
else
  echo "  FAIL R-SV1: createDialogContent is no longer the plain-text renderer (unexpected)"; rc=1
fi
# R-A6 / R-P5 (host-identity removal, ex-R-S17): the host-key pin subsystem is RETIRED. The spec now
# derives the CPace PRS from the password alone (fixed salt, R-P1), so there is no long-term per-box
# identity key, no host-proof, and no local pin of any kind (R-P5). These ABSENCE greps REPLACE the old
# R-S17 presence-gates (the set_pinned_pk-confinement gate here, the viewer host-proof-verify gate, the
# host-pin-dialog gate, and the --get-fingerprint bootstrap gate — all now deletions). Each token MUST
# return zero non-comment hits in the shipped Rust tree (ra6_clean skips //-comments, libs/pake,
# libs/cpace_it, and the gitignored bridge_generated FRB shim).
ra6_clean 'HostIdentity|build_host_identity|verify_host_identity'                       'R-A6/R-P5 HostIdentity host-proof (frame + build/verify)' || rc=1
ra6_clean 'HOST_PROOF_DSI|rustdesk-fork/host-proof|fn host_proof_message'               'R-A6/R-P5 host-proof DSI + signable message' || rc=1
ra6_clean '"--get-fingerprint"|"--pin-host"|"--forget-host"|"--list-known-hosts"'       'R-A6/R-P5 host-key bootstrap/pin CLI arms' || rc=1
ra6_clean 'mod host_pin|host_pin::|set_pinned_pk|get_pinned_pk|remove_pinned|list_pinned' 'R-A6/R-P5 host_pin pin store + API' || rc=1
ra6_clean 'session_pin_host|pin_host_by_fingerprint|set_pin_host_and_reconnect|pending_host_pk' 'R-A6/R-P5 viewer pin FFI + pending-key stash' || rc=1
ra6_clean 'main_get_fingerprint|main_list_pinned_hosts|main_forget_pinned_host|fn get_fingerprint|fn set_fingerprint' 'R-A6/R-P5 fingerprint/pin main-FFI + surfacing' || rc=1
ra6_clean 'known_hosts|commit_key_pair'                                                  'R-A6/R-P5 known_hosts store + dead commit_key_pair' || rc=1
# R-A6 / R-P5 (Dart side): the host-identity / fingerprint / known-hosts UI is fully excised from
# flutter/lib. generated_bridge.dart is the gitignored FRB shim (regenerated from flutter_ffi.rs), so
# it is excluded exactly as ra6_clean excludes the Rust bridge_generated.
ra6_dart_tok='FingerprintState|hostNotPinnedDialog|hostMismatchDialog|host-not-pinned-prompt|host-mismatch-prompt|KnownHostsManager|_KnownHostsPage|onCopyFingerprint|sessionPinHost|mainGetFingerprint|mainListPinnedHosts|mainForgetPinnedHost'
ra6_dart_hits=$(grep -RInE "$ra6_dart_tok" flutter/lib --include='*.dart' 2>/dev/null | grep -v 'generated_bridge.dart' || true)
if [ -n "$ra6_dart_hits" ]; then
  echo "  FAIL R-A6/R-P5: host-identity/fingerprint/known-hosts Dart UI must be absent but is present:"; echo "$ra6_dart_hits" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-A6/R-P5 host-identity/fingerprint/known-hosts Dart UI excised (flutter/lib, generated_bridge excluded)"
fi
# R-A6 / BR-13 (native-driver minimization): the remote-printer capability is EXCISED. A print driver
# drives the same native display-DRIVER API class the fork minimizes — the rationale that pins
# enable-virtual-display OFF (R-D8 / Appendix C #2b) — it is Windows-only + inert on the §17 Linux box,
# and its "Install {App} Printer" action errored (no driver payload shipped). Removed end-to-end: the
# `remote_printer` crate + workspace member, `printer_service` + `on_printer_data`, the
# `enable-remote-printer` pin + option consts, the install/print FFI, the Dart Printer settings tab, the
# MSI `RemotePrinter` custom action + `RustDeskPrinterDriver` driver payload, and the proto
# `FileType.Printer` / `ControlPermissions.remote_printer`. These tokens MUST stay absent.
ra6_clean 'remote_printer|printer_service|enable-remote-printer|install-printer|is-support-printer-driver|is_support_remote_print|on_printer_data|session_printer_response|main_get_printer_names' 'R-A6/BR-13 remote-printer capability (Rust: crate/service/FFI/config/proto)' || rc=1
# The Dart UI + MSI/WiX/C++ side (ra6_clean is Rust-only): the Printer settings tab + install-printer
# FFI callers (flutter/lib; generated_bridge.dart is the regenerated FRB shim, excluded), and the WiX
# RemotePrinter custom action + RustDeskPrinterDriver driver-package payload (res/). Comment lines
# (//, #, <!--) are excluded so an explanatory reference cannot false-trip.
ra6_printer_tok='RemotePrinter|RustDeskPrinterDriver|remote_printer|printer_service|enable-remote-printer|install-printer|is-support-printer-driver'
ra6_printer_hits=$(grep -RInE "$ra6_printer_tok" flutter/lib res --include='*.dart' --include='*.rs' --include='*.cpp' --include='*.h' --include='*.def' --include='*.vcxproj' --include='*.wxs' --include='*.wxl' --include='*.py' 2>/dev/null | grep -v 'generated_bridge.dart' | grep -vE ':[0-9]+:[[:space:]]*(//|#|<!--)' || true)
if [ -n "$ra6_printer_hits" ]; then
  echo "  FAIL R-A6/BR-13: remote-printer tokens must be absent from flutter/lib + res but are present:"; echo "$ra6_printer_hits" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-A6/BR-13 remote-printer tokens absent from flutter/lib + res (Dart UI + MSI/WiX/C++)"
fi
ra6_clean 'DEBUG_BOOT_COMPLETED'                                          'R-X6 fake-boot broadcast'  || rc=1
# R-X6: the Linux D-Bus deep-link delivery transport (src/server/dbus.rs: session-bus name
# org.rustdesk.rustdesk, method NewConnection) is EXCISED. It ignored the caller (any co-installed
# same-session app could fire it — a local-IPC injection vector) and claimed the bus name with
# replace_existing=true (a name-hijack to intercept legitimate links). The module is deleted; uni-links
# are self-handled per-instance (core_main); their embedded key/password/relay is stripped (R-X6, below). \bstart_dbus_server
# excludes the kept no-op FFI shim main_start_dbus_server (no word boundary before "start").
ra6_clean 'crate::dbus|org\.rustdesk\.rustdesk|\bstart_dbus_server' 'R-X6 D-Bus deep-link transport (NewConnection)' || rc=1
# R-X6 (cont.): dbus-crossroads (the D-Bus SERVER framework) was the dead Cargo-dep residual of the
# excised dbus.rs — zero crossroads:: usage remains, so the dep is dropped. Assert it stays gone (the
# base `dbus` crate stays for the legit platform/linux.rs session-bus call — do NOT gate that out).
grep -qE '^dbus-crossroads = ' Cargo.toml && { echo "  FAIL R-X6: the dead dbus-crossroads dep (only the excised dbus.rs used it) is back in Cargo.toml"; rc=1; }
# R-X6/R-S11c-9 (_url sender-auth): the SEPARATE _url deep-link IPC listener (server::start_ipc_url_server)
# bypasses the main handle() service-accept gate, so it MUST authenticate its sender identity and
# executable path — else a local process can inject a rustdesk:// connect/relay/key.
if grep -qE 'fn start_ipc_url_server' src/server.rs && ! grep -qE 'authorize_url_ipc_sender' src/server.rs; then
  echo "  FAIL R-X6/R-S11c-9: start_ipc_url_server does not authenticate its _url IPC sender"; rc=1
else
  echo "  ok  R-X6/R-S11c-9 _url IPC listener authenticates its sender (authorize_url_ipc_sender)"
fi
# R-S11c-9: Windows URL forwarding must not use public HWND messages. Existing-instance URL handoff
# goes through the same authenticated _url IPC receiver as macOS, with a restricted Windows named-pipe
# DACL and receiver-side same-session/current-executable checks.
r_s11c9_win_url=""
r_s11c9_tmp="${TMPDIR:-/tmp}/rd_verify_r_s11c9_winmsg.$$"
if grep -RInE 'WM_COPYDATA|COPYDATASTRUCT|DispatchToUniLinksDesktop|send_message_to_hnwd|WM_USER[[:space:]]*\+[[:space:]]*2' \
    src/core_main.rs src/platform/windows.rs flutter/windows/runner/main.cpp 2>/dev/null >"$r_s11c9_tmp"; then
  r_s11c9_win_url="$r_s11c9_win_url window-message-forwarder"
fi
grep -qF 'return if let Err(_) = crate::ipc::send_url_scheme(uni_links)' src/core_main.rs || r_s11c9_win_url="$r_s11c9_win_url core-main-no-url-ipc"
grep -qF 'authorize_windows_url_ipc_connection' src/ipc.rs || r_s11c9_win_url="$r_s11c9_win_url ipc-no-windows-url-auth"
grep -qF 'postfix == WINDOWS_URL_IPC_POSTFIX' src/ipc/auth.rs || r_s11c9_win_url="$r_s11c9_win_url url-pipe-not-restricted"
grep -qF 'assert!(super::windows_privileged_ipc_uses_restricted_dacl("_url"))' src/ipc/auth.rs || r_s11c9_win_url="$r_s11c9_win_url no-url-dacl-test"
grep -qF '#[cfg(any(target_os = "windows", target_os = "macos"))]' src/server.rs || r_s11c9_win_url="$r_s11c9_win_url server-not-windows"
grep -qF 'rustdesk_send_url_scheme' src/flutter.rs || r_s11c9_win_url="$r_s11c9_win_url c-abi-url-bridge-missing"
grep -qF 'url.starts_with(&crate::get_uri_prefix())' src/flutter.rs || r_s11c9_win_url="$r_s11c9_win_url c-abi-url-prefix-not-checked"
grep -qF 'send_rustdesk_url_scheme(argument.c_str())' flutter/windows/runner/main.cpp || r_s11c9_win_url="$r_s11c9_win_url runner-not-calling-url-bridge"
grep -qF '(isWindows || isMacOS) && isMain' flutter/lib/models/native_model.dart || r_s11c9_win_url="$r_s11c9_win_url dart-does-not-start-url-server"
if [ -n "$r_s11c9_win_url" ]; then
  echo "  FAIL R-S11c-9: Windows URL forwarding is not provably off HWND messages and onto authenticated _url IPC:$r_s11c9_win_url"
  [ -s "$r_s11c9_tmp" ] && sed 's/^/      /' "$r_s11c9_tmp"
  rc=1
else
  echo "  ok  R-S11c-9 Windows URL forwarding uses authenticated _url IPC and no HWND message dispatcher"
fi
rm -f "$r_s11c9_tmp"
# R-X6 deep-link embedded-credential strip — BOTH layers (a Dart-only strip is bypassable, since the raw
# URI reaches the Rust core via bind.sendUrlScheme). (1) The Dart parser urlLinkToCmdArgs
# (flutter/lib/common.dart) MUST NOT fold an embedded ?key= into the id, nor propagate ?password=/?relay=
# into the connect call or the launch args — a malicious rustdesk:// link must carry no trust anchor/cred.
if grep -qF '?key=$key' flutter/lib/common.dart || grep -qF "['--password', password]" flutter/lib/common.dart; then
  echo "  FAIL R-X6: flutter/lib/common.dart deep-link parser still carries an embedded key/password"; rc=1
elif ! grep -qF 'connect-only and MUST NOT carry an embedded' flutter/lib/common.dart; then
  echo "  FAIL R-X6: the urlLinkToCmdArgs R-X6 strip marker is gone (regrowth risk)"; rc=1
else
  echo "  ok  R-X6 Dart deep-link parser strips embedded key/password/relay"
fi
# R-X6 (stricter) — the handleUriLink DESKTOP/CLI args-list branch MUST NOT parse an embedded --password
# nor forward any password into the deep-link/CLI connect. The mobile branch (urlLinkToCmdArgs) already
# omits it; this locks the desktop/CLI (common.dart) + mobile (home_page.dart handleUnilink) branches to the same clean shape. A password baked into a rustdesk://
# link or a --password CLI arg is a footgun (it leaks into shell history, logs, clipboards, shared msgs).
# Assert (a) no `password = args[i+1]` parse, (b) no `new*(cid, ...password:)` forward into the connect
# (only handleUriLink connects via the `cid` local; the legit UI connect paths use `id` + a remembered
# secret and keep their password), and (c) the positive strip marker is present (regrowth guard).
r_x6_cli=""
grep -qE 'password *= *args\[ *i *\+ *1 *\]' flutter/lib/common.dart flutter/lib/mobile/pages/home_page.dart                            && r_x6_cli="$r_x6_cli parse:--password"
grep -qE 'rustDeskWinManager\.new[A-Za-z]+\(cid,[^)]*password:' flutter/lib/common.dart   && r_x6_cli="$r_x6_cli forward:new*(cid,password)"
grep -qF 'NO embedded credential is forwarded into any deep-link/CLI connect' flutter/lib/common.dart || r_x6_cli="$r_x6_cli marker-gone"
if [ -n "$r_x6_cli" ]; then
  echo "  FAIL R-X6: the deep-link/CLI handleUriLink connect still carries an embedded password:$r_x6_cli"; rc=1
else
  echo "  ok  R-X6 handleUriLink connect carries NO embedded password (desktop/CLI branch matches the clean mobile branch)"
fi
# R-X6 (stricter, Rust layer) — core_main_invoke_new_connection MUST NOT fold an embedded --password into
# the connect URI. It used to `param_array.push(format!("password={password}"))`, folding it as ?password=
# into the uni-link then delivered through desktop URL handoff — leaking the credential into that IPC
# message even before any consumer read it. The strip MUST hold in BOTH layers,
# because the raw URI reaches the Rust core via bind.sendUrlScheme, bypassing a Dart-only fix (spec R-X6).
r_x6_rustcli=""
grep -qE 'param_array\.push\(format!\("password=' src/core_main.rs && r_x6_rustcli="$r_x6_rustcli fold:password="
grep -qF 'NEVER fold an embedded credential into the connect URI' src/core_main.rs || r_x6_rustcli="$r_x6_rustcli marker-gone"
if [ -n "$r_x6_rustcli" ]; then
  echo "  FAIL R-X6: core_main still folds an embedded --password into the connect URI:$r_x6_rustcli"; rc=1
else
  echo "  ok  R-X6 core_main connect URI carries the address only (no embedded --password fold)"
fi
# R-G6 / R-SV4 / R-X6: relay route syntax must FAIL CLOSED. The inherited flow accepted
# rustdesk://<id>/r, stripped `/r` in Rust, set forceRelay, and could persist
# force-always-relay. The direct-only fork may keep generated ABI compatibility, but no
# source path may strip a relay suffix, serialize relay=true, or save/read force-always-relay.
if grep -qF 'param_array.push(format!("relay=true"))' src/core_main.rs; then
  echo "  FAIL R-G6/R-X6: core_main still forwards --relay as relay=true"; rc=1
elif ! grep -qF 'rejecting --relay on direct-only fork' src/core_main.rs; then
  echo "  FAIL R-G6/R-X6: core_main no longer explicitly rejects --relay"; rc=1
else
  echo "  ok  R-G6/R-X6 CLI --relay rejected instead of forwarded"
fi
if grep -qE 'handle_relay_id\(' src/client.rs; then
  echo "  FAIL R-G6/R-SV4: client.rs still strips relay suffixes through handle_relay_id"; rc=1
fi
if grep -RInE 'force-always-relay' src libs --include='*.rs' 2>/dev/null \
    | grep -v '//' | grep -v 'bridge_generated' >/dev/null; then
  echo "  FAIL R-G6/R-SV4: force-always-relay is still a live Rust config/read/write token"; rc=1
else
  echo "  ok  R-G6/R-SV4 force-always-relay live Rust token absent"
fi
# I-2/Tier-4 (2026-07-03): handle_relay_id (the dead identity shim) + its main_handle_relay_id FFI are
# EXCISED — no relay/Change-ID UI feeds them, and Client::_start rejects a `/r` route as a non-direct
# address. This flipped from an identity-PRESENCE gate to an ABSENCE gate (the fn must be gone).
grep -qE 'fn handle_relay_id' src/ui_interface.rs \
  && { echo "  FAIL R-G6/R-SV4: handle_relay_id must be EXCISED (dead relay-route shim) — found a residual fn"; rc=1; } \
  || echo "  ok  R-G6/R-SV4 handle_relay_id excised (direct-only _start rejects /r; client.rs never strips)"
# R-G6 ADDITIVE copy — the half the deletion-only greps never asserted (so it silently slipped): the
# direct-only failure/status semantics MUST be REWRITTEN, not merely have the relay copy deleted. Two
# MUST clauses: (a) a peer that DISABLED a capability surfaces a SPECIFIC "disabled on the peer"
# message, not a confusing generic connect failure; (b) an unreachable host gets actionable "check the
# address / port-forward" guidance (there is no relay fallback to suggest). Assert both lang keys exist
# in en.rs AND are wired in client.rs (present + referenced, not orphaned) so the copy cannot regress.
r_g6_add=""
grep -qF '"Capability disabled on the remote peer"' src/lang/en.rs || r_g6_add="$r_g6_add en:cap-disabled-key"
grep -qF '"direct_unreachable_tip"' src/lang/en.rs                  || r_g6_add="$r_g6_add en:unreachable-tip-key"
grep -qF '"Capability disabled on the remote peer"' src/client.rs   || r_g6_add="$r_g6_add wire:cap-disabled-msgbox"
grep -qF 'err.starts_with("No permission of")' src/client.rs        || r_g6_add="$r_g6_add wire:cap-refusal-detect"
grep -qF '"direct_unreachable_tip"' src/client.rs                   || r_g6_add="$r_g6_add wire:unreachable-msgbox"
grep -qF 'err.contains("Failed to connect")' src/client.rs          || r_g6_add="$r_g6_add wire:unreachable-detect"
if [ -n "$r_g6_add" ]; then
  echo "  FAIL R-G6: the direct-only ADDITIVE error/status copy is missing/unwired:$r_g6_add"; rc=1
else
  echo "  ok  R-G6 additive copy present+wired (capability-disabled-on-peer message + unreachable check-address/port-forward guidance)"
fi
# (2) The Rust core LoginConfigHandler::initialize (src/client.rs) MUST NOT adopt an embedded ?key= into
# other_server, nor re-adopt a persisted/option-injected other-server-key.
if grep -qE 'args_map\.remove\("key"\)' src/client.rs; then
  echo "  FAIL R-X6: src/client.rs still parses an embedded ?key= into other_server"; rc=1
elif ! grep -qF 'NEVER adopt an embedded' src/client.rs; then
  echo "  FAIL R-X6: the client.rs ?key= strip marker is gone (regrowth risk)"; rc=1
else
  echo "  ok  R-X6 Rust core never adopts an embedded ?key= (other_server key held empty)"
fi
# R-X6 confirmation gate: a deep-link-initiated connection MUST be confirmed by the user. The Dart gate
# (confirmDeepLinkConnect via msgBox) wraps every rustdesk:// connect, routed through the `fromUri`
# discriminator so the user-typed CLI is NOT gated but every URI-derived connect is.
if grep -qF 'confirmDeepLinkConnect' flutter/lib/common.dart && grep -qF 'fromUri' flutter/lib/common.dart; then
  echo "  ok  R-X6 deep-link connect is confirmation-gated (confirmDeepLinkConnect + fromUri)"
else
  echo "  FAIL R-X6: the deep-link-connect confirmation gate (confirmDeepLinkConnect/fromUri) is missing"; rc=1
fi
# R-X6 deep-link WRITE authorities: rustdesk://config/<b64> (server + key trust-anchor write) and
# rustdesk://password/<pw> (permanent-password write) MUST be ignored, not honored (the same trust-anchor
# / credential-injection class as R-X4). Assert urlLinkToCmdArgs still treats them as ignore-return-null.
if grep -qF '["config", "password"].contains(uri.authority)' flutter/lib/common.dart && grep -qF 'Ignoring rustdesk:// server/credential write authority' flutter/lib/common.dart; then
  echo "  ok  R-X6 deep-link config/password WRITE authorities are ignored (no trust-anchor/credential write)"
else
  echo "  FAIL R-X6: the rustdesk://config + rustdesk://password WRITE authorities are not provably excised"; rc=1
fi
# R-X6 Android manifest hardening (committed d4cb686 + f8ddac8) — lock it against regrowth. The dropped
# tokens survive only in explanatory comments, so gate on LIVE <uses-permission>/<service> declarations +
# the allowBackup/requestLegacyExternalStorage attributes + the cleartext-deny network-security-config.
AMF=flutter/android/app/src/main/AndroidManifest.xml
if grep -qF 'android:allowBackup="false"' "$AMF" \
   && ! grep -qE '(uses-permission|<service)[^>]*(SYSTEM_ALERT_WINDOW|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|FloatingWindowService)' "$AMF" \
   && ! grep -qE 'android:requestLegacyExternalStorage' "$AMF" \
   && grep -qF 'cleartextTrafficPermitted="false"' flutter/android/app/src/main/res/xml/network_security_config.xml; then
  echo "  ok  R-X6 Android manifest hardened (allowBackup=false; no live overlay/legacy-storage/floating-svc decl; cleartext-deny)"
else
  echo "  FAIL R-X6: Android manifest hardening regressed (allowBackup / a live SYSTEM_ALERT_WINDOW|storage|FloatingWindowService decl / requestLegacyExternalStorage / network-security-config)"; rc=1
fi
# R-X6 Android: the dead floating-window / SYSTEM_ALERT_WINDOW Dart UI is excised (commit 917ebd0; the
# native FloatingWindowService was cut in f8ddac8). Assert no LIVE kSystemAlertWindow reference regrows in
# the Flutter UI — a regrown overlay-permission request would re-introduce the dropped permission AND the
# canStartOnBoot silent-disable boot-start bug. (Filter the grep -rn 'file:line:' prefix so the lone
# explanatory comment in consts.dart is not a false positive.)
if grep -rn 'kSystemAlertWindow' flutter/lib/ | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  echo "  FAIL R-X6: a live kSystemAlertWindow reference regrew in flutter/lib (floating-window/overlay UI)"; rc=1
else
  echo "  ok  R-X6 Android floating-window / SYSTEM_ALERT_WINDOW Dart UI excised (no live ref)"
fi
# R-G1/R-G2 (§19): the mobile QR scanner is EXCISED, not just neutered. Its config-QR import backend
# was dead (R-X4/R-X6) and the fork generates no QR to scan (the ID-sharing QR generator is gone,
# R-G2); the lone surviving path (rustdesk://<addr> -> direct connect) is redundant with the connect
# box, so the whole scanner (camera + gallery-image + deep-link parser = untrusted-input surface) is
# removed. Assert the page, the live refs, and the scanner-only deps are all absent. (The flutter/lib
# grep filters `//` comment lines so the settings_page excision-rationale comment is not a false hit.)
if [ -e flutter/lib/mobile/pages/scan_page.dart ]; then
  echo "  FAIL R-G1/R-G2: scan_page.dart regrew (QR scanner page)"; rc=1
elif grep -rn 'ScanButton\|ScanPage\|QRView\|qr_code_scanner' flutter/lib/ | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  echo "  FAIL R-G1/R-G2: a live QR-scanner reference regrew in flutter/lib (ScanButton/ScanPage/QRView/qr_code_scanner)"; rc=1
elif grep -qE '^[[:space:]]*(qr_code_scanner|zxing2|image_picker):' flutter/pubspec.yaml; then
  echo "  FAIL R-G1/R-G2: a QR/image-scanner dep regrew in pubspec.yaml (qr_code_scanner/zxing2/image_picker)"; rc=1
else
  echo "  ok  R-G1/R-G2 mobile QR scanner fully excised (page + live refs + qr_code_scanner/zxing2/image_picker deps gone)"
fi
# R-X8/R-X6 terminal-admin (run-as-administrator) viewer mode -- EXCISED. It set IS_TERMINAL_ADMIN=Y, which
# client.rs handle_hash short-circuited into a msgbox ("terminal-admin-login") the Flutter model has NO
# handler for -> a guaranteed blank-dialog dead-end that then closes the connection (a 100%-failure
# affordance). The field + env + the get_key admin branch + the 5 peer-card menu items + the --terminal-admin
# CLI + the terminal-admin deep-link are all removed; the plain (non-admin) _terminalAction stays. (The inert
# terminal-admin-login-tip lang strings are harmless localization data and are intentionally left in place.)
ra6_clean 'is_terminal_admin|IS_TERMINAL_ADMIN|terminal-admin-service-id' 'R-X8/R-X6 terminal-admin viewer field/env/service-id-key' || rc=1
if grep -rqE 'setEnvTerminalAdmin|_terminalRunAsAdminAction|IS_TERMINAL_ADMIN|terminal-admin|isTerminalRunAsAdmin' flutter/lib/; then
  echo "  FAIL R-X8/R-X6: a terminal-admin (run-as-administrator) trigger regrew in flutter/lib"; rc=1
elif grep -rqF '_terminalAction(context)' flutter/lib/common/widgets/peer_card.dart; then
  echo "  ok  R-X8/R-X6 terminal-admin viewer mode excised (env/method/menu/CLI/deep-link); non-admin terminal kept"
else
  echo "  FAIL R-X8/R-X6: the non-admin _terminalAction was lost (over-excision)"; rc=1
fi
ra6_clean 'ConfigureUpdate|TestNatResponse'                              'R-X3 server-push config-update + NAT-response rewrite arms' || rc=1
# R-P3 / R-P14: the inherited insecure direct-mode used a plaintext constant-byte ack ("direct-ok")
# to admit a peer WITHOUT the PAKE key-confirmation. The fork makes CPace mandatory (R-A1), so any
# such constant ack MUST stay absent — its return would be a PAKE bypass.
ra6_clean 'direct-ok'                                                     'R-P3 insecure constant-byte ack (direct-ok), PAKE bypass' || rc=1
ra6_clean 'RUSTDESK_FORCED_DISPLAY_SERVER'                                'R-X12 display-server knob' || rc=1
# R-X12: is_x11() is compile-pinned `true` in BOTH the main crate (src/platform/linux.rs) and scrap
# (libs/scrap/src/common/mod.rs) — the capture+input backend is X11 with NO runtime display-server
# selector (the `*IS_X11` detection cache + the is_x11_or_headless() body are gone). Startup-asserted
# (R-A4, direct_service). Guards a regression that re-adds runtime capture/input backend selection.
r_x12_pin=
grep -A1 'pub fn is_x11() -> bool {' src/platform/linux.rs        | grep -qE '^\s*true\s*$' || r_x12_pin="$r_x12_pin main-is_x11"
grep -A1 'pub fn is_x11() -> bool {' libs/scrap/src/common/mod.rs | grep -qE '^\s*true\s*$' || r_x12_pin="$r_x12_pin scrap-is_x11"
grep -q 'static ref IS_X11' src/platform/linux.rs && r_x12_pin="$r_x12_pin IS_X11-cache-returned"
if [ -n "$r_x12_pin" ]; then
  echo "  FAIL R-X12: is_x11() X11-pin incomplete:$r_x12_pin"; rc=1
else
  echo "  ok  R-X12 is_x11() compile-pinned true (main + scrap; no runtime display-server selection)"
fi
# R-X12: get_display_server() is ALSO compile-pinned to the X11 constant — NOT just is_x11(). The
# session-admission gate (server::connection "Unsupported display server type") and ui_interface
# get_error() consult get_display_server(), not is_x11(); leaving it a runtime probe (loginctl /
# stray session-type) let a seatless/container session still REFUSE an incoming connection — the
# exact failure R-X12 says the x11 pin eliminates ("determinism a property of the binary, so no
# operator ever needs the env override"). The body MUST be the constant return, no runtime probe.
# (Comment lines are stripped before the probe check so the rationale can name the removed probe.)
r_x12_gds_code="$(awk '/^pub fn get_display_server\(\) -> String \{/{f=1} f && $0 !~ /^[[:space:]]*\/\//{print} f && /^\}/{exit}' libs/hbb_common/src/platform/linux.rs)"
if printf '%s\n' "$r_x12_gds_code" | grep -qE 'DISPLAY_SERVER_X11' \
   && ! printf '%s\n' "$r_x12_gds_code" | grep -qE 'run_loginctl|XDG_SESSION_TYPE'; then
  echo "  ok  R-X12 get_display_server() compile-pinned to the X11 constant (no runtime probe; refuse-path cannot misfire)"
else
  echo "  FAIL R-X12: get_display_server() still runtime-probes — the 'Unsupported display server type' refuse-path can misfire (R-X12 promise undelivered)"; rc=1
fi
# R-X12 (§8) — the Wayland/pipewire CAPTURE path is COMPILED OUT (the CI-grep deliverable): the scrap
# `wayland` feature + `mod wayland` (libs/scrap/src/wayland/ — the xdg-portal ScreenCast + restore-token
# persistence, R-S14) are REMOVED; X11 is the sole compile-pinned capture backend (the gstreamer/dbus/
# zbus pipewire surface is no longer linked). Asserts the feature enabling + `mod wayland` + the dir absent.
r_x12_cap=
grep -qE 'scrap = .*wayland'                Cargo.toml            && r_x12_cap="$r_x12_cap root-scrap-wayland-feature"
grep -qE '^wayland = \['                     libs/scrap/Cargo.toml && r_x12_cap="$r_x12_cap scrap-wayland-feature"
grep -rqE '^[[:space:]]*(pub )?mod wayland'   libs/scrap/src        && r_x12_cap="$r_x12_cap scrap-mod-wayland"
[ -e libs/scrap/src/wayland ]                                      && r_x12_cap="$r_x12_cap scrap-wayland-dir"
if [ -n "$r_x12_cap" ]; then
  echo "  FAIL R-X12: Wayland capture not compiled out:$r_x12_cap"; rc=1
else
  echo "  ok  R-X12 Wayland/pipewire capture compiled out (no scrap wayland feature / mod wayland / dir)"
fi
ra6_clean 'gtk_sudo|run_cmds_privileged|"-gtk-sudo"'                      'R-X11 gtk_sudo elevation'  || rc=1
ra6_clean 'start_uinput_service'                                         'R-X13 dormant uinput listener' || rc=1
# R-X13 (§8): the rdp_input module — Wayland-portal RDP keyboard/mouse injection via the dbus
# org.freedesktop.portal.RemoteDesktop session (RdpInputKeyboard/RdpInputMouse as the enigo custom
# backend) — is EXCISED. XTEST/enigo is the pinned sole injector (wayland_use_rdp_input() was already
# false by construction), so this was compiled-in dead surface (§8 "removed not disabled"). The module
# file + setup_rdp_input + the selector + the dead branches are gone. The uinput sibling and
# Wayland/pipewire capture path are asserted by the adjacent R-X13/R-X12 gates.
if [ -e src/server/rdp_input.rs ]; then
  echo "  FAIL R-X13: the excised src/server/rdp_input.rs reappeared"; rc=1
else
  echo "  ok  R-X13 rdp_input module file absent"
fi
ra6_clean 'RdpInput|fn setup_rdp_input|wayland_use_rdp_input|mod rdp_input' 'R-X13 rdp_input Wayland-portal injection (module/setup/selector)' || rc=1
# R-X13 (§8): the uinput INJECTION module — Wayland kernel input injection (/dev/uinput) driven over a
# cross-uid `_uinput_*` IPC SERVICE — is EXCISED (src/server/uinput.rs, 1350 lines). XTEST/enigo is the
# pinned sole injector (wayland_use_uinput() was already false). Gone: the module, the client
# (UInputKeyboard/UInputMouse + setup_uinput/set_uinput_resolution/update_mouse_resolution), and the
# uinput-only IPC-auth helpers (log_rejected_uinput_connection, ensure_peer_executable_matches_current_by_fd).
# The _service-channel peer-uid authorization is UNTOUCHED (gate 3b-i still green). The dead
# selector/dispatch guards are asserted below, and config_it asserts `_uinput_*` is no longer a
# world-connectable service IPC postfix.
if [ -e src/server/uinput.rs ]; then
  echo "  FAIL R-X13: the excised src/server/uinput.rs reappeared"; rc=1
else
  echo "  ok  R-X13 uinput module file absent"
fi
ra6_clean 'mod uinput|UInputKeyboard|UInputMouse|fn setup_uinput|update_mouse_resolution|set_uinput_resolution|log_rejected_uinput_connection|ensure_peer_executable_matches_current_by_fd' 'R-X13 uinput injection module/client + cross-uid IPC auth helpers' || rc=1
# R-X13 (§8): the uinput DISPATCH guards (the wayland_use_uinput() selector + its dead `if false`
# branches in the input hot-path) AND the coupled Wayland clipboard-input echo-suppression subsystem
# (the WRITER chain set_clipboard_for_paste_sync/input_text_via_clipboard_server/record_..._for_sync_filter
# in input_service.rs + the READER should_skip_wayland_clipboard_sync/is_recent_wayland_clipboard_input
# in clipboard_service.rs + the owner-marked SET path in clipboard.rs) are EXCISED — XTEST/enigo is the
# unconditional sole injector and nothing self-injects clipboard text, so there is no echo to suppress.
ra6_clean 'wayland_use_uinput|should_skip_wayland_clipboard_sync|is_recent_wayland_clipboard_input|input_text_via_clipboard_server|set_clipboard_for_paste_sync|set_with_owner_marker_for_linux' 'R-X13 uinput dispatch guards + Wayland clipboard-input echo-suppression subsystem' || rc=1
# R-X14 (Appendix C #17, a Tier-1-class remote root-context PAM oracle): the os_login -> PAM
# desktop-session-start in linux_desktop_manager.rs is EXCISED. Upstream let a peer's
# LoginRequest.os_login drive a real PAM credential check + a root window-manager-launch script to
# spawn an X session as an arbitrary OS account — on the plaintext direct path BEFORE the password
# check. The whole X-session-spawn + PAM subsystem is removed (linux_desktop_manager collapsed to
# seat0 capture-discovery only; the connection wrapper ignores os_login). These tokens MUST stay
# absent (the capture-side discovery — get_username/is_headless/seat0 — is kept, R-S14).
ra6_clean 'pam::Client|try_start_x_session|start_x_session|start_x11|add_xauth_cookie|pam_get_service_name|should_check_linux_headless_os_auth|should_record_linux_headless_os_auth' 'R-X14 os_login->PAM desktop-session-start + the connection.rs headless OS-auth limiter site (R-T15 line 254)' || rc=1
# R-X8: the terminal OS-login SECOND CREDENTIAL is excised — the terminal is now SessionUser-only
# (one PAKE password -> the service user's shell, R-F1; should_use_terminal_os_login_scope gone,
# prepare_terminal_login_for_authorization renamed to prepare_terminal_session_user). What goes to
# zero: the Windows LogonUserW admin-check (handle_administrator_check / get_logon_user_token /
# is_user_token_admin) AND the whole per-terminal OS-credential rate-limit + concurrency subsystem
# (login_failure_check.rs DELETED: FailureScope / TerminalOsLogin / evaluate_os_credential_policy /
# record_os_credential_failure / try_acquire_os_credential_login_gate, plus the connection.rs
# check_failure / update_failure_with_scope shims — R-T15b had already excised LOGIN_FAILURES, so
# CPace GUESS_FAILURES (R-P14c) is the sole online-guess limiter). CreateProcessWithLogonW is R-X9.
ra6_clean 'should_use_terminal_os_login_scope|prepare_terminal_login_for_authorization|handle_administrator_check|get_logon_user_token|is_user_token_admin|LogonUserW|FailureScope|TerminalOsLogin|TERMINAL_OS_LOGIN_FAILED_MSG|try_acquire_os_credential_login_gate|evaluate_os_credential_policy|record_os_credential_failure|update_failure_with_scope|check_failure_with_scope' 'R-X8 terminal OS-login second-credential + its FailureScope/login_failure_check limiter subsystem' || rc=1
# R-X9: the peer-triggered elevation feature is FULLY excised — a connected peer can no longer ask
# the controlled box to spawn a SYSTEM service. BOTH routes are gone: the OS-credential path (peer
# username+password -> Windows CreateProcessWithLogonW, ElevationRequestWithLogon) AND — newly — the
# Direct UAC path (Misc::ElevationRequest -> handle_elevation_request -> start_portable_service).
# Removed across the wire (message.proto ElevationRequest msg + elevation_request 18 /
# elevation_response 19 Misc fields), the cfg(windows) server (connection.rs dispatch arm +
# handle_elevation_request), and the viewer sender (io_loop Data::ElevateDirect arm + ElevationResponse
# reader, ui_session_interface elevate_direct, flutter_ffi session_elevate_direct, client.rs
# Data::ElevateDirect). The sole sanctioned privilege transition is the installed-service
# winlogon-token launch (kept). uac(15)/foreground_window_elevated(16) are a separate status
# feature, kept. portable_service_running(20) is now ALSO excised — see the slices-2-4 gate
# below. (Patterns are code-specific so the "...excised" comments the removal left behind do
# not self-trip the grep.)
ra6_clean 'create_process_with_logon|CreateProcessWithLogonW|StartPara::Logon|elevation_request::Union' 'R-X9 os-credential elevation (CreateProcessWithLogonW / Logon arm)' || rc=1
ra6_clean 'fn handle_elevation_request|Data::ElevateDirect|fn elevate_direct|fn session_elevate_direct|set_elevation_request|set_elevation_response|misc::Union::ElevationRequest|misc::Union::ElevationResponse' 'R-X9 Direct peer-triggered elevation (handle_elevation_request / ElevateDirect / ElevationRequest|Response)' || rc=1
r_x9_proto=
grep -qE 'message +ElevationRequest(WithLogon)?\b' libs/hbb_common/protos/message.proto && r_x9_proto="$r_x9_proto ElevationRequest-msg"
grep -qE 'elevation_request *= *18|elevation_response *= *19' libs/hbb_common/protos/message.proto && r_x9_proto="$r_x9_proto elevation-field"
# R-X9 (slices 2-4): portable_service_running (Misc field 20) excised — the host never sets it
# (the connection.rs::portable_check sender is removed) and the viewer never reads it.
grep -qE 'portable_service_running *= *20' libs/hbb_common/protos/message.proto && r_x9_proto="$r_x9_proto portable_service_running-field"
if [ -n "$r_x9_proto" ]; then
  echo "  FAIL R-X9: peer-elevation proto surface still present:$r_x9_proto"; rc=1
else
  echo "  ok  R-X9 ElevationRequest message + elevation_request/response + portable_service_running(20) Misc fields absent from message.proto"
fi
# R-X9 (slices 2-4): the Windows portable/un-installed run-mode + quick-support + interactive
# (UAC/token-theft) elevation are excised — "removed not disabled". src/server/portable_service.rs
# (the SYSTEM helper) is deleted; its capture/input/cursor routes are inlined to the direct path
# (video_service create_capturer -> Capturer::new; input_service handle_mouse/pointer/key -> *_;
# windows.rs get_cursor -> GetCursorInfo). run_uac / elevate / run_as_system / elevate_or_run_as_system
# + the core_main --elevate/--run-as-system/--quick_support dispatch + the CM DataPortableService::
# RequestStart trigger + the portable_service_running sender are gone; impersonate_system (token-theft)
# + shared_memory (capture shmem) deps removed. The installed LocalSystem service (launch_privileged_
# process / CreateProcessAsUserW, KEPT) is the SOLE controlled entry. check_super_user_permission is
# KEPT (R-X11 UI) but converted to a passive is_elevated() check — no UAC self-relaunch. (Patterns are
# code-specific; the "...excised" // comments the removal left are stripped by ra6_clean's `grep -v //`.)
# NOTE: the orphaned portable-service IPC PEER-AUTH + LISTENER [ipc/auth.rs + ipc.rs `_portable_service`
# branch + windows.rs portable_service_logon_helper_paths] is now removed + gated just below. The
# former Layer-2 token handshake, DataPortableService data-enum, and shmem-ACL follow-ups are gated
# in the adjacent R-X9 clauses. (libs/portable is NOT dead — it is the live rustdesk-portable-packer installer.)
ra6_clean 'pub mod portable_service|crate::portable_service::|portable_service::client|portable_service::server|fn run_uac|fn run_as_system|fn elevate_or_run_as_system|pub fn elevate\(arg: &str|impersonate_system::|set_quick_support|start_portable_service|set_portable_service_running|misc::Union::PortableServiceRunning|drop_portable_service_shared_memory' 'R-X9 portable run-mode + quick-support + interactive elevation (slices 2-4)' || rc=1
# R-X9 slices 2-4: the impersonate_system (SYSTEM token-theft, drove run_as_system) + shared_memory
# (portable capture shmem) Cargo deps are removed — both were used only by the excised portable_service.
r_x9_deps=
grep -qE '^impersonate_system =|^shared_memory =' Cargo.toml && r_x9_deps="$r_x9_deps cargo-dep-present"
if [ -n "$r_x9_deps" ]; then
  echo "  FAIL R-X9: portable-service Cargo deps still present:$r_x9_deps"; rc=1
else
  echo "  ok  R-X9 impersonate_system + shared_memory Cargo deps removed (slices 2-4)"
fi
# R-X9 (slices 2-4 follow-on): the orphaned portable-service IPC PEER-AUTH + LISTENER subsystem is excised
# (ipc/auth.rs + ipc.rs + windows.rs). The deleted portable SYSTEM helper connected over the
# `_portable_service` named pipe, so its peer-authenticator (authorize_windows_portable_service_ipc_connection
# + is_allowed_windows_portable_service_peer + the logon-helper exe-trust exception
# windows_portable_service_ipc_allows_logon_helper_executable / portable_service_helper_is_trusted /
# windows.rs portable_service_logon_helper_paths), the listener SDDL builder
# (portable_service_listener_security_attributes) + the new_listener `_portable_service` branch, and the
# trait method portable_service_authorization_status_for_session are all removed. KEPT: the LIVE main-IPC
# auth (authorize_windows_main_ipc_connection) + the `_service`-channel auth + ensure_peer_executable_
# matches_current_by_pid (now WITHOUT the dead portable exception — behaviorally identical, no live caller
# ever passed `_portable_service`). The token-handshake, DataPortableService, and shmem-ACL follow-ups
# are gated by the adjacent R-X9 clauses.
ra6_clean 'fn portable_service_listener_security_attributes|fn authorize_windows_portable_service_ipc_connection|fn is_allowed_windows_portable_service_peer|fn portable_service_helper_is_trusted|fn windows_portable_service_ipc_allows_logon_helper_executable|fn portable_service_authorization_status_for_session|fn portable_service_logon_helper_paths|postfix == "_portable_service"' 'R-X9 orphaned portable-service IPC peer-auth + listener (slices 2-4 follow-on)' || rc=1
# R-X9 (slices 2-4 follow-on, Layer 2a): the orphaned portable-service IPC TOKEN-HANDSHAKE cluster is
# excised — the portable SYSTEM helper that did the one-time-token handshake over the `_portable_service`
# pipe is deleted, so generate_one_time_ipc_token + constant_time_ipc_token_eq + the IPC_TOKEN_LEN/
# RANDOM_BYTES consts + PORTABLE_SERVICE_IPC_HANDSHAKE_TIMEOUT_MS + the two handshake fns
# (portable_service_ipc_handshake_as_client/_server, ZERO callers) + the DataPortableService AuthToken/
# AuthResult variants (handshake-only) are all dead. The DataPortableService RequestStart/CmShowElevation
# variants + the CM elevation UI are gated separately in Layer 2b.
ra6_clean 'fn generate_one_time_ipc_token|fn constant_time_ipc_token_eq|fn portable_service_ipc_handshake|const IPC_TOKEN_LEN|PORTABLE_SERVICE_IPC_HANDSHAKE_TIMEOUT_MS' 'R-X9 orphaned portable-service IPC token-handshake (slices 2-4 follow-on, Layer 2a)' || rc=1
# R-X9 (slices 2-4 follow-on, Layer 2b): the dead CM "elevate" UI + the DataPortableService IPC data-enum.
# b3e8485 removed the SERVER-side portable-service/peer-elevation, leaving the CM elevate button + its
# transport orphaned. Excised: elevate_portable (sent DataPortableService::RequestStart to a deleted
# receiver), show_elevation + the Data::DataPortableService(CmShowElevation) reader (nothing sent it),
# can_elevate (gated the button), and — every remaining variant then being dead — the WHOLE
# DataPortableService enum + the Data::DataPortableService arm. Across Rust + sciter cm.tis + flutter.
ra6_clean 'enum DataPortableService|fn elevate_portable|fn show_elevation|fn can_elevate' 'R-X9 CM elevation UI + DataPortableService enum (slices 2-4 follow-on, Layer 2b)' || rc=1
r_x9_2b=
{ grep -rE 'cmCanElevate|cm_can_elevate|elevatePortable|sessionElevatePortable|DataPortableService' flutter/lib 2>/dev/null | grep -v '//' | grep -q . ; } && r_x9_2b="present"
if [ -n "$r_x9_2b" ]; then
  echo "  FAIL R-X9 Layer 2b: CM-elevation dart/sciter residue still present"; rc=1
else
  echo "  ok  R-X9 Layer 2b CM-elevation dart/sciter residue (cmCanElevate/elevatePortable/DataPortableService) excised"
fi
# R-X9 (slices 2-4 follow-on, Layer 5 — COMPLETES the portable-service IPC excision): the dead cfg(windows)
# shared-memory ACL in src/platform/windows/acl.rs. The portable SYSTEM helper that mmap'd the shmem (+ its
# ACL hardening) is deleted, so set_path_permission_for_portable_service_shmem_dir/file +
# validate_path_for_portable_service_shmem_dir + the private impls + current_process_user_sid_string (its
# last non-shmem user, ipc/auth.rs, went in Layer 3+4) + the windows.rs re-exports + the shmem tests are
# all dead. KEPT: the generic set_path_permission + sid_string_to_local_alloc_guard (still live).
ra6_clean 'fn set_path_permission_for_portable_service_shmem|fn validate_path_for_portable_service_shmem_dir|fn validate_portable_service_shmem_dir_target|fn current_process_user_sid_string' 'R-X9 portable-service shmem-ACL + current_process_user_sid_string (slices 2-4 follow-on, Layer 5)' || rc=1
# R-X9/R-X10/R-A6: the stop-service runtime toggle no longer gates the controlled-side SERVICE
# creation (windows.rs get_create_service / linux.rs check_if_stop_service + switch_service) or the
# direct LISTENER (direct_service.rs) — the installed service is always created + auto-start and the
# direct listener starts UNCONDITIONALLY (reads no option, R-A4/R-D4). "removed not disabled": no
# get/set_option("stop-service"), option2bool, or check_if_stop_service in that machinery. The key
# stays pinned "N" in PINNED_SETTINGS (R-S16) + in the is_option_can_save reject set (R-S11) — the
# un-writable guarantee. The Flutter card-removal (R-G1) + read-only behavior and the runtime
# service-kill writers are gated by the R-S16(d) UI and R-X9/R-X10 clauses below.
r_x9_stopsvc=
grep -qE 'Config::(get|set)_option\([^)]*"stop-service"|option2bool\("stop-service"|fn check_if_stop_service' src/platform/windows.rs src/platform/linux.rs src/direct_service.rs && r_x9_stopsvc="$r_x9_stopsvc service-listener-reads-toggle"
grep -qE '\("stop-service", *"N"\)' libs/hbb_common/src/config.rs || r_x9_stopsvc="$r_x9_stopsvc pin-removed"
grep -qE 'option == "stop-service"' libs/hbb_common/src/config.rs || r_x9_stopsvc="$r_x9_stopsvc not-in-reject-set"
if [ -n "$r_x9_stopsvc" ]; then
  echo "  FAIL R-X9: stop-service service/listener machinery not clean or pin/guard removed:$r_x9_stopsvc"; rc=1
else
  echo "  ok  R-X9/R-X10 stop-service excised from service-creation + direct-listener (always-on/unconditional); key pinned N + un-writable (R-S16/R-S11)"
fi
# R-X9/R-X10 (§19): the ui_interface::set_option `stop-service` special-case (value=="Y" -> uninstall_service,
# else -> install_service) is EXCISED — it was the LIVE runtime service-kill path reachable from the legacy
# sciter "Enable service"/"Start service" toggle. Residual desktop production Config/IPC writers of this
# dead key are rejected too; the explicit uninstall path must uninstall, not persist a runtime service switch.
# The old service-kill shape bypassed the R-S11
# config-write reject (it called uninstall_service DIRECTLY, before any Config write). The installed desktop
# service is un-killable at runtime; the SOLE sanctioned uninstall is the `--uninstall` CLI (core_main). The
# sciter UI controls (#stop-service menu + #start-service link + their handlers + the hide_stop_service
# builtin) are removed too — bringing the legacy sciter front-end + the shared set_option to flutter parity
# (flutter excised its stop-service button earlier). (Android has no stop-service config toggle: the
# controlled-side stop is the MainService.onDestroy -> JNI stopServer foreground-service lifecycle that
# supersedes the direct listener's service-owned generation — not a Config write — R-D7a.)
r_x9_killsvc=
grep -qE '&key == "stop-service"' src/ui_interface.rs && r_x9_killsvc="$r_x9_killsvc ui_interface-special-case"
grep -qE '(ipc::set_option|Config::set_option)\("stop-service"' src/platform/*.rs src/ui_interface.rs src/core_main.rs && r_x9_killsvc="$r_x9_killsvc stop-service-config-writer"
# (the sciter #stop-service/#start-service/Enable-service controls are gone with the Sciter UI, R-B6)
if [ -n "$r_x9_killsvc" ]; then
  echo "  FAIL R-X9/R-X10: runtime service-kill path still present:$r_x9_killsvc"; rc=1
else
  echo "  ok  R-X9/R-X10 runtime service-kill path excised (ui_interface set_option stop-service special-case + sciter Enable/Start-service controls; service un-killable except --uninstall CLI)"
fi
# R-D7a (SHOULD): the Android keep-screen-on local-option is hard-pinned to "during controlled" — the
# never / service-on modes + the settings radio + the KeepScreenOn enum/mappers are excised, so the
# screen stays on exactly while a controlled session is active (hardcoded in server_model). And the
# foreground service's onStartCommand stays START_NOT_STICKY so a service restart never re-enters
# capture outside a confirmed PAKE session (R-S14). R-D7a #2: the dead useVP9 / MediaCodec capture
# encoder is excised so the raw ImageReader is the single capture encoder.
r_d7a=
sp=flutter/lib/mobile/pages/settings_page.dart
grep -qE 'enum KeepScreenOn|KeepScreenOn\.(never|serviceOn)' "$sp" && r_d7a="$r_d7a keep-screen-on-modes-present"
grep -qF "title: 'Keep screen on'" "$sp" && r_d7a="$r_d7a keep-screen-on-radio-present"
ms=flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt
af=libs/scrap/src/android/ffi.rs
grep -qE 'return START_NOT_STICKY' "$ms" || r_d7a="$r_d7a onStartCommand-not-START_NOT_STICKY"
grep -qE 'return START_STICKY|START_REDELIVER_INTENT' "$ms" && r_d7a="$r_d7a sticky-restart-present"
grep -qE 'val useVP9|startVP9VideoRecorder|createMediaCodec|MIMETYPE_VIDEO_VP9' "$ms" && r_d7a="$r_d7a vp9-encoder-present"
grep -qF 'data: Vec<u8>' "$af" || r_d7a="$r_d7a android-raw-media-not-owned"
grep -qF 'update_from_jni_buffer' "$af" || r_d7a="$r_d7a android-raw-media-no-jni-copy"
grep -qF 'MAX_ANDROID_VIDEO_RAW_BYTES' "$af" || r_d7a="$r_d7a android-video-raw-no-cap"
grep -qF 'MAX_ANDROID_AUDIO_RAW_BYTES' "$af" || r_d7a="$r_d7a android-audio-raw-no-cap"
grep -qF 'dropping oversized Android' "$af" || r_d7a="$r_d7a android-raw-media-no-oversize-drop"
grep -qF 'AtomicPtr' "$af" && r_d7a="$r_d7a android-raw-media-retains-pointer"
if [ -n "$r_d7a" ]; then
  echo "  FAIL R-D7a: keep-screen-on / onStartCommand / useVP9-encoder / Android raw-media JNI not conformant:$r_d7a"; rc=1
else
  echo "  ok  R-D7a keep-screen-on pinned during-controlled + onStartCommand START_NOT_STICKY + dead useVP9/MediaCodec encoder excised (raw ImageReader single) + Android raw media JNI copies into bounded Rust-owned storage"
fi
# R-T13 (§20, SHOULD): Android controlled-side networking lifecycle. The foreground service must
# observe network loss/availability and drive the existing direct-listener rebuild path (`listener =
# None`, not a full server restart), and the R-T10 TCP keepalive must be paired with a foreground
# partial wakelock so probes continue during radio sleep/Doze.
r_t13=
grep -qF 'ConnectivityManager.NetworkCallback' "$ms" || r_t13="$r_t13 no-NetworkCallback"
grep -qF 'override fun onAvailable(network: Network)' "$ms" || r_t13="$r_t13 no-onAvailable"
grep -qF 'override fun onLost(network: Network)' "$ms" || r_t13="$r_t13 no-onLost"
grep -qF 'NetworkRequest.Builder().build()' "$ms" || r_t13="$r_t13 callback-not-all-networks"
grep -qF 'NET_CAPABILITY_INTERNET' "$ms" && r_t13="$r_t13 internet-only-network-callback"
grep -qF '@Synchronized' "$ms" || r_t13="$r_t13 callback-registration-unsynchronized"
grep -qF 'connectivityManager.registerNetworkCallback(request, networkCallback)' "$ms" || r_t13="$r_t13 no-register"
grep -qF 'connectivityManager.unregisterNetworkCallback(networkCallback)' "$ms" || r_t13="$r_t13 no-unregister"
grep -qF 'FFI.rebuildDirectServerListener()' "$ms" || r_t13="$r_t13 no-kotlin-rebuild-call"
grep -qF 'PowerManager.PARTIAL_WAKE_LOCK' "$ms" || r_t13="$r_t13 no-partial-wakelock"
grep -qF 'rustdesk:network-keepalive' "$ms" || r_t13="$r_t13 no-wakelock-tag"
grep -qF 'setReferenceCounted(false)' "$ms" || r_t13="$r_t13 wakelock-refcounted"
grep -qF 'networkKeepaliveWakeLock.acquire()' "$ms" || r_t13="$r_t13 no-wakelock-acquire"
grep -qF 'networkKeepaliveWakeLock.release()' "$ms" || r_t13="$r_t13 no-wakelock-release"
grep -qF 'external fun rebuildDirectServerListener()' flutter/android/app/src/main/kotlin/ffi.kt || r_t13="$r_t13 no-kotlin-ffi"
grep -qF 'Java_ffi_FFI_rebuildDirectServerListener' src/flutter_ffi.rs || r_t13="$r_t13 no-jni-export"
grep -qF 'request_direct_listener_rebuild("android-network-change")' src/flutter_ffi.rs || r_t13="$r_t13 no-jni-rebuild-hook"
grep -qF 'static LISTENER_REBUILD_EPOCH' src/direct_service.rs || r_t13="$r_t13 no-rebuild-epoch"
grep -qF 'R-T13: rebuilding direct listener after Android network change' src/direct_service.rs || r_t13="$r_t13 no-rebuild-log"
grep -qF 'listener = None;' src/direct_service.rs || r_t13="$r_t13 no-listener-none-rebuild"
if [ -n "$r_t13" ]; then
  echo "  FAIL R-T13: Android network-change listener rebuild / partial-wakelock keepalive missing:$r_t13"; rc=1
else
  echo "  ok  R-T13 Android network lifecycle: ConnectivityManager callback -> JNI rebuild hook -> listener=None rebind, with foreground partial wakelock for TCP keepalive"
fi
# R-X4 (custom_server): the custom-rendezvous-server-from-exe-name feature is excised. The installer
# could embed a rendezvous/api server in the exe NAME (rustdesk-host=... ; rustdesk-licensed-<b64>.exe),
# parsed by custom_server.rs and injected as custom-rendezvous-server / api-server at 4 sites
# (get_rendezvous_server, get_custom_rendezvous_server, get_api_server_, bootstrap EXE_RENDEZVOUS_SERVER
# + the install-time config write) -- a server config arriving from the binary's filename, a
# sovereignty/trust-anchor egress vector on a direct-IP-only fork. The whole module +
# get_license_from_exe_name + get_license(CustomServer) go to zero.
ra6_clean 'mod custom_server|get_custom_server_from_string|get_license_from_exe_name|\bCustomServer\b|EXE_RENDEZVOUS_SERVER' 'R-X4 custom-rendezvous-server-from-exe-name (custom_server module + get_license_from_exe_name + the EXE_RENDEZVOUS_SERVER config-level override)' || rc=1
# R-X14 (cont.): the excision is COMPLETE through the build + packaging — with zero pam:: usage the dead
# `pam` crate dep, its transitive pam-sys libpam runtime link, the .deb libpam0g Depends, and the
# /etc/pam.d/rustdesk install were all dead weight (a third-party git dep + a runtime-link + a dead
# config). Assert they stay gone so the supply-chain / runtime-link surface cannot silently regrow.
grep -qE '^pam = '      Cargo.toml  && { echo "  FAIL R-X14: the dead 'pam' crate dep is back in Cargo.toml"; rc=1; }
grep -q  'libpam0g'     build.py    && { echo "  FAIL R-X14: the .deb still Depends on libpam0g (the binary has no PAM)"; rc=1; }
grep -qE 'pam\.d/rustdesk' build.py && { echo "  FAIL R-X14: the .deb still installs the dead /etc/pam.d/rustdesk"; rc=1; }
[ -e res/pam.d ] && { echo "  FAIL R-X14: the dead res/pam.d/ PAM config files are back"; rc=1; } || true
# Supply-chain hygiene (§18 sovereignty / §11 dep surface): third-party (git) deps whose ONLY users were
# excised features stay removed from Cargo.toml, so the dep + its runtime-link + transitive surface cannot
# silently regrow. pam (R-X14, above) + dbus-crossroads (R-X6, gated at its R-ID) are done; here the two
# input/transport residuals: evdev (R-X12/X13 -- no raw /dev/input reading; X11+XTEST is the input path)
# and kcp-sys (R-D5 -- the KCP reliable-UDP transport, exactly what the no-UDP/direct-IP thesis sheds).
grep -qE '^evdev = ' Cargo.toml && { echo "  FAIL supply-chain: the dead evdev dep (input excision) is back in Cargo.toml"; rc=1; }
grep -qE '^kcp-sys'  Cargo.toml && { echo "  FAIL supply-chain: the dead kcp-sys dep (KCP reliable-UDP, vs the no-UDP thesis) is back"; rc=1; }
# R-X7 / §18: the 2FA machinery is FULLY excised. Responder side: the `require_2fa` field, the
# Auth2fa gate/handler, the trusted-device bypass, the raii session-2FA state (2FA was
# pinned-off-dead: `2fa`="" so require_2fa was always None ⇒ every branch unreachable). Now also:
# the viewer-side `send2fa` sender, the `Auth2FA` proto field, src/auth_2fa.rs, the totp-rs +
# qrcode-generator deps, and the Sciter 2FA UI (index/msgbox/common.tis) — no 2FA path on either
# side or on the wire. Two hard gates lock it in (the second covers the module/proto/dep/FFI):
ra6_clean 'require_2fa|set_session_2fa'                                   'R-X7 responder 2FA machinery' || rc=1
ra6_clean 'totp|Auth2FA|auth_2fa|generate2fa|verify2fa|set_auth_2fa|add_trusted_device' 'R-X7 2FA module/totp-rs/Auth2FA proto/FFI/trusted-device' || rc=1
# R-S16(d)(ii): the runtime SwitchPermission widener (the conn-side handler that
# re-assigned conn.keyboard/clipboard/audio/... bypassing the pinned policy) is
# removed. The qualified `ipc::Data::SwitchPermission` token was unique to that
# handler arm; the CM-side senders use the unqualified `Data::SwitchPermission`
# (R-G7 GUI surface), so this gate is specific to the widener.
ra6_clean 'ipc::Data::SwitchPermission'                                  'R-S16(d)(ii) SwitchPermission widener' || rc=1
# R-S16(d) / flutter UI correctness (the pinned-policy audit): a control whose write the policy funnel
# rejects must not render as a live, mutating affordance that silently no-ops.
#  - is_option_fixed() reports PINNED_SETTINGS keys as fixed, so every pinned control auto-greys (BUG4 root).
#  - the desktop CM mid-session permission icons are non-interactive (Data::SwitchPermission excised; BUG1).
#  - the desktop Service Start/Stop card is REMOVED, not Offstage-hidden (GC/R-G1: the service is pinned
#    always-on -- stop-service=N, un-killable by a local write -- and OS-supervised, so it is never a user
#    control; the honest reachability status lives on the connection page, T1). A pinned actuating control
#    is deleted, not hidden -- the former Offstage-when-running hide was the exact R-G1 "hidden != removed"
#    trap. Assert the card + its stop-service write/hide are ABSENT from the desktop settings UI.
#  - GA/M1 (§19): the mobile controlled-side pinned capabilities (enable-keyboard/clipboard/file-transfer/
#    audio) are shown READ-ONLY via _pinnedPolicyRow ("Set by policy", the mobile _PinnedPolicyToggle
#    twin, R-G1) — NOT live toggles that wrote the pinned enable-* key (the funnel rejected the write, so
#    the switch snapped back: the misleading-control footgun the operator hit on Android). This SUPERSEDES
#    the older keep-the-toggle-but-resync approach with a STRONGER invariant: (a) the read-only indicator
#    is present, and (b) the inert enable-* writes are EXCISED from the model. The OS-permission grant
#    affordances (Accessibility/storage/mic, R-G7) are preserved separately and are NOT enable-* writes.
r_s16d_ui=""
grep -qF 'PINNED_SETTINGS.iter().any' src/ui_interface.rs || r_s16d_ui="$r_s16d_ui is_option_fixed-pinned"
! grep -qE 'cmSwitchPermission|canModifyPermission' flutter/lib/desktop/pages/server_page.dart || r_s16d_ui="$r_s16d_ui cm-perms-runtime-switchable"
! grep -qE 'StopService|start_service\(' flutter/lib/desktop/pages/desktop_setting_page.dart || r_s16d_ui="$r_s16d_ui stop-service-card-present"
grep -qF '_pinnedPolicyRow' flutter/lib/mobile/pages/server_page.dart || r_s16d_ui="$r_s16d_ui mobile-pinned-readonly"
! grep -qE 'mainSet[A-Za-z]*Option\([^;]*kOptionEnable(Keyboard|Audio|Clipboard|FileTransfer)' flutter/lib/models/server_model.dart || r_s16d_ui="$r_s16d_ui mobile-inert-enable-write"
if [ -n "$r_s16d_ui" ]; then
  echo "  FAIL R-S16(d)/UI: a pinned-policy control reverted to a live silent-no-op affordance:$r_s16d_ui"; rc=1
else
  echo "  ok  R-S16(d)/UI pinned controls grey + CM perms inert + Stop-service card removed + mobile pinned caps read-only"
fi
# R-G7 (§19): the Android controlled-side UI conformance — two literal removals the §19 sweep mandates.
#  (1) CLICK-TO-ACCEPT dropped: the incoming-connection login dialog passes a NULL accept callback, so
#      showClientDialog renders no "Accept" button AND binds no Enter->accept (approve-mode is pinned
#      'password', R-S9/R-S16 -> acceptance is automatic post-PAKE). Any `sendLoginResponse(_, true)`
#      sender, or dropping the `onSubmit != null` guard, re-opens the click-to-accept path R-G7 forbids.
#      (The post-auth in-session voice-call request keeps its accept via a non-null onSubmit -- a kept
#      audio capability, not the pre-auth accept path.)
#  (2) The user-settable "Start on boot" toggle is REMOVED and boot-start is re-homed on
#      RECEIVE_BOOT_COMPLETED ALONE -- no KEY_START_ON_BOOT_OPT prefs gate in BootReceiver (one mode, no
#      runtime knob, R-D2) -- with the battery-optimization onboarding the spec requires kept RELOCATED
#      to server_model.toggleService (service-start), so the auto-start capability is "not left silently
#      broken". A regrown toggle (the get/set channel keys, the switchTile, or the prefs gate) would
#      restore the forbidden knob; a missing battery-opt request would silently break boot-start.
r_g7=""
grep -rqE 'sendLoginResponse\([^)]*true' flutter/lib/ && r_g7="$r_g7 android-login-accept-path"
grep -qF 'if (onSubmit != null) dialogButton("Accept"' flutter/lib/models/server_model.dart || r_g7="$r_g7 conditional-accept-missing"
grep -qF 'onSubmit: onSubmit == null ? null : submit' flutter/lib/models/server_model.dart || r_g7="$r_g7 conditional-onsubmit-missing"
{ grep -rn 'kGetStartOnBootOpt\|kSetStartOnBootOpt' flutter/lib/ | grep -qvE ':[0-9]+:[[:space:]]*//'; } && r_g7="$r_g7 start-on-boot-channel-live"
grep -rqF "translate('Start on boot')" flutter/lib/ && r_g7="$r_g7 start-on-boot-toggle"
grep -qF 'getBoolean(KEY_START_ON_BOOT_OPT' flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/BootReceiver.kt && r_g7="$r_g7 bootreceiver-toggle-gate"
grep -qF 'kRequestIgnoreBatteryOptimizations' flutter/lib/models/server_model.dart || r_g7="$r_g7 battery-opt-not-relocated"
if [ -n "$r_g7" ]; then
  echo "  FAIL R-G7: Android controlled-side UI conformance regressed:$r_g7"; rc=1
else
  echo "  ok  R-G7 Android: login click-to-accept dropped (null accept -> no button, no Enter) + Start-on-boot toggle removed, boot re-homed on RECEIVE_BOOT_COMPLETED alone (battery-opt onboarding relocated to service-start)"
fi
# R-A6 / R-S2 / R-G4: the switch-sides role-swap feature is FULLY excised. SwitchSidesResponse
# was a password-bypass + 2FA-skip authorization path (R-S2) — the resume itself was deleted by
# R-A2 (2cf3ad6), and this removes the rest for structural absence: the 3 proto messages
# (SwitchSidesRequest/SwitchSidesResponse/SwitchBack) + their Misc/Message Union arms, the ipc
# Data variants + relay handlers, the connection.rs UUID statics/helpers + the LIVE responder
# handler (the run_me("--switch_uuid") process-spawn), the client.rs consume/send_switch_login/
# handle_hash flow, the io_loop SwitchBack handler, and the whole flutter switch_sides FFI+UI.
# Case-sensitive, so the R-B6-deferred sciter `switch_sides` {} stub + `switch_back` trait method
# (lowercase) are not matched. The proto twin is gated just below.
ra6_clean 'SwitchSides|SwitchBack'                                       'R-A6/R-S2 switch-sides role-swap' || rc=1
if grep -qE 'SwitchSides|SwitchBack' libs/hbb_common/protos/message.proto 2>/dev/null; then
  echo "  FAIL R-A6: switch-sides proto messages/arms must be absent from message.proto"; rc=1
else echo "  ok  R-A6/R-S2 switch-sides proto absent"; fi
# R-S2 FSM-collapse: the post-keying salted-hash password oracle is deleted. With CPace
# (R-P14) every connection is mutually password-authenticated at keying, and R-A1 (now
# unconditional) refuses unkeyed streams before Connection::start, so the inherited
# login-time `validate_password`/`verify_h1` challenge-response was unreachable (R-S6) — the
# responder authorizes purely on the CPace KEYED edge. The call site now reads `!is_secured()`
# alone (fail-closed: an unkeyed stream is rejected, never password-validated). The 30-s
# recent-session resume `is_recent_session` + its entire dead SESSIONS cache (the only populator
# was `validate_password`, so it was never filled) are deleted too. The `Hash{salt,challenge}` FSM is
# now FULLY collapsed (R-T15c, gated immediately below): no set_hash emission, no handle_hash responder,
# no reactive Union::Hash arm; the viewer logs in proactively (CPace is the sole authenticator).
ra6_clean 'validate_password|verify_h1|is_recent_session'               'R-S2 post-key oracle + recent-session resume' || rc=1
# R-T15c: the legacy Hash challenge/response is collapsed end-to-end. The server emits no Hash (no
# set_hash), there is no handle_hash responder or reactive Union::Hash arm, and the proto Hash message +
# its field 9 are gone (9 reserved). The viewer sends its login PROACTIVELY in Client::start once the
# stream is CPace-keyed. (be052d9 PRS-hoist + a68618a server/proactive-login + the
# dead-code/proto cleanup; client::tests pin the PRS-persistence the collapse depends on.)
r_t15c=
grep -rqE 'set_hash\(|fn handle_hash|\.handle_hash\(|Union::Hash' src/ --include=*.rs && r_t15c="$r_t15c rust-Hash-FSM-present"
grep -qE 'message Hash\b|Hash +hash *=' libs/hbb_common/protos/message.proto && r_t15c="$r_t15c proto-Hash-present"
grep -qE 'reserved 3, 4, 9' libs/hbb_common/protos/message.proto || r_t15c="$r_t15c proto-field9-not-reserved"
if [ -n "$r_t15c" ]; then echo "  FAIL R-T15c Hash challenge/response collapse:$r_t15c"; rc=1; else
  echo "  ok  R-T15c -> Hash challenge collapsed (no set_hash/handle_hash/Union::Hash in Rust; proto Hash + field 9 gone, 9 reserved)"; fi
# R-SV7 / §18: the Telegram 2FA push/enrollment egress (a hardcoded api.telegram.org
# POST that leaked the box id + peer IP, gated on `bot`/`2fa` not `api-server`, so the
# R-D6 api-server pin never silenced it) is excised from the tree — structurally
# absent, not config-pinned (R-SV1). The fn defs and the URL literal are gone; only
# `//` comments naming the host remain (filtered above).
ra6_clean 'api\.telegram\.org|send_2fa_code_to_telegram|get_chatid_telegram' 'R-SV7 Telegram 2FA egress' || rc=1
# R-SV6(c) / §18: the device-deploy egress — deploy_device() POSTed {id,uuid,pk}+token to
# get_api_server()+"/api/devices/deploy" (account-server device registration a sovereign
# fork has no server for) — is excised: the endpoint literal + the --deploy CLI driver are
# gone (deploy_device is a refuse-stub; the §19/R-G4 sweep removes its flutter UI caller).
ra6_clean 'api/devices/deploy|api/devices/cli' 'R-SV6(c) device-deploy/assign egress' || rc=1
# R-SV6(d) / R-D6 / §18: the hardwired global api-server default ("https://admin.rustdesk.com")
# is excised — get_api_server_'s fallback is String::new() (behavior-gated at (3b-ii)). Assert the
# host literal never returns to the tree (a cheap string backstop for the resolution-layer test).
ra6_clean 'admin\.rustdesk\.com' 'R-SV6(d) hardwired global api-server default (admin.rustdesk.com)' || rc=1
# R-D4 Stage 2 / R-SV10: the rendezvous-mediator PROTOCOL is removed from the tree (the
# register loop + register_pk method, the relay/punch-hole/intranet handlers, the UDP/KCP
# path). These worker symbols were mediator-internal and are now tree-wide absent — the
# direct-only service entry (start_direct_only -> direct_server) is all that remains.
ra6_clean 'handle_request_relay|handle_punch_hole|udp_nat_listen|punch_udp_hole|KcpStream::accept' 'R-D4 Stage 2 mediator relay/punch/KCP protocol' || rc=1
# R-D4 Stage 3 / R-SV10: the inherited `rendezvous_mediator` module is RENAMED to `direct_service`.
# After Stage 1/2 (the registration/relay/UDP protocol + every no-op shell are gone), the module is
# honestly the direct-only service path (start_direct_only -> direct_server + the R-A4/R-T* self-
# checks), so the spec's must-be-absent token `mod rendezvous_mediator` — and the misleading module
# name itself — are grep-absent across the tree (R-SV10 names `mod rendezvous_mediator` in its set).
if [ -f src/rendezvous_mediator.rs ] || grep -rqI 'rendezvous_mediator' src/ libs/ --include=*.rs 2>/dev/null; then
  echo "  FAIL R-D4 Stage 3/R-SV10: the inherited rendezvous_mediator module name is back (it is renamed to direct_service)"; rc=1
else
  echo "  ok  R-D4 Stage 3/R-SV10 module renamed rendezvous_mediator -> direct_service (the spec token 'mod rendezvous_mediator' is grep-absent; the module is honestly the direct-only service path)"
fi
# R-D4 Stage 4 / R-SV4 / R-SV10 / §8: the rendezvous WIRE PROTOCOL itself is removed from
# rendezvous.proto. Stage 2 removed the mediator HANDLERS (Rust); this removes the MESSAGES they spoke
# -- RendezvousMessage (the ~22-variant oneof: RegisterPeer/PunchHole*/RegisterPk*/RequestRelay/
# RelayResponse/TestNat*/FetchLocalAddr/LocalAddr/ConfigUpdate/SoftwareUpdate/PeerDiscovery/Online*/
# KeyExchange/HealthCheck/HttpProxy*) + the NatType enum. The fork had ZERO senders + its sole reader
# (common.rs get_next_nonkeyexchange_msg) was dead. KEPT: ConnType + ControlPermissions
# (the two types still used on the direct path). The binary can no longer encode/parse a rendezvous
# message (R-SV1 structural absence). The proto comment naming the removed types starts with `//`, so
# the anchored `^message`/`^enum` greps below do not match it.
if grep -qE '^message RendezvousMessage|^message PunchHole|^message RegisterPk|^message RequestRelay|^message RelayResponse|^enum NatType' libs/hbb_common/protos/rendezvous.proto; then
  echo "  FAIL R-D4 Stage 4/R-SV4: the rendezvous wire protocol (RendezvousMessage / PunchHole / NatType / ...) is back in rendezvous.proto"; rc=1
else
  echo "  ok  R-D4 Stage 4/R-SV4 rendezvous wire protocol absent from rendezvous.proto (only ConnType/ControlPermissions remain)"
fi
if grep -qE '^message HeaderEntry\b' libs/hbb_common/protos/rendezvous.proto; then
  echo "  FAIL R-D4/R-SV6: HeaderEntry must stay absent from rendezvous.proto (generic HTTP headers are excised)"; rc=1
else
  echo "  ok  R-D4/R-SV6 HeaderEntry removed from rendezvous.proto (no generic HTTP header payload remains)"
fi
ra6_clean '\bRendezvousMessage\b|rendezvous_message::|get_next_nonkeyexchange_msg' 'R-D4 Stage 4/R-SV4 RendezvousMessage type + oneof submodule + its dead parser' || rc=1
# R-SV4/R-SV10 / §18 (sovereignty): the Change-ID flow's rendezvous-dialing register_pk sender is
# EXCISED. The inherited ui_interface::check_id connect_tcp'd to RENDEZVOUS_PORT and sent RegisterPk
# (registering the device pk + checking ID availability with the rendezvous) — a sovereignty/egress
# leak (R-D6 "dial nobody") and the register_pk R-SV10 greps absent. change_id_shared_ now stores a
# changed ID LOCALLY (the ID is a vestigial label — R-SV5 connects by IP, never by ID). Assert no
# register_pk SENDER (set_register_pk) or the check_id rendezvous-dial helper survives.
ra6_clean 'set_register_pk|async fn check_id' 'R-SV4/R-SV10 Change-ID register_pk rendezvous-dial' || rc=1
# R-SV4(e)/R-S11: the service IPC handler's mediator-control arm that reached an OUTBOUND rendezvous
# DIAL is REMOVED OUTRIGHT (§8 "removed not disabled"). Upstream's Data::TestRendezvousServer ->
# crate::test_rendezvous_server (connect_tcp to RENDEZVOUS_PORT, latency-probing each configured
# rendezvous) was first neutered to a no-op; the whole IPC message is now gone — the variant, its
# (zero-caller) ipc::test_rendezvous_server sender, AND the no-op handler arm — so a local IPC message
# can no longer even NAME a rendezvous dial. The dead common::refresh_rendezvous_server wrapper (the
# message's only would-be caller) is removed with it. (Data::Deployed, the mediator-redeploy arm, is
# likewise REMOVED — R-SV6(c)/R-D4 — with its dead notify_deployed() sender and the NEEDS_DEPLOY flag.)
if grep -qE 'TestRendezvousServer' src/ipc.rs || grep -qE 'fn refresh_rendezvous_server' src/common.rs; then
  echo "  FAIL R-SV4(e)/R-S11: an IPC rendezvous-dial residue survives (Data::TestRendezvousServer in ipc.rs or refresh_rendezvous_server in common.rs must be fully removed)"; rc=1
else
  echo "  ok  R-SV4(e)/R-S11 IPC rendezvous-dial message fully removed (Data::TestRendezvousServer variant+sender+handler + refresh_rendezvous_server wrapper gone; Data::Deployed removed)"
fi
# R-SV4(d)/R-SV10 (sovereignty): the rendezvous-server LATENCY PROBE itself — crate::test_rendezvous_server,
# which spawned a startup outbound connect_tcp to RENDEZVOUS_PORT on each configured broker to pick the
# fastest one — is EXCISED outright (the function AND every caller: src/main.rs flutter/cli mains,
# src/cli.rs, src/flutter_ffi.rs). The fork is direct-IP only (RENDEZVOUS_SERVERS empty, R-SV4) so there
# is NO broker to probe; R-SV10's symbol list names test_rendezvous_server as one that MUST be absent —
# not merely dead-by-empty-config (a config-write to rendezvous-servers + serial could otherwise revive
# its egress). Assert the symbol is gone (explanatory comments excepted by ra6_clean's `//` filter).
ra6_clean 'test_rendezvous_server' 'R-SV4(d)/R-SV10 rendezvous-server latency-probe startup phone-home' || rc=1
# R-X10 (§8 run-mode plurality): the GUI/client (`is_server == false`) startup path NEVER auto-starts
# a controlled server — the controlled side starts ONLY via the installed `--service`/`--server` (one
# mode, R-D8). The inherited `else { start_server(true) }` fallback in server.rs's `is_server == false`
# branch (a SECOND, non-installed-service way to run the controlled side — the portable/quick-support/
# run-from-terminal twin) is removed. Assert NO non-comment `start_server(true)` survives in server.rs
# (the legitimate `start_server(true, false)` entries live in core_main.rs's `--server` arm, KEPT).
r_x10_n=$(grep -E 'start_server\(true' src/server.rs 2>/dev/null | grep -vcE '//' || true)
if [ "${r_x10_n:-1}" -eq 0 ]; then
  echo "  ok  R-X10 GUI/client path never auto-starts a controlled server (server-fallback removed; controlled = installed --service only)"
else
  echo "  FAIL R-X10: a start_server(true) fallback survives in server.rs's is_server==false branch (found ${r_x10_n} non-comment)"; rc=1
fi
# R-X10 (cont.): the --no-server flag + its vestigial no_server param are compiled out (the GUI never
# starts a controlled server, so the flag was redundant; ipc.rs's main-window restart no longer passes
# it; start_server is now 1-arg). Assert the flag string is absent (R-A6).
ra6_clean '"--no-server"' 'R-X10 --no-server flag (the GUI never starts a controlled server -> compiled out)' || rc=1
# R-D6 / §18 (sovereignty): the box never phones home with audit logs. The connection/alarm/file
# audit POST helpers (post_conn_audit/post_alarm_audit/post_file_audit -> <api-server>/api/audit/*)
# are EXCISED — absent, not merely api-server-pinned — so an audit-egress leak cannot regress in.
ra6_clean 'post_conn_audit|post_alarm_audit|post_file_audit' 'R-D6 audit phone-home (conn/alarm/file POST)' || rc=1
# R-D6(d)(iii)/R-S11: socks/proxy is INERT AT THE ACCESSOR. set_socks/get_socks/get_network_type bypass
# the get_option funnel (they read the structured CONFIG2.socks field), so the PINNED_SETTINGS proxy-url
# pin does not reach them — the inherited guard only checked the RustDesk-SIGNED OVERWRITE_SETTINGS, which
# is EMPTY on a fork, leaving set_socks LIVE. The fork makes each accessor consult the proxy-url pin
# DIRECTLY (pinned_setting), so the historical local IPC proxy write cannot install a proxy (a
# local-MITM / egress-reroute primitive, or trigger CheckTestNatType's is_direct to fire
# a STUN UDP probe). Behavior is proven by config_it (socks_is_inert_under_the_proxy_pin); this is belt.
r_d6socks_n=$(grep -c 'pinned_setting(keys::OPTION_PROXY_URL).is_some()' libs/hbb_common/src/config.rs 2>/dev/null || echo 0)
if [ "${r_d6socks_n:-0}" -ge 3 ]; then
  echo "  ok  R-D6(d)(iii) socks/proxy inert at the accessor (set_socks/get_socks/get_network_type honor the proxy-url pin; behavior-tested by config_it)"
else
  echo "  FAIL R-D6(d)(iii): socks accessors not all inert-at-accessor (found ${r_d6socks_n}/3 proxy-url pin checks in config.rs)"; rc=1
fi
# R-SV6(b)/R-SV1/R-SV10 / §18: the session-record UPLOAD egress (hbbs_http::record_upload — a reqwest
# POST of the recorded session to <api-server>/api/record) is EXCISED — the whole module is removed
# from the tree, not merely its is_enable() neutralized (the prior state). Recording stays local
# (R-D6 dial-nobody). The video_service caller now hard-codes the upload channel to None.
ra6_clean 'record_upload|api/record\b' 'R-SV6(b) session-record upload egress' || rc=1
# R-SV3 / R-SV1 (§18 sovereignty): the version-check phone-home is DELETED structurally, not
# neutered. Upstream's hbb_common `version_check_request` built a device-fingerprinted POST
# (os/arch/device_id) to a HARDWIRED api.rustdesk.com/version endpoint — a global-reaching egress
# the R-D6 api-server pin never covered, fired ~1s after launch by the Dart `checkUpdate`. That
# caller + the egress worker were already gone and `check_software_update` neutered; this locks in
# the BUILDER's removal so no version_check_request / VersionCheck{Request,Response} / hardwired
# api.rustdesk.com endpoint survives in the binary (Dart-side excision comments are `//`-filtered).
ra6_clean 'version_check_request|VersionCheckRequest|VersionCheckResponse|VER_TYPE_RUSTDESK|api\.rustdesk\.com' 'R-SV3 version-check phone-home (api.rustdesk.com builder)' || rc=1
# R-SV6(b)/R-SV3/R-X3/R-SV4(e) / §18: the HBBS heartbeat/sysinfo POST loop and its
# namespace are excised — it POSTed get_sysinfo() to <api-server>/api/{heartbeat,sysinfo}
# and adopted server `strategy` config via handle_config_options (R-X3's heartbeat re-home
# twin). The worker, re-home handler, and the old local stub namespace are all absent.
if [ -e src/hbbs_http.rs ] || [ -d src/hbbs_http ]; then
  echo "  FAIL R-SV6(b): src/hbbs_http* is back (heartbeat/sysinfo/account namespace must be absent)"; rc=1
else
  echo "  ok  R-SV6(b) hbbs_http namespace files absent"
fi
ra6_clean 'api/heartbeat|api/sysinfo|heartbeat_url|handle_config_options|start_hbbs_sync_async|start_hbbs_sync|hbbs_http::sync|mod hbbs_http|signal_receiver\(|is_pro\(' 'R-SV6(b) HBBS heartbeat/sysinfo egress + sync namespace' || rc=1
# R-S18 / Appendix C #22: the viewer's auto-sent OS-credential leak is removed — upstream
# built `os_login: Some(OSLogin {os-username, os-password})` + the hwid device fingerprint
# into the LoginRequest on EVERY connect (client.rs create_login_msg), so a substituted
# peer (answering at the same address) harvested the operator's stored OS creds with no interaction. The responder
# already ignores os_login (0685c28); deleting the sender completes the symmetric removal.
ra6_clean 'Some\(OSLogin|\.set_logon\(|ElevateWithLogon|elevate_with_logon' 'R-S18 viewer os_login + elevation-with-logon senders' || rc=1
ra6_clean '\bget_hwid\b' 'R-S18 stable hardware-fingerprint helper' || rc=1
# R-S18 / Appendix C: the OSLogin message + the `os_login` field (12) are now DELETED from
# message.proto entirely (field 12 retired, not reused) and every responder read is gone. The
# responder used to clear+ignore a parsed os_login (R-X14); now the peer cannot encode an OS
# username/password into the LoginRequest AT ALL -- structural absence in the parsed auth protocol,
# not a runtime strip. (The two cfg(windows) login branches that read os_login.username -- the dead
# "installed version" refuse + the prelogin guard -- are removed/simplified accordingly.)
ra6_clean '\bOSLogin\b|\bos_login\b' 'R-S18 OSLogin message + os_login field/reads (peer OS-credential in the parsed LoginRequest)' || rc=1
if grep -qE '^\s*message OSLogin|^\s*OSLogin +os_login' libs/hbb_common/protos/message.proto; then
  echo "  FAIL R-S18: the OSLogin message or os_login field declaration is back in message.proto"; rc=1
else
  echo "  ok  R-S18 OSLogin message + os_login field absent from message.proto (field 12 retired)"
fi
# R-S18 / R-S2 / R-S6: the legacy LoginRequest.password salted-hash credential is deleted too.
# The PAKE is the sole authenticator; LoginRequest carries only session metadata. The deleted
# credential/HWID tags stay reserved together so protobuf regeneration cannot silently reuse them.
r_s18_password=
grep -qE '^\s*bytes +password *= *2\b' libs/hbb_common/protos/message.proto && r_s18_password="$r_s18_password proto-field2-live"
grep -qE '^\s*reserved +2, *12, *14;' libs/hbb_common/protos/message.proto || r_s18_password="$r_s18_password proto-deleted-tags-2-12-14-not-reserved"
grep -RInE '\blr\.password\b' src/server --include='*.rs' 2>/dev/null | grep -v '//' >/dev/null && r_s18_password="$r_s18_password responder-lr-password-read"
client_login_request_init=$(awk '/let mut lr = LoginRequest \{/{flag=1} flag{print} flag && /\.\.Default::default\(\)/{flag=0}' src/client.rs)
if [ -z "$client_login_request_init" ]; then
  r_s18_password="$r_s18_password client-loginrequest-init-missing"
elif printf '%s\n' "$client_login_request_init" | grep -qE '^[[:space:]]*password[[:space:]]*:'; then
  r_s18_password="$r_s18_password client-sends-password-field"
fi
ra6_clean '\bos_username\b|\bos_password\b' 'R-S18 Rust session-login OS-credential fields/parameters' || rc=1
if [ -n "$r_s18_password" ]; then
  echo "  FAIL R-S18: legacy LoginRequest.password credential deletion gap:$r_s18_password"; rc=1
else
  echo "  ok  R-S18 LoginRequest password/os_login/hwid tags retired (fields 2/12/14 reserved; no sender/responder read)"
fi
# R-S18 / Appendix C #22 (cont.): the persisted os-username/os-password OPTION READS the spec names
# for deletion are gone from the Rust viewer — get_option("os-username"/"os-password") + should_auto_login()
# (which returned the STORED os-password to auto-type into the remote OS on connect, a persisted second
# OS credential). The manual input_os_password path (operator types a FRESH password — not persisted,
# not named by R-S18) stays.
ra6_clean 'get_option\("os-username"\)|get_option\("os-password"\)|fn should_auto_login' 'R-S18 viewer persisted os-credential reads (.rs)' || rc=1
# (The former sciter "OS Password" persistence cluster in src/ui/header.tis is gone with the entire
# Sciter UI — R-B6 — so that .tis gate is subsumed by the R-B6 deletion gate above.)
# R-S15 (Appendix C #19): the viewer's in-session PeerConfig writes from peer-controlled data MUST be
# funnelled through a validated allowlist before save_config — a keyed-but-hostile host (§4.4) must not
# inject unbounded/injection strings into the on-disk config. The initiator-side twin of the responder's
# R-S11 gate. This gate VALUE-asserts the SPECIFIC named writes are routed (not mere token presence,
# which passed green despite the service_id sibling write being unbounded): (a) PeerInfo + service_id
# clamped via hbb_common::config::bound_peer_config_string; (b) the privacy-mode impl_key REJECTED
# unless it is in the compile-time get_supported_privacy_mode_impl() set, and peer privacy-mode status
# may persist only as a response to a local outbound toggle request. KAT: config_it tests/r_s15.rs.
r_s15_missing=
for f in src/client.rs src/client/io_loop.rs; do
  grep -q 'bound_peer_config_string' "$f" || r_s15_missing="$r_s15_missing $f:bound-absent"
done
# the TerminalResponse.service_id write is bounded — AND the raw unbounded clone is gone (regression guard)
grep -q 'bound_peer_config_string(&opened.service_id)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing service_id-unbounded"
grep -qE 'set_option\(key, opened\.service_id\.clone' src/client/io_loop.rs && r_s15_missing="$r_s15_missing service_id-RAW-write-present"
# the privacy-mode impl_key is allowlist-validated against the supported set before the insert
grep -q 'get_supported_privacy_mode_impl()' src/client/io_loop.rs || r_s15_missing="$r_s15_missing impl_key-unvalidated"
# peer BackNotification::PrivacyModeState is status, not write authority: persistence requires a pending
# local privacy-mode request recorded by the Rust I/O loop after an outbound toggle send.
grep -q 'struct PendingPrivacyModeRequest' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-pending-request-missing"
grep -q 'enum PrivacyModeResponseAdmission' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-response-admission-missing"
grep -q 'fn from_message(msg: &Message, default_remote_session: bool)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-request-not-session-bound"
grep -q 'misc::Union::TogglePrivacyMode(toggle)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-toggle-request-not-recorded"
grep -q 'option.privacy_mode.enum_value' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-legacy-option-request-not-recorded"
grep -q 'record_pending_privacy_mode_request(&msg)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-ui-toggle-send-not-recorded"
grep -q 'record_pending_privacy_mode_request(&msg_out)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-auto-toggle-send-not-recorded"
grep -q 'privacy_mode_response_admission(state, &impl_key)' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-response-not-classified"
grep -q 'persist_privacy_mode_response_if_admitted' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-persist-helper-missing"
r_s15_privacy_persist_calls=$(grep -c 'self.update_privacy_mode(impl_key' src/client/io_loop.rs || true)
[ "$r_s15_privacy_persist_calls" -eq 1 ] || r_s15_missing="$r_s15_missing privacy-direct-persist-call-count:$r_s15_privacy_persist_calls"
grep -q 'privacy_mode_response_classifier_requires_matching_pending_request' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-response-match-test-missing"
grep -q 'privacy_mode_response_classifier_handles_off_and_expiry' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-response-expiry-test-missing"
grep -q 'privacy_mode_pending_request_is_recorded_only_from_local_remote_toggle' src/client/io_loop.rs || r_s15_missing="$r_s15_missing privacy-request-record-test-missing"
# peer-controlled version/platform may determine the effective runtime keyboard mode, but must not
# select or rewrite the operator-owned persisted PeerConfig.keyboard_mode.
r_s15_peer_info_body="$(sed -n '/pub fn handle_peer_info(&mut self, pi: &PeerInfo)/,/pub fn get_remote_dir/p' src/client.rs)"
printf '%s\n' "$r_s15_peer_info_body" | grep -qE 'keyboard_mode|get_supported_keyboard_modes|is_keyboard_mode_supported' &&
  r_s15_missing="$r_s15_missing peer-info-keyboard-mode-persistence"
grep -q 'peer_info_does_not_choose_saved_keyboard_mode' src/client.rs || r_s15_missing="$r_s15_missing keyboard-mode-empty-regression-test"
grep -q 'peer_info_does_not_rewrite_saved_keyboard_mode' src/client.rs || r_s15_missing="$r_s15_missing keyboard-mode-existing-regression-test"
grep -RIn 'checkDesktopKeyboardMode' flutter/lib >/tmp/rd_verify_r_s15_keyboard_mode.$$ &&
  r_s15_missing="$r_s15_missing flutter-auto-keyboard-mode-persist-helper"
rm -f /tmp/rd_verify_r_s15_keyboard_mode.$$
r_s15_flutter_peer_info="$(sed -n '/handlePeerInfo(Map<String, dynamic> evt/,/notifyListeners()/p' flutter/lib/models/model.dart)"
printf '%s\n' "$r_s15_flutter_peer_info" | grep -qE 'sessionSetKeyboardMode|checkDesktopKeyboardMode' &&
  r_s15_missing="$r_s15_missing flutter-peer-info-keyboard-mode-persistence"
grep -q 'isInputSourceFlutter && isDesktop' flutter/lib/models/input_model.dart || r_s15_missing="$r_s15_missing runtime-flutter-input-fallback"
if [ -n "$r_s15_missing" ]; then
  echo "  FAIL R-S15: peer-config-write allowlist gap:$r_s15_missing"; rc=1
else
  echo "  ok  R-S15 viewer PeerConfig writes routed (PeerInfo+service_id bounded; privacy status requires a pending local request before persistence; peer keyboard-mode compatibility runtime-only)"
fi
# R-A2 (clipboard-file capability parity): the inbound Cliprdr clipboard-FILE arm (connection.rs ~2311)
# drives unix_file_clip::serve_clip_messages — the FUSE context + host-clipboard file:// injection. It
# MUST gate on the SAME capability as the SUBSCRIPTION (can_sub_file_clipboard_service = clipboard +
# file-transfer enabled, NOT one-way), like the text-clipboard arms gate on `if self.clipboard` — not
# merely the peer-reported is_support_file_copy_paste version (no security meaning). This arm is
# #[cfg(unix-file-copy-paste)] (compiled out of (4), compiled IN at (4a)), so this is a source-structure
# gate: assert the combined capability+version gate is present AND the version is no longer the sole gate.
r_clip_file=
grep -A1 'if self.can_sub_file_clipboard_service()' src/server/connection.rs | grep -q 'is_support_file_copy_paste' || r_clip_file="$r_clip_file inbound-cliprdr-not-capability-gated"
grep -qE 'if crate::is_support_file_copy_paste\(&self\.lr\.version\) \{' src/server/connection.rs && r_clip_file="$r_clip_file version-only-sole-gate-present"
if [ -n "$r_clip_file" ]; then
  echo "  FAIL R-A2 clipboard-file inbound arm capability gap:$r_clip_file"; rc=1
else
  echo "  ok  R-A2 inbound clipboard-file (Cliprdr) arm gated on can_sub_file_clipboard_service (not version-only)"
fi
# R-T1 / R-T12 (§20 CRITICAL): the DMZ connection-flood bound + flood-safe observability MUST be
# present — the pre-key handshake semaphore (PREKEY_HANDSHAKE_SLOTS, acquired in the accept loop
# before the task is spawned, server.rs) and the rate-limited AGGREGATED security log
# (note_security_event), so an unauthenticated flood is shed before it can exhaust the host
# WITHOUT the shed itself becoming a log-amplification DoS (R-T0 rule 1). The systemd cgroup caps
# (res/rustdesk.service MemoryMax/TasksMax) bound the blast radius to the service, never the host.
r_t1_missing=
grep -q 'PREKEY_HANDSHAKE_SLOTS' src/server.rs                  || r_t1_missing="$r_t1_missing server.rs:semaphore"
grep -q 'fn note_security_event' src/server.rs                  || r_t1_missing="$r_t1_missing server.rs:agg-log"
grep -q 'fn note_accept_setup_error' src/server.rs              || r_t1_missing="$r_t1_missing server.rs:accept-setup-agg-log"
grep -q 'try_acquire_owned' src/direct_service.rs          || r_t1_missing="$r_t1_missing mediator:acquire-before-spawn"
grep -q 'note_accept_setup_error' src/direct_service.rs    || r_t1_missing="$r_t1_missing accept-setup-errors-not-aggregated"
if grep -q 'direct access from' src/direct_service.rs; then
  r_t1_missing="$r_t1_missing per-accept-info-log"
fi
if grep -q 'failed to set TCP keepalive on' src/direct_service.rs; then
  r_t1_missing="$r_t1_missing per-accept-keepalive-warning"
fi
# R-T1 / R-P14b (active-router threat model): the pre-key handshake SEND must be deadline-bounded, not
# only the read. A malicious router manipulating TCP flow control (a forged zero-window advertisement
# or dropped ACKs) can stall even a sub-buffer-sized CPace send forever; without a send deadline the
# responder/initiator blocks inside `send` holding its R-T1 semaphore permit (+task+fd) indefinitely,
# and 256 such stalls exhaust the slots to deny legitimate handshakes (keepalive can't help — the
# router ACKs probes while pinning the window at zero). send_cpace MUST carry the SAME per-step
# deadline recv_cpace already applies (next_timeout), so the handshake is fully step-bounded in BOTH
# directions and a router-stalled send drops the permit fail-closed. Covers both roles (the responder
# and initiator drivers share send_cpace), per the user's "both sides on a malicious router" model.
grep -qE 'timeout\(HANDSHAKE_STEP_TIMEOUT_MS,[[:space:]]*stream\.send' libs/hbb_common/src/cpace.rs || r_t1_missing="$r_t1_missing cpace.rs:send_cpace-not-deadline-bounded"
# R-T1(a): the memory ceilings MUST be host-RELATIVE percentages, NEVER an absolute byte count — an
# absolute `4G` is a no-op on a 2 GiB box (the spec names this exact regression). Anchored `^…=NN%$`
# fails on MemoryMax=4G / =2147483648 / =infinity; presence-only greps did not. TasksMax is a count.
grep -qE '^MemoryMax=[0-9]+%$'  res/rustdesk.service            || r_t1_missing="$r_t1_missing service:MemoryMax-not-percent"
grep -qE '^MemoryHigh=[0-9]+%$' res/rustdesk.service            || r_t1_missing="$r_t1_missing service:MemoryHigh-not-percent"
grep -qE '^TasksMax=[0-9]+$'    res/rustdesk.service            || r_t1_missing="$r_t1_missing service:TasksMax"
# The fd bound + the auto-restart the R-T1 comment claims but did not check (gap-analysis-3). LimitNOFILE
# is SECURITY-relevant: upstream's 100000 only serves an fd-exhaustion attacker; the fork pins the bounded
# 8192 (single-user headroom). Restart=on-failure keeps the headless box up after a crash; RestartSec the delay.
grep -qE '^LimitNOFILE=8192$'   res/rustdesk.service            || r_t1_missing="$r_t1_missing service:LimitNOFILE(bounded-8192-not-100000)"
grep -qE '^Restart=on-failure$' res/rustdesk.service            || r_t1_missing="$r_t1_missing service:Restart"
grep -qE '^RestartSec=[0-9]+$'  res/rustdesk.service            || r_t1_missing="$r_t1_missing service:RestartSec"
# R-T1(a) self-enforced in the BINARY (launcher-independent — the new MUST; the unit ceilings above are
# now the REDUNDANT outer RSS/task bound): the --server self-applies RLIMIT_NOFILE at startup and rejects
# past a hard global concurrent-authorized-session cap (MAX_AUTHED_SESSIONS) at on_open, so the §20
# fd/session blast-radius bound holds under supervisord / a bare container too, not only the cgroup.
grep -q 'fn self_enforce_resource_limits' src/direct_service.rs              || r_t1_missing="$r_t1_missing self:rlimit-fn"
grep -q 'setrlimit(libc::RLIMIT_NOFILE' src/direct_service.rs                || r_t1_missing="$r_t1_missing self:rlimit-nofile"
# soft-only / hard-preserving: getrlimit reads the inherited hard ceiling, which we KEEP so the
# owner's terminal child (R-F1) can `ulimit -n` back up — a resource bound, not a privilege confinement.
grep -q 'getrlimit(libc::RLIMIT_NOFILE' src/direct_service.rs                || r_t1_missing="$r_t1_missing self:rlimit-hard-preserved"
grep -q 'self_enforce_resource_limits();' src/direct_service.rs              || r_t1_missing="$r_t1_missing self:rlimit-called"
grep -q 'const MAX_AUTHED_SESSIONS' src/server/connection.rs                 || r_t1_missing="$r_t1_missing self:session-cap-const"
grep -q 'AUTHED_CONNS.lock().unwrap().len() >= MAX_AUTHED_SESSIONS' src/server/connection.rs || r_t1_missing="$r_t1_missing self:session-cap-check"
# R-D3a: the unit MUST NOT actively set NoNewPrivileges — it would break the owner's sudo in the
# pinned-ON full-access terminal (R-F1) and the --service sudo -u drop. The launcher provides the
# privilege sandbox WITHOUT this owner-breaking knob; the binary never self-applies one. (A comment
# documenting the omission is fine — only an active `^NoNewPrivileges=` directive is the regression.)
grep -qE '^NoNewPrivileges=' res/rustdesk.service && r_t1_missing="$r_t1_missing service:NoNewPrivileges-set(breaks-owner-sudo)"
if [ -n "$r_t1_missing" ]; then
  echo "  FAIL R-T1: connection-flood bound / flood-safe observability absent:$r_t1_missing"; rc=1
else
  echo "  ok  R-T1/R-T12 connection-flood bound + flood-safe observability present"
fi
# R-T12 (§20): the accept-error arm MUST (a) MAP the fd/resource-exhaustion errnos (EMFILE/ENFILE/
# ENOBUFS / WSAEMFILE/WSAENOBUFS) via raw_os_error() so the operator sees the cause, not a bare int,
# and (b) apply an ESCALATING bounded back-off (a per-streak-counter min(50ms·2^n, 5s)), not a flat
# sleep — under an fd-exhaustion flood the kernel keeps signalling the socket readable while accept()
# returns EMFILE, so a fixed sleep still busy-spins. (The 3-way outcome split + rate-limited
# aggregation are gated by R-T1/R-T12 above.)
r_t12_eb=
grep -qE 'accept_err_streak'              src/direct_service.rs || r_t12_eb="$r_t12_eb no-streak-counter"
grep -qE '\(50u64 << accept_err_streak\.min\(7\)\)\.min\(5000\)' src/direct_service.rs || r_t12_eb="$r_t12_eb no-escalating-bounded-backoff(50<<streak.min7-cap5000)"
grep -qE 'fn accept_error_class'          src/server.rs              || r_t12_eb="$r_t12_eb no-errno-mapper"
grep -qE 'libc::EMFILE|libc::ENFILE'      src/server.rs              || r_t12_eb="$r_t12_eb no-EMFILE-map"
grep -qE 'ACCEPT_ERR_COUNT'               src/server.rs              || r_t12_eb="$r_t12_eb no-accept-error-counter"
grep -qE 'ACCEPT_ERR_LOG_STATE'           src/server.rs              || r_t12_eb="$r_t12_eb no-accept-error-agg-state"
grep -qE 'count=.*last_class='            src/server.rs              || r_t12_eb="$r_t12_eb no-counted-accept-error-summary"
if [ -n "$r_t12_eb" ]; then
  echo "  FAIL R-T12: accept-error escalating-backoff/errno-map incomplete:$r_t12_eb"; rc=1
else
  echo "  ok  R-T12 accept-error escalating bounded back-off + EMFILE/ENFILE errno mapping present"
fi
# R-T0 / Appendix C #2b-adjacent responder display control: authenticated peers must not be
# able to drive native display/capture/virtual-display driver APIs through unchecked signed
# display indexes, unsupported resolution dimensions, or a live virtual-display toggle.
r_display_control=
grep -qF 'pub const OPTION_ENABLE_VIRTUAL_DISPLAY: &str = "enable-virtual-display";' libs/hbb_common/src/config.rs ||
  r_display_control="$r_display_control no-virtual-display-option"
grep -qF '(OPTION_ENABLE_VIRTUAL_DISPLAY, "N")' libs/hbb_common/src/config.rs ||
  r_display_control="$r_display_control virtual-display-not-pinned-off"
grep -qF '        OPTION_ENABLE_VIRTUAL_DISPLAY,' libs/hbb_common/src/config.rs ||
  r_display_control="$r_display_control virtual-display-not-in-keys-settings"
grep -qF '"enable-virtual-display",' libs/config_it/tests/lockdown.rs ||
  r_display_control="$r_display_control virtual-display-pin-not-tested"
grep -qF 'struct DisplayControlRejectLog' src/server/connection.rs ||
  r_display_control="$r_display_control no-display-reject-log-throttle"
grep -qF 'DISPLAY_CONTROL_LOG_INTERVAL' src/server/connection.rs ||
  r_display_control="$r_display_control no-display-reject-log-interval"
grep -qF 'suppressed {} similar events' src/server/connection.rs ||
  r_display_control="$r_display_control no-display-reject-suppression-summary"
grep -qF 'fn validate_peer_display_index' src/server/connection.rs ||
  r_display_control="$r_display_control no-display-index-validator"
grep -qF 'fn validate_peer_display_index_syntax' src/server/connection.rs ||
  r_display_control="$r_display_control no-cheap-display-index-syntax-validator"
grep -qF 'usize::try_from(raw_display)' src/server/connection.rs ||
  r_display_control="$r_display_control no-checked-display-index-conversion"
grep -qF 'fn validate_peer_display_indexes' src/server/connection.rs ||
  r_display_control="$r_display_control no-display-list-validator"
grep -qF 'fn validate_peer_display_indexes_syntax' src/server/connection.rs ||
  r_display_control="$r_display_control no-cheap-display-list-syntax-validator"
grep -qF 'MAX_PEER_CAPTURE_DISPLAY_ENTRIES' src/server/connection.rs ||
  r_display_control="$r_display_control no-capture-display-entry-cap"
grep -qF 'capture display message has multiple non-empty operations' src/server/connection.rs ||
  r_display_control="$r_display_control no-ambiguous-capture-operation-reject"
grep -qF 'let Some(display_count) = self.peer_display_count()' src/server/connection.rs ||
  r_display_control="$r_display_control no-shared-display-enumeration"
grep -qF 'duplicate display index' src/server/connection.rs ||
  r_display_control="$r_display_control no-duplicate-display-reject"
grep -qF 'refresh video display' src/server/connection.rs ||
  r_display_control="$r_display_control refresh-video-display-not-validated"
grep -qF 'message query switch display' src/server/connection.rs ||
  r_display_control="$r_display_control message-query-switch-display-not-validated"
grep -qF 'screenshot request' src/server/connection.rs ||
  r_display_control="$r_display_control screenshot-display-not-validated"
grep -qF '&displays.add,' src/server/connection.rs ||
  r_display_control="$r_display_control capture-add-not-validated"
grep -qF '&displays.sub,' src/server/connection.rs ||
  r_display_control="$r_display_control capture-sub-not-validated"
grep -qF '&displays.set,' src/server/connection.rs ||
  r_display_control="$r_display_control capture-set-not-validated"
if grep -qF 'displays.add.iter().map(|d| *d as usize)' src/server/connection.rs; then
  r_display_control="$r_display_control unchecked-capture-add-cast"
fi
if grep -qF 'self.refresh_video_display(Some(display as usize))' src/server/connection.rs; then
  r_display_control="$r_display_control unchecked-refresh-video-display-cast"
fi
if grep -qF 'request.display as _' src/server/connection.rs || grep -qF 'request.display as usize' src/server/connection.rs; then
  r_display_control="$r_display_control unchecked-screenshot-display-cast"
fi
if grep -qF 'mq.switch_display as _' src/server/connection.rs; then
  r_display_control="$r_display_control unchecked-message-query-switch-display-cast"
fi
if grep -qF 'self.change_resolution(Some(dr.display as _), &dr.resolution)' src/server/connection.rs; then
  r_display_control="$r_display_control unchecked-change-display-resolution-cast"
fi
grep -qF 'validate_peer_resolution_dims' src/server/connection.rs ||
  r_display_control="$r_display_control no-resolution-dimension-validator"
grep -qF 'MAX_PEER_DISPLAY_DIMENSION' src/server/connection.rs ||
  r_display_control="$r_display_control no-resolution-dimension-cap"
grep -qF 'crate::platform::resolutions(&name)' src/server/connection.rs ||
  r_display_control="$r_display_control no-supported-mode-check"
grep -qF 'unsupported mode' src/server/connection.rs ||
  r_display_control="$r_display_control no-unsupported-mode-log"
grep -qF 'refusing peer virtual-display toggle under pinned policy' src/server/connection.rs ||
  r_display_control="$r_display_control virtual-display-toggle-not-policy-gated"
grep -qF 't.display < 0' src/server/connection.rs ||
  r_display_control="$r_display_control virtual-display-negative-index-not-rejected"
if [ -n "$r_display_control" ]; then
  echo "  FAIL R-T0/App.C#2b: responder display-control validation incomplete:$r_display_control"; rc=1
else
  echo "  ok  R-T0/App.C#2b responder display-control messages validate indexes/modes and virtual-display toggles are pinned off"
fi
# R-SV10 (§18, the FIFTH config funnel): LocalConfig::get_option reads the UNPINNED _local namespace —
# unlike Config::get_option it has NO PINNED_SETTINGS head-guard (config.rs). CI MUST assert no
# SECURITY-RELEVANT key resolves through it without a pin or a compile-out (mirroring R-S16(d)(iv)'s
# get_builtin_option treatment). The spec names enable-check-update — the software-updater egress —
# which R-SV3 compiles OUT. The other capability-adjacent LocalConfig readers are #[cfg(windows)]
# (pre-elevate-service @ core_main.rs = the local-pref elevation),
# so the Linux build (the cargo-check gate below) compiles it out — unreachable on the deployed box.
# The remaining readers are benign UI prefs (lang/texture-render/video-dir/input-source/group-panel).
r_sv10=
# (a) no LocalConfig reader resolves the updater-egress key, and the const stays UNDEFINED (R-SV3
#     excised both — only an excision comment remains in config.rs); a re-add of either re-opens it.
grep -rnE 'LocalConfig::get_option[^)]*(OPTION_ENABLE_CHECK_UPDATE|"enable-check-update")' src libs --include=*.rs | grep -qv '//' && r_sv10="$r_sv10 enable-check-update-reader"
grep -rqE '^[[:space:]]*pub const OPTION_ENABLE_CHECK_UPDATE' libs/hbb_common/src/config.rs && r_sv10="$r_sv10 OPTION_ENABLE_CHECK_UPDATE-redefined"
# (b) the local-pref elevation read, IF present, MUST be confined to core_main.rs under #[cfg(windows)]
preelev_sites=$(grep -rlE 'LocalConfig::get_option\("pre-elevate-service"\)' src --include=*.rs || true)
if [ -n "$preelev_sites" ]; then
  [ "$preelev_sites" = "src/core_main.rs" ] || r_sv10="$r_sv10 pre-elevate-service-outside-core_main($preelev_sites)"
  grep -B6 'LocalConfig::get_option("pre-elevate-service")' src/core_main.rs | grep -q '#\[cfg(windows)\]' || r_sv10="$r_sv10 pre-elevate-service-not-windows-gated"
fi
if [ -n "$r_sv10" ]; then
  echo "  FAIL R-SV10: a security-relevant key resolves through the unpinned LocalConfig funnel:$r_sv10"; rc=1
else
  echo "  ok  R-SV10 LocalConfig funnel clean (enable-check-update excised; pre-elevate-service windows-gated)"
fi
# R-D3a (§17): the root service unit carries the launcher sandbox. Linux file
# clipboard is shipped and uses FUSE, so the syscall policy admits only the
# direct FUSE mount/unmount calls and keeps denied syscalls fail-closed.
r_d3a_missing=
grep -qE '^CapabilityBoundingSet='      res/rustdesk.service || r_d3a_missing="$r_d3a_missing CapabilityBoundingSet"
grep -qE '^RestrictAddressFamilies=AF_UNIX AF_INET$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing RestrictAddressFamilies-v4only"
grep -qE '^SystemCallFilter=@system-service mount umount umount2$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing SystemCallFilter-fuse-mounts"
grep -qE '^SystemCallFilter=~@reboot @swap$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing SystemCallFilter-subtraction"
grep -qF 'direct FUSE mount/unmount syscalls' res/rustdesk.service || r_d3a_missing="$r_d3a_missing unit-fuse-syscall-comment"
grep -qF 'direct native <code>mount</code>/<code>umount</code>/<code>umount2</code> syscalls' requirements.html || r_d3a_missing="$r_d3a_missing requirements-fuse-syscall-scope"
grep -RInE 'legacy FUSE mount (path|calls|syscalls)' res/rustdesk.service scripts/verify.sh requirements.html >/tmp/rd_verify_r_d3a_fuse_legacy.$$ &&
  r_d3a_missing="$r_d3a_missing stale-legacy-fuse-mount-wording"
rm -f /tmp/rd_verify_r_d3a_fuse_legacy.$$
grep -qE '^SystemCallErrorNumber=' res/rustdesk.service && r_d3a_missing="$r_d3a_missing SystemCallErrorNumber-fallback"
grep -qE '^SystemCallFilter=.*@mount' res/rustdesk.service && r_d3a_missing="$r_d3a_missing broad-mount-group"
grep -qE '^SystemCallFilter=.*\b(chroot|pivot_root|open_tree|move_mount|fsconfig|fsopen|fsmount|fspick|mount_setattr)\b' res/rustdesk.service && r_d3a_missing="$r_d3a_missing broad-mount-syscall"
grep -qE '^ProtectKernelModules=yes$'       res/rustdesk.service || r_d3a_missing="$r_d3a_missing ProtectKernelModules"
grep -qE '^ProtectKernelTunables=yes$'      res/rustdesk.service || r_d3a_missing="$r_d3a_missing ProtectKernelTunables"
grep -qE '^RestrictRealtime=yes$'           res/rustdesk.service || r_d3a_missing="$r_d3a_missing RestrictRealtime"
grep -qE '^LockPersonality=yes$'            res/rustdesk.service || r_d3a_missing="$r_d3a_missing LockPersonality"
grep -qE '^SystemCallArchitectures=native$' res/rustdesk.service || r_d3a_missing="$r_d3a_missing SystemCallArchitectures-native"
grep -qE '^MemoryDenyWriteExecute=yes$'  res/rustdesk.service || r_d3a_missing="$r_d3a_missing MemoryDenyWriteExecute(validated)"
grep -q 'PR_SET_MDWE' examples/mdwe_codec_probe.rs           || r_d3a_missing="$r_d3a_missing mdwe_codec_probe"
if [ -n "$r_d3a_missing" ]; then
  echo "  FAIL R-D3a: systemd sandbox / validated-MDWE incomplete:$r_d3a_missing"; rc=1
else
  echo "  ok  R-D3a systemd sandbox + FUSE-only mount exception + MemoryDenyWriteExecute present"
fi
# R-T7 (§20): every frame on a KEYED (Dual) stream MUST be AEAD-authenticated — the ≤1-byte
# decrypt bypass is removed (the one path by which a byte could reach the application parser
# unauthenticated; also the closure of the unkeyed→keyed boundary, R-T6). The legacy single-key
# `Encrypt` cipher (which carried the only ≤1-byte bypass) was excised entirely at R-A6, so this
# now asserts ZERO `bytes.len() <= 1` in tcp.rs — the keyed edge is CPace/Dual-only.
r_t7_n=$(grep -c 'bytes.len() <= 1' libs/hbb_common/src/tcp.rs 2>/dev/null || true)
if [ "${r_t7_n:-99}" -gt 0 ]; then
  echo "  FAIL R-T7: a <=1-byte decrypt bypass remains in tcp.rs (found $r_t7_n) — must be ZERO"; rc=1
else
  echo "  ok  R-T7 <=1-byte AEAD bypass fully removed (single-key Encrypt excised, R-A6)"
fi
# R-T2 (§20): the FramedStream poison flag. A keyed stream's write nonce is pre-incremented by
# `seal` before the ciphertext is flushed; reusing a stream after a send error would re-flush
# stale bytes under an advanced nonce and permanently desync the c2s direction. The poison flag
# (the `poison: bool` field, after R-T3 restructured FramedStream to the keying-state machine) makes
# "a send/recv error is fatal-to-the-connection" structural: send_bytes bails when poisoned and sets
# it on any send error; next() returns EOF when poisoned and sets it on any read OR (now codec-fold)
# decrypt/auth failure. Presence gate: the short-circuit guard (>=2 sites: send_bytes + next) and
# the poison-set (>=2 sites: send error, and next's unified read/decrypt error).
r_t2_guard=$(grep -c 'if self.poison {' libs/hbb_common/src/tcp.rs 2>/dev/null || true)
r_t2_set=$(grep -c 'self.poison = true' libs/hbb_common/src/tcp.rs 2>/dev/null || true)
if [ "${r_t2_guard:-0}" -ge 2 ] && [ "${r_t2_set:-0}" -ge 2 ]; then
  echo "  ok  R-T2 FramedStream poison flag present (guard x$r_t2_guard, poison-set x$r_t2_set)"
else
  echo "  FAIL R-T2: poison flag incomplete (guard=$r_t2_guard need>=2, set=$r_t2_set need>=2)"; rc=1
fi
# R-T5 (§20): decryption is FOLDED INTO the Framed-owned codec (SecretboxCodec) — decode()
# reassembles ONE frame then authenticates+decrypts it, advancing read_seq INSIDE decode, so a
# dropped next() (select!/timeout losing the race) cannot desync the recv counter. The cipher
# lives in the codec, inheriting tokio-util's StreamExt::next cancel-safety verbatim. Gate: the
# codec + its Decoder/Encoder impls + the Framed<_,SecretboxCodec> type + the mandated regression
# test (drives next() under a biased select and asserts read_seq unchanged via recv_counter).
r_t5_missing=
grep -q 'pub struct SecretboxCodec' libs/hbb_common/src/tcp.rs              || r_t5_missing="$r_t5_missing codec-struct"
grep -q 'impl Decoder for SecretboxCodec' libs/hbb_common/src/tcp.rs        || r_t5_missing="$r_t5_missing decoder-impl"
grep -q 'impl Encoder<Bytes> for SecretboxCodec' libs/hbb_common/src/tcp.rs || r_t5_missing="$r_t5_missing encoder-impl"
grep -q 'Framed<DynTcpStream, SecretboxCodec>' libs/hbb_common/src/tcp.rs   || r_t5_missing="$r_t5_missing framed-type"
grep -rq 'recv_counter' libs/cpace_it/tests/                               || r_t5_missing="$r_t5_missing regression-test"
if [ -n "$r_t5_missing" ]; then
  echo "  FAIL R-T5: decrypt-in-codec incomplete:$r_t5_missing"; rc=1
else
  echo "  ok  R-T5 decrypt folded into SecretboxCodec (read_seq advances in decode) + regression test"
fi
# R-T7/R-A1 follow-on: after AEAD succeeds, a malformed protobuf `Message` frame is still an
# authenticated protocol violation. It MUST close/poison the session, not be silently ignored and
# leave the keyed connection in a weird state. Gate both post-key dispatch roots: responder
# (connection.rs) and initiator/viewer (client/io_loop.rs). The old pattern was:
#   if let Ok(msg_in) = Message::parse_from_bytes(...) { dispatch(msg_in) }
# with no `else`; that made parse failures no-ops.
r_t7_parse_missing=
grep -q 'Malformed post-key Message frame' src/server/connection.rs || r_t7_parse_missing="$r_t7_parse_missing server-close-marker"
grep -q 'Malformed post-key Message frame from peer' src/client/io_loop.rs || r_t7_parse_missing="$r_t7_parse_missing client-close-marker"
if grep -qE 'if let Ok\(msg_in\) = Message::parse_from_bytes\(&?(bytes|data)\)' src/server/connection.rs src/client/io_loop.rs; then
  r_t7_parse_missing="$r_t7_parse_missing silent-if-let-parse-regressed"
fi
if [ -n "$r_t7_parse_missing" ]; then
  echo "  FAIL R-T7/R-A1: malformed post-key Message parse does not fail closed:$r_t7_parse_missing"; rc=1
else
  echo "  ok  R-T7/R-A1 malformed post-key Message parse fails closed (server + viewer)"
fi
# R-T8 / R-T16 (§20): the single-writer + framing/processing-order contract is CODIFIED at the
# FramedStream type (and at the Connection.stream owner) so a refactor cannot silently regress to
# a second writer (wire-interleave / cipher desync) or to parsing a raw TCP segment. The invariant
# already holds structurally — the write API is &mut self, the type owns a Box<dyn> socket and is
# not Clone, and the stream is never split / Arc<Mutex>-wrapped — so this gate (a) keeps the
# contract docs present and (b) forbids the one realistic second-writer regression: an Arc<Mutex>
# write-wrapper or a `.split()` of the stream in CODE (doc-comment mentions, `///`, are excluded).
r_t8_missing=
grep -q 'Single-writer contract (R-T8' libs/hbb_common/src/tcp.rs        || r_t8_missing="$r_t8_missing tcp-writer-doc"
grep -q 'Framing + processing-order contract (R-T16' libs/hbb_common/src/tcp.rs || r_t8_missing="$r_t8_missing tcp-framing-doc"
grep -q 'the single writer' src/server/connection.rs                     || r_t8_missing="$r_t8_missing conn-stream-doc"
# R-T3 introduces exactly ONE controlled split — set_session_keys splits the keyed Framed so the write
# half goes to the SOLE dedicated writer task (single-writer preserved, NOT a second writer). Forbid any
# OTHER code split, and assert this one has the R-T3 shape feeding writer_task (doc `///` mentions excluded).
code_splits=$(grep -n '\.split()' libs/hbb_common/src/tcp.rs 2>/dev/null | grep -v '///' | wc -l)
if [ "$code_splits" != "1" ]; then
  r_t8_missing="$r_t8_missing tcp-split-count=$code_splits(want exactly the 1 R-T3 writer-task split)!"
fi
grep -q 'let (sink, read) = framed.split();' libs/hbb_common/src/tcp.rs || r_t8_missing="$r_t8_missing rt3-split-shape"
grep -q 'tokio::spawn(writer_task(sink,'     libs/hbb_common/src/tcp.rs || r_t8_missing="$r_t8_missing rt3-sole-writer-consumer"
if grep -rn 'Arc<.*Mutex<.*FramedStream' src libs/hbb_common/src 2>/dev/null | grep -vq '///'; then
  r_t8_missing="$r_t8_missing arc-mutex-framedstream!"
fi
if [ -n "$r_t8_missing" ]; then
  echo "  FAIL R-T8/R-T16: single-writer/framing contract codification incomplete or violated:$r_t8_missing"; rc=1
else
  echo "  ok  R-T8/R-T16 single-writer + framing/processing-order contract codified (no second-writer handle)"
fi
# R-T9 (§20): graceful shutdown on SIGTERM/SIGINT. A process-wide CancellationToken (server.rs) is
# cancelled by the signal handler (direct_service.rs); the accept loop then stops accepting and
# drops its listener, every live session's run-loop drains via its `cancelled()` select-arm
# (CloseReason -> flush -> CM Close), and a BOUNDED drain deadline — shorter than the unit's
# TimeoutStopSec — precedes a force-exit(0). The unit cgroup's TimeoutStopSec/SIGKILL path stays the backstop.
# Presence gate across the three layers (server primitive, connection drain arm, mediator handler).
r_t9_missing=
grep -q 'fn begin_graceful_shutdown' src/server.rs         || r_t9_missing="$r_t9_missing begin_graceful_shutdown"
grep -q 'fn is_shutting_down' src/server.rs                || r_t9_missing="$r_t9_missing is_shutting_down"
grep -q 'SHUTDOWN_TOKEN' src/server.rs                     || r_t9_missing="$r_t9_missing SHUTDOWN_TOKEN"
grep -q 'shutdown.cancelled()' src/server/connection.rs    || r_t9_missing="$r_t9_missing conn-drain-arm"
grep -q 'flush_writer' libs/hbb_common/src/tcp.rs          || r_t9_missing="$r_t9_missing writer-drain-method"
grep -q 'WriterCommand::Drain' libs/hbb_common/src/tcp.rs  || r_t9_missing="$r_t9_missing writer-drain-command"
grep -q 'self.stream.flush_writer().await' src/server/connection.rs || r_t9_missing="$r_t9_missing close-reason-flush"
grep -q 'SignalKind::terminate' src/direct_service.rs || r_t9_missing="$r_t9_missing sigterm-handler"
grep -q 'is_shutting_down()' src/direct_service.rs    || r_t9_missing="$r_t9_missing accept-stop"
grep -qE '^TimeoutStopSec=[1-9][0-9]*$' res/rustdesk.service || r_t9_missing="$r_t9_missing service-TimeoutStopSec(must be a positive drain backstop, =0 is infinite)"
grep -qE '^KillMode=control-group$' res/rustdesk.service || r_t9_missing="$r_t9_missing service-KillMode-control-group"
if grep -qE '^ExecStop=|pkill|KillMode=mixed' res/rustdesk.service; then
  r_t9_missing="$r_t9_missing legacy-pkill-or-mixed-stop"
fi
if [ -n "$r_t9_missing" ]; then
  echo "  FAIL R-T9: graceful-shutdown machinery incomplete:$r_t9_missing"; rc=1
else
  echo "  ok  R-T9 graceful shutdown present (signal handler + accept-stop + drain arm + bounded exit)"
fi
# R-T14 (§20): the cross-backend cancellation-safety guarantee — dropping a tokio read future
# consumes ZERO bytes on epoll/kqueue/IOCP because mio's do_io does a synchronous std recv (no
# kernel overlapped buffer in flight) — MUST be documented WITH its mio/tokio citation at the read
# site (the basis R-T5 relies on), so a contributor cannot "fix" it with a hand-rolled WSARecv
# overlapped read that would reintroduce a real per-OS hazard. Presence gate on the citation.
r_t14_missing=
grep -q 'R-T14' libs/hbb_common/src/tcp.rs                   || r_t14_missing="$r_t14_missing anchor"
grep -q 'mio 1.0.3 / tokio 1.44.2' libs/hbb_common/src/tcp.rs || r_t14_missing="$r_t14_missing citation"
grep -q 'do_io' libs/hbb_common/src/tcp.rs                   || r_t14_missing="$r_t14_missing do_io-basis"
if [ -n "$r_t14_missing" ]; then
  echo "  FAIL R-T14: cross-backend cancellation-safety citation incomplete:$r_t14_missing"; rc=1
else
  echo "  ok  R-T14 cross-backend cancellation-safety guarantee documented (mio/tokio cited at read site)"
fi
# R-S9 / R-D2 (§20): there is NO in-app source-IP ACL — CPace is the sole gate (the bar is SSH), and
# source-IP scoping belongs at the firewall (which sheds in the kernel before the process). The
# post-key check_whitelist/whitelist_admits filter and the `whitelist` option MUST be fully excised
# (symbol-absent), not merely default-open.
r_s9_present=
grep -Eq 'fn whitelist_admits|check_whitelist' src/server/connection.rs src/direct_service.rs && r_s9_present="$r_s9_present whitelist-fn-present!"
grep -q 'OPTION_WHITELIST' libs/hbb_common/src/config.rs && r_s9_present="$r_s9_present option-const-present!"
if [ -n "$r_s9_present" ]; then
  echo "  FAIL R-S9/R-D2: in-app source ACL not fully excised:$r_s9_present"; rc=1
else
  echo "  ok  R-S9/R-D2 no in-app source ACL (check_whitelist/whitelist_admits/OPTION_WHITELIST absent) — CPace is the sole gate"
fi
# (R-S9/BUG3 flutter whitelist-UI polarity gate removed — the whitelist settings UI itself is now excised
# (§19 dead-UI: the A1 backend removal left consts.kOptionWhitelist / common.whitelistNotEmpty /
# dialog.changeWhiteList / the mobile+desktop toggles dead, all now gone), so there is no UI polarity left
# to police. The R-S9 backend-absence gate above remains the live whitelist gate.)
# R-T10 (§20): TCP keepalive on every accepted peer socket — the kernel backstop the NAT'd-client
# reality demands (idle/rebinding/sleeping NAT mappings vanish WITHOUT a FIN/RST, so a dead peer
# would otherwise hold an fd+task+capture+CM until the app deadline). Set at the accept site via
# socket2 0.5's SockRef + TcpKeepalive (with_time + with_interval; with_retries compiled out on
# Windows), the app 30s deadline staying the portable primary. Gate: the 0.5 dep + accept-site call.
r_t10_missing=
grep -q '^socket2 = "0.5"' Cargo.toml                  || r_t10_missing="$r_t10_missing socket2-0.5-dep"
grep -q 'set_tcp_keepalive' src/direct_service.rs || r_t10_missing="$r_t10_missing keepalive-call"
grep -q 'with_time' src/direct_service.rs         || r_t10_missing="$r_t10_missing with_time-knob"
if [ -n "$r_t10_missing" ]; then
  echo "  FAIL R-T10: TCP keepalive on accepted sockets incomplete:$r_t10_missing"; rc=1
else
  echo "  ok  R-T10 TCP keepalive set on accepted peer sockets (SockRef + TcpKeepalive, app deadline primary)"
fi
# R-T3 (§20): the dedicated WRITER TASK so the reader/control channels stay pollable DURING a write.
# set_session_keys splits the keyed Framed — the read half stays on the run-loop (decode + recv-AEAD),
# the write half moves into a SINGLE dedicated writer task (the sole sink consumer, R-T8) fed an mpsc of
# ALREADY-SEALED frames. The run-loop's send_bytes SEALS on the single-producer enqueue side (the nonce
# advances in channel-FIFO order) then try_sends NON-BLOCKING; a full BOUNDED channel is the back-pressure
# liveness signal that DROPS the connection — REPLACING R-T2's per-write deadline (so the old
# set_send_timeout-on-the-keyed-session is GONE). Lock the chain so it cannot regress to a send().await
# inside a select! branch (which would freeze reads/CM/timers for the duration of one write).
r_t3_missing=
grep -q 'async fn writer_task('          libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing writer-task-fn"
grep -q 'tokio::spawn(writer_task(sink,' libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing spawn-sole-writer"
grep -q 'const WRITER_CHANNEL_CAP'       libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing bounded-channel"
grep -q 'try_send(WriterCommand::Frame'  libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing nonblocking-enqueue"
grep -q 'TrySendError::Full'             libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing full-drops-connection"
grep -q 'k.seal.seal(&bytes)'            libs/hbb_common/src/tcp.rs || r_t3_missing="$r_t3_missing producer-side-seal"
# R-T2's per-write deadline is REPLACED by the channel bound — the keyed session must NOT install a
# set_send_timeout (a stale one would be a misleading no-op now that the keyed path uses try_send).
if grep -q 'set_send_timeout' src/server/connection.rs libs/hbb_common/src/stream.rs; then
  r_t3_missing="$r_t3_missing stale-set_send_timeout!"
fi
if [ -n "$r_t3_missing" ]; then
  echo "  FAIL R-T3: dedicated writer-task transport incomplete:$r_t3_missing"; rc=1
else
  echo "  ok  R-T3 dedicated writer task (split sink -> sole writer, producer-side seal, bounded back-pressure drop replaces the per-write deadline)"
fi
# R-T15(b) / R-S10: the inherited LOGIN_FAILURES limiter — unbounded-growth / never-decaying /
# full-IPv6-keyed, and on dead paths (the legacy unkeyed/salted-hash login is gone) — MUST be
# excised so the live online-guess limiter is unambiguously the bounded, decaying, per-v4-source
# GUESS_FAILURES in cpace.rs (R-P14c). Gate: no LOGIN_FAILURES reference remains in CODE (the
# excision-documenting comments are allowed), and GUESS_FAILURES (the live limiter) is still present.
r_t15b_missing=
grep -q 'static ref LOGIN_FAILURES' src/server/connection.rs && r_t15b_missing="$r_t15b_missing static-present!"
grep -q 'fn check_failure_ipv6_prefix' src/server/connection.rs && r_t15b_missing="$r_t15b_missing ipv6-helper-present!"
grep -q 'fn get_ipv6_prefixes' src/server/connection.rs && r_t15b_missing="$r_t15b_missing prefixes-helper-present!"
grep -q 'GUESS_FAILURES' libs/hbb_common/src/cpace.rs || r_t15b_missing="$r_t15b_missing guess-failures-MISSING!"
if [ -z "$r_t15b_missing" ]; then
  echo "  ok  R-T15(b) LOGIN_FAILURES limiter excised (GUESS_FAILURES remains the live limiter)"
else
  echo "  FAIL R-T15(b): excision incomplete:$r_t15b_missing"; rc=1
fi
# R-S10(b): the live online-guess limiter (GUESS_FAILURES, cpace.rs) MUST be bounded by VALUE, not just
# present — a HARD entry-count ceiling (MAX_TRACKED_SOURCES) with oldest-window eviction ON TOP of the
# time-eviction, plus a finite per-source threshold and window. Value-assert the named constants + the
# eviction path + the flood-cap KAT (cpace_it/tests/guess_limiter_cap.rs, run under -p cpace_it above),
# so a regression to unbounded / never-decaying tracking fails closed (presence-only would not catch it).
r_s10b=
grep -qE '^const MAX_TRACKED_SOURCES: usize = 8192;'                  libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-8192-cap"
grep -qE 'while map\.len\(\) > MAX_TRACKED_SOURCES'                   libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-cap-eviction"
grep -qE '^const MAX_GUESSES_PER_WINDOW: u32 = 10;'                   libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-threshold-value"
grep -qE '^const GUESS_WINDOW: Duration = Duration::from_secs\(60\);' libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-window-value"
grep -qE 'map\.retain'                                               libs/hbb_common/src/cpace.rs || r_s10b="$r_s10b no-time-eviction"
[ -f libs/cpace_it/tests/guess_limiter_cap.rs ]                                                   || r_s10b="$r_s10b no-cap-KAT"
if [ -z "$r_s10b" ]; then
  echo "  ok  R-S10(b) online-guess limiter bounded by value (8192-source cap + oldest-eviction + 10/60s + KAT)"
else
  echo "  FAIL R-S10(b): limiter bound weakened:$r_s10b"; rc=1
fi
# R-T4 (§20): per-connection cleanup and external notification MUST run on cancellation, so the
# synchronous cleanup lives in Connection::Drop (which Rust runs when the run-loop future is dropped
# at its await), not only in the normal post-loop tail. The CM lifecycle is shared on Linux headless
# (connection.rs first reuses an existing uid-scoped `_cm` socket), so a literal per-connection
# kill_on_drop would kill a CM still serving another connection. The equivalent invariant is now
# explicit and gated: Drop sends Data::Close to the CM IPC client synchronously; `--cm-no-ui` opts
# into idle-exit; and the CM process exits once its last IPC client is removed. The global
# CHILD_PROCESS list is only the zombie reaper for spawned children, not the lifecycle control.
r_t4_missing=
grep -q 'the per-connection cleanup that was previously straight-line' src/server/connection.rs || r_t4_missing="$r_t4_missing drop-cleanup"
grep -q 'have MOVED into' src/server/connection.rs || r_t4_missing="$r_t4_missing tail-note"
grep -qF 'self.tx_to_cm.send(ipc::Data::Close)' src/server/connection.rs || r_t4_missing="$r_t4_missing drop-cm-close"
grep -q 'static EXIT_ON_IDLE: AtomicBool' src/ui_cm_interface.rs || r_t4_missing="$r_t4_missing cm-idle-flag"
grep -q 'set_exit_on_idle(true)' src/flutter.rs || r_t4_missing="$r_t4_missing cm-no-ui-idle-wire"
grep -q 'no-ui connection manager idle after last IPC client; exiting' src/ui_cm_interface.rs || r_t4_missing="$r_t4_missing cm-idle-exit"
if [ -z "$r_t4_missing" ]; then
  echo "  ok  R-T4 cancellation-safe teardown + CM notification/lifecycle (Drop close + no-ui idle-exit)"
else
  echo "  FAIL R-T4: teardown cleanup not folded into Drop:$r_t4_missing"; rc=1
fi
# R-T15(a) / R-P12: secret-zeroization in libs/pake — curve25519-dalek 4.1.3 impls the Zeroize
# TRAIT but not Drop, so secrets not explicitly wiped linger on attacker-inducible abort/timeout
# paths. The ISK master secret is wrapped in Zeroizing, the initiator's ephemeral scalar is wiped
# on the decompress-error early-return, and the two *AwaitConfirm states carry a Drop that wipes
# their session keys / ephemeral scalar on the R-P14b step-timeout drop. The KATs check derived
# VALUES, not wiping, so this is a presence gate.
r_t15a_missing=
grep -q 'impl Drop for InitiatorAwaitConfirm' libs/pake/src/lib.rs || r_t15a_missing="$r_t15a_missing InitiatorDrop"
grep -q 'impl Drop for ResponderAwaitConfirm' libs/pake/src/lib.rs || r_t15a_missing="$r_t15a_missing ResponderDrop"
grep -q 'Zeroizing::new(compute_isk' libs/pake/src/lib.rs            || r_t15a_missing="$r_t15a_missing isk-Zeroizing"
if [ -n "$r_t15a_missing" ]; then
  echo "  FAIL R-T15(a): pake secret-zeroization absent:$r_t15a_missing"; rc=1
else
  echo "  ok  R-T15(a) pake secret-zeroization present (isk Zeroizing + *AwaitConfirm Drop)"
fi
# R-P12: constant-time machine-check of the CPace tag verify + ephemeral-scalar sampling in
# libs/pake. R-P12 requires the R-P3 tag compare to run in constant time via HMAC's verify_slice
# (subtle-backed CtOutput) — never a `==`/`!=` byte compare that early-exits and leaks the tag
# prefix — and the ephemeral scalar to be sampled by the wide reduction (from_bytes_mod_order_wide),
# never the deprecated, non-reducing Scalar::from_bits (§10.4 trap #1). The KATs check derived
# VALUES, not the comparison/sampling discipline, so this is a source-structure gate. (ra6_clean
# deliberately excludes libs/pake, so this pake-scoped gate is separate.) A dudect-style statistical
# timing test is deliberately NOT wired into this fast gate — the tag compare is dominated by the
# full HMAC-SHA512 recompute, so it has near-zero detection power and is flaky; it lives #[ignore]d
# in libs/pake (tests::tag_compare_constant_time_probe), runnable manually. The type-level
# subtle/dalek guarantees + this deterministic gate are the machine-check R-P12 actually rests on.
r_p12_ct=
verify_tag_body=$(awk '/fn verify_tag/,/^}/' libs/pake/src/lib.rs)
echo "$verify_tag_body" | grep -q 'verify_slice'                 || r_p12_ct="$r_p12_ct verify_tag-no-verify_slice"
if echo "$verify_tag_body" | grep -qE '==|!='; then r_p12_ct="$r_p12_ct verify_tag-eq-compare"; fi
sample_scalar_body=$(awk '/fn sample_scalar/,/^}/' libs/pake/src/lib.rs)
echo "$sample_scalar_body" | grep -q 'from_bytes_mod_order_wide' || r_p12_ct="$r_p12_ct sample_scalar-no-wide-reduction"
if grep -REn 'from_bits[[:space:]]*\(' libs/pake/src --include='*.rs' | grep -q .; then
  r_p12_ct="$r_p12_ct from_bits-call-present"
fi
if [ -z "$r_p12_ct" ]; then
  echo "  ok  R-P12 pake constant-time tag verify (verify_slice, no ==/!=) + wide scalar sampling (no Scalar::from_bits)"
else
  echo "  FAIL R-P12: pake constant-time discipline weakened:$r_p12_ct"; rc=1
fi
# R-S19 / CVE-2026-58056 / CWE-863 (Appendix C #24): every peer-triggerable capability MUST key on the
# authorized AuthConnType, never a decoupled per-capability boolean or the broad `self.authorized`
# state. Under the pinned access-mode=full (R-S16) every boolean resolves true, so AuthConnType is the
# ONLY real session-type confinement. The structural fix, all asserted below:
#  (a) confine_capabilities_to_conn_type derives the capability booleans from the AuthConnType and is
#      called BEFORE update_options applies any peer login option — so no login-time option can
#      transiently re-grant a cleared capability (the ordering window behind CVE-2026-58056);
#  (b) the on_message dispatcher is a 3-way AuthConnType allowlist — INPUT + remote-CONTROL
#      (reboot / privacy-toggle / virtual-display) Remote-only, desktop CAPTURE Remote-or-ViewCamera;
#  (c) the flag-gated sinks the guard's message set does not cover key on AuthConnType / voice_calling:
#      host clipboard-TEXT write (Remote-only), peer->host audio (voice-call only), cursor/window
#      capture (Remote-only).
rs19=
conn=src/server/connection.rs
grep -q 'fn confine_capabilities_to_conn_type' "$conn"                   || rs19="$rs19 no-derivation-fn"
grep -q 'self.confine_capabilities_to_conn_type(auth_conn_type)' "$conn" || rs19="$rs19 derivation-not-called"
# (a) ordering: the derivation MUST run before the peer login-option apply (R-S19(b))
confine_ln=$(grep -n 'self.confine_capabilities_to_conn_type(auth_conn_type)' "$conn" | head -1 | cut -d: -f1 || true)
optapply_ln=$(grep -n 'self.options_in_login.take()' "$conn" | head -1 | cut -d: -f1 || true)
if [ -n "$confine_ln" ] && [ -n "$optapply_ln" ] && [ "$confine_ln" -lt "$optapply_ln" ]; then :; else rs19="$rs19 derivation-not-before-options"; fi
# derivation body clears each control capability for the non-Remote types (all seven appear across arms)
deriv=$(awk '/fn confine_capabilities_to_conn_type/,/^    }$/' "$conn")
for cap in keyboard block_input privacy_mode restart recording audio clipboard file; do
  echo "$deriv" | grep -qF "self.$cap = false" || rs19="$rs19 deriv-missing-$cap"
done
# the OLD ad-hoc per-branch clears MUST be gone (subsumed by the derivation, closing the ordering hole)
lgn=$(awk '/Some\(\(dir, show_hidden\)\) = self\.file_transfer\.clone/,/} else if sub_service/' "$conn")
if echo "$lgn" | grep -q 'self.keyboard = false'; then rs19="$rs19 stale-branch-clear-remains"; fi
# (b) 3-way guard
grep -q 'is_remote_input' "$conn"    || rs19="$rs19 no-input-set"
grep -q 'is_remote_control' "$conn"  || rs19="$rs19 no-control-set"
grep -q 'is_desktop_capture' "$conn" || rs19="$rs19 no-capture-set"
grep -q '(is_remote_input || is_remote_control) && !self.is_authed_remote_conn()' "$conn" || rs19="$rs19 input-control-not-remote-gated"
ctrl=$(awk '/let is_remote_control = match/,/_ => false,/' "$conn")
echo "$ctrl" | grep -q 'RestartRemoteDevice' || rs19="$rs19 restart-not-remote-only"
echo "$ctrl" | grep -q 'TogglePrivacyMode'   || rs19="$rs19 privacy-toggle-not-remote-only"
capset=$(awk '/let is_desktop_capture = match/,/_ => false,/' "$conn")
if echo "$capset" | grep -q 'RestartRemoteDevice'; then rs19="$rs19 restart-still-in-capture"; fi
if echo "$capset" | grep -q 'TogglePrivacyMode';   then rs19="$rs19 privacy-still-in-capture"; fi
# MessageQuery answers make_display_changed_msg (monitor geometry/resolution), so it MUST sit in the
# Remote-or-ViewCamera capture allowlist — else a FileTransfer/Terminal/PortForward peer reads display metadata.
echo "$capset" | grep -q 'MessageQuery'            || rs19="$rs19 messagequery-not-capture-gated"
# (c) flag-gated sinks key on AuthConnType / voice_calling
grep -q 'self.clipboard && self.is_authed_remote_conn()' "$conn"       || rs19="$rs19 clipboard-text-not-remote-gated"
grep -q '!self.disable_audio && self.voice_calling' "$conn"            || rs19="$rs19 audio-not-voice-gated"
grep -q 'q == BoolOption::Yes && self.is_authed_remote_conn()' "$conn" || rs19="$rs19 cursor-window-not-remote-gated"
if [ -z "$rs19" ]; then
  echo "  ok  R-S19/CVE-2026-58056/CWE-863: capabilities confined by AuthConnType (derivation-before-options + 3-way guard + sink gates)"
else
  echo "  FAIL R-S19: capability confinement weakened:$rs19"; rc=1
fi
# R-S19 edge residuals (found by the final all-platform sweep): capability-confinement instances the
# connection.rs on_message dispatch did not reach. (1) SCREENSHOTS keyed by (video source, display
# index) so a concurrent Remote monitor loop cannot fulfill a ViewCamera peer's screenshot request;
# (2) the VIEWER syncs a peer's clipboard into its own OS clipboard only in a default (Remote) session
# (io_loop is_default gate on both Clipboard/MultiClipboards arms); (3) the Windows file-clipboard->CM
# forward gated on the confined self.clipboard && self.file; (4) Android MediaProjection capture
# excludes view-camera/terminal (Dart server_model + Kotlin MainService).
rs19e=
grep -q 'set_take_screenshot(source: VideoSource' src/server/video_service.rs        || rs19e="$rs19e screenshot-not-source-keyed"
grep -q 'HashMap<(VideoSource, usize), Screenshot>' src/server/video_service.rs       || rs19e="$rs19e screenshot-map-not-source-keyed"
vc_gated=$(grep -A1 'self.handler.is_default()' src/client/io_loop.rs | grep -c 'disable_clipboard.v' || true)
if [ "${vc_gated:-0}" -ge 2 ]; then :; else rs19e="$rs19e viewer-clipboard-not-default-gated"; fi
if grep -B1 'send_to_cm(ipc::Data::ClipboardFile(clip))' src/server/connection.rs | grep -q 'self.clipboard && self.file'; then :; else rs19e="$rs19e win-cliprdr-not-file-gated"; fi
grep -q 'isViewCamera' flutter/lib/models/server_model.dart                                                  || rs19e="$rs19e android-dart-no-viewcamera-gate"
grep -q 'isViewCamera' flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt            || rs19e="$rs19e android-kotlin-no-viewcamera-gate"
if [ -z "$rs19e" ]; then
  echo "  ok  R-S19 edge residuals confined (screenshot source-keyed + viewer-clipboard default-only + win-CLIPRDR file-gated + Android capture excludes view-camera/terminal)"
else
  echo "  FAIL R-S19 edge residuals:$rs19e"; rc=1
fi
# R-F1/R-F2 (functional: FILE TRANSFER preserved on the headless unix --server). On a box with no
# logind/console session, get_active_username() resolves empty and windows_sessions is always empty,
# so the inherited viewer gate ("No active console user logged on") mis-fired and blocked file
# transfer even though file I/O runs in the CM process at the --server owner's privilege (like the
# terminal's SelfUser, R-F1). Two coordinated guards restore it, both asserted here:
#  (1) SERVER: PeerInfo.username falls back to the --server PROCESS OWNER (hbb_common::whoami::
#      username) when get_active_username() is empty — a truthful non-empty username. Scoped to unix
#      desktops (linux+macos) and empty-guarded, so Windows/Android WTS/console semantics are untouched.
#  (2) VIEWER: the "No active console user logged on" refusal is Windows-PEER-only (that state is
#      Windows session semantics — the pre-logon SYSTEM session); a unix peer serves file transfer at
#      service privilege, so an empty console user MUST NOT block it. Both refusal sites
#      (handle_peer_info + send_selected_session_id) gate on pi.platform == whoami::Platform::Windows.
ftx=
conn=src/server/connection.rs
uif=src/ui_session_interface.rs
# (1) server-side process-owner username fallback: unix-only cfg, empty-guarded, whoami::username
ftu_block=$(awk '/let mut username = crate::platform::get_active_username/,/let mut res = LoginResponse::new/' "$conn")
echo "$ftu_block" | grep -q 'cfg(any(target_os = "linux", target_os = "macos"))'  || ftx="$ftx server-fallback-not-unix-cfg-gated"
echo "$ftu_block" | grep -q 'if username.is_empty()'                              || ftx="$ftx server-fallback-not-empty-guarded"
echo "$ftu_block" | grep -q 'username = hbb_common::whoami::username()'           || ftx="$ftx server-no-process-owner-fallback"
# (1b) the prelogin username-blanking for a file-transfer login is Windows-ONLY. On a headless unix
#      box is_prelogin() is TRUE (no seat0 -> `getent passwd ` lists every user, matching nologin
#      shells), so a unix-broad re-clear (the inherited cfg(not(android/ios))) would UNDO the
#      process-owner fallback above. It MUST sit under cfg(windows) — mirroring the terminal's
#      Windows-only is_prelogin handling (fill_terminal_user_token) — so unix keeps the real user.
if grep -B1 'if self.file_transfer.is_some() && crate::platform::is_prelogin()' "$conn" | grep -q 'cfg(target_os = "windows")'; then :; else ftx="$ftx ft-prelogin-reclear-not-windows-gated"; fi
if grep -A1 'if self.file_transfer.is_some() {' "$conn" | grep -q 'if crate::platform::is_prelogin'; then ftx="$ftx ft-prelogin-reclear-old-unix-nested-form-remains"; fi
# (2) both viewer refusal sites are Windows-peer-gated; the old ungated username-only refusal is gone
n_win=$(grep -c 'pi.platform == hbb_common::whoami::Platform::Windows.to_string()' "$uif" || true)
[ "${n_win:-0}" -ge 2 ] || ftx="$ftx viewer-refusal-fewer-than-2-windows-guards"
if grep -q 'if pi.username.is_empty() && pi.windows_sessions.sessions.is_empty() {' "$uif"; then
  ftx="$ftx viewer-handle_peer_info-ungated-refusal-remains"
fi
hpi=$(awk '/fn handle_peer_info/,/} else if !self.is_port_forward/' "$uif")
echo "$hpi" | grep -q 'No active console user'  || ftx="$ftx handle_peer_info-refusal-vanished"
echo "$hpi" | grep -q 'peer_is_windows'         || ftx="$ftx handle_peer_info-refusal-not-windows-gated"
if [ -z "$ftx" ]; then
  echo "  ok  R-F1/R-F2 file transfer on headless unix: server reports the process-owner username + the viewer 'no console user' refusal is Windows-peer-only"
else
  echo "  FAIL R-F1/R-F2 file-transfer headless-unix guards weakened:$ftx"; rc=1
fi
# R-T11 (§20): the PUBLIC listener (listen_any_v4) MUST bind WITHOUT SO_REUSEPORT — a single-
# instance service needs no kernel load-balance group, and REUSEPORT lets another same-uid (root)
# process silently join the group and steal inbound connections (invisible to R-A4's own-process
# /proc self-check, violating R-D3 "no second listener"). It binds via the dedicated
# new_listener_socket (SO_REUSEADDR on non-Windows only; Windows omits it for an exclusive bind).
# Production code must also have one bind shape: v4 ANY on the pinned public port. Test-only loopback
# binding belongs in the smoke harness, not behind a runtime env selector in the shipped listener.
listen_any_v4_body=$(awk '/pub async fn listen_any_v4/,/^}/' libs/hbb_common/src/tcp.rs)
r_t11_missing=
echo "$listen_any_v4_body" | grep -q 'new_listener_socket' || r_t11_missing="$r_t11_missing no-new-listener"
echo "$listen_any_v4_body" | grep -q 'Ipv4Addr::UNSPECIFIED' || r_t11_missing="$r_t11_missing no-v4-unspecified"
if echo "$listen_any_v4_body" | grep -qE 'std::env::var|Ipv4Addr::LOCALHOST|127\.0\.0\.1'; then
  r_t11_missing="$r_t11_missing runtime-bind-selector"
fi
bind_knob='RUSTDESK_BIND_'
bind_knob="${bind_knob}LOOPBACK"
if grep -R -q "$bind_knob" libs src scripts 2>/dev/null; then
  r_t11_missing="$r_t11_missing env-bind-knob"
fi
if [ -z "$r_t11_missing" ]; then
  echo "  ok  R-T11 public listener is fixed-shape v4 ANY via REUSEPORT-free new_listener_socket"
else
  echo "  FAIL R-T11: listen_any_v4 bind invariant weakened:$r_t11_missing"; rc=1
fi
# R-S1/R-A1: the direct TCP path must not carry a legacy plaintext staging knob. The responder has
# no `secure: bool` selector, direct_service cannot pass a false "unsecured" argument, and the viewer
# `_start` returns only after CPace keying. The message-loop handoff remains
# an assert, not a fallback keying site.
r_s1_stage=
grep -q 'secure: bool' src/server.rs && r_s1_stage="$r_s1_stage server-secure-bool"
grep -q 'let _ = secure' src/server.rs && r_s1_stage="$r_s1_stage server-discarded-secure"
direct_tcp_call=$(awk '/create_tcp_connection\(/,/permit,/' src/direct_service.rs)
echo "$direct_tcp_call" | grep -qE 'false,|secure' && r_s1_stage="$r_s1_stage direct-service-plaintext-arg"
viewer_start_body=$(awk '/pub async fn start\(/,/async fn _start\(/' src/client.rs)
echo "$viewer_start_body" | grep -q 'key_initiator' && r_s1_stage="$r_s1_stage start-fallback-keying"
viewer_direct_body=$(awk '/async fn _start\(/,/async fn key_initiator/' src/client.rs)
echo "$viewer_direct_body" | grep -q 'return Ok' && r_s1_stage="$r_s1_stage unkeyed-early-return"
echo "$viewer_direct_body" | grep -q 'Self::key_initiator' || r_s1_stage="$r_s1_stage no-direct-keying"
# (the ex-R-S17 host-key attach in the staging tuple is retired — the R-A6 absence-gates prove it gone)
if [ -z "$r_s1_stage" ]; then
  echo "  ok  R-S1/R-A1 direct TCP has no plaintext staging selector and _start returns keyed streams"
else
  echo "  FAIL R-S1/R-A1: direct TCP staging path not structurally collapsed:$r_s1_stage"; rc=1
fi
# R-A4 (§9 / §14): every shipped platform that exposes a controlled inbound
# listener needs a live socket-surface assertion for exactly one v4 TCP listener
# and zero UDP sockets, scoped to THIS PROCESS. The box is NOT guaranteed its own
# network namespace (docs/DEPLOYMENT.md runs it alongside SSH + systemd-resolved),
# so the read is scoped to this process's own sockets, not the whole netns. Linux and
# Android both map /proc/self/fd socket:[inode] links back to /proc/self/net rows
# (read_proc_self_net_owned); Windows filters the IP Helper owner-PID TCP/UDP
# tables to this process. This is intentionally a source-structure gate here;
# platform artifact/runtime jobs provide the native execution evidence.
r_a4_platform=
r_a4_surface=libs/hbb_common/src/socket_surface.rs
for marker in \
  'parse_tcp_listen_ports_for_inodes' \
  'count_udp_sockets_for_inodes' \
  'parse_proc_fd_socket_inode' \
  'read_proc_self_socket_inodes' \
  'read_proc_self_net_owned' \
  'read_windows_process_tables' \
  'GetExtendedTcpTable' \
  'GetExtendedUdpTable' \
  'TCP_TABLE_OWNER_PID_ALL' \
  'UDP_TABLE_OWNER_PID'
do
  grep -q "$marker" "$r_a4_surface" || r_a4_platform="$r_a4_platform socket_surface:$marker"
done
# The Linux surface read is PROCESS-SCOPED (owned-inode filtered), so a co-resident
# SSH/systemd-resolved socket is correctly ignored rather than counted. Assert the owned read is
# compiled for Linux (not android-only), and that no netns-wide unfiltered reader
# (fn read_proc_self_net) is present.
grep -q 'cfg(any(target_os = "linux", target_os = "android"))' "$r_a4_surface" || r_a4_platform="$r_a4_platform socket_surface:linux-process-scoped-cfg"
if grep -qE 'fn read_proc_self_net\(' "$r_a4_surface"; then r_a4_platform="$r_a4_platform socket_surface:netns-wide-read-still-present"; fi
for feature in '"iphlpapi"' '"iprtrmib"' '"tcpmib"' '"udpmib"' '"winerror"' '"ws2def"'; do
  grep -q "$feature" libs/hbb_common/Cargo.toml || r_a4_platform="$r_a4_platform hbb_common-winapi:$feature"
done
grep -q 'process_inode_filter_counts_only_this_process_sockets' libs/surface_it/tests/surface.rs || r_a4_platform="$r_a4_platform surface_it:inode-filter-test"
grep -q 'proc_fd_socket_inode_parser_is_strict' libs/surface_it/tests/surface.rs || r_a4_platform="$r_a4_platform surface_it:fd-inode-parser-test"
if [ -n "$r_a4_platform" ]; then
  echo "  FAIL R-A4: Windows/Android process-owned socket-surface assertion gap:$r_a4_platform"; rc=1
else
  echo "  ok  R-A4 Windows/Android process-owned socket-surface assertion source gates present"
fi
# R-P5 / R-SV4(b): the SignedId <-> PublicKey device-identity key bootstrap is removed. The
# viewer's `secure_connection` (the only SignedId user) + the whole initiator-side
# rendezvous/relay/NAT-punch cluster it lived in (_start_inner/connect/request_relay/
# create_relay) are deleted (Client::_start is now direct-only, fail-closed); the responder's
# handling went earlier (9e65a5b); and the `SignedId`/`PublicKey` proto messages are deleted
# (reserved 3,4). Gate the proto keying types — `SignedId`, the `set_public_key` setter, and the
# `Union::PublicKey` arm — NOT the sodiumoxide `sign::PublicKey`/`box_::PublicKey` crypto types,
# which legitimately remain. Only `//` doc comments naming SignedId survive (filtered above).
ra6_clean 'SignedId|set_signed_id|set_public_key|message::Union::PublicKey' 'R-P5 SignedId/PublicKey device-identity keying' || rc=1
# R-A5: the directional-cipher nonce IS the per-direction counter, so seal/open MUST use a CHECKED
# increment (checked_add, fail-closed at 2^64) — a raw `seq += 1` would silently WRAP in a release
# build, resetting to an already-used nonce and reusing (key, nonce) (catastrophic for the AEAD).
# Assert the raw compound-increment never returns to cpace.rs's DirectionalCipher.
ra6_clean 'write_seq *\+=|read_seq *\+=' 'R-A5 unchecked nonce-counter increment (must be checked_add)' || rc=1
# R-A5: the directional-cipher two-key DISTINCTNESS assert MUST read back the ENGAGED key material
# (the send_key / recv_key built in split_session_keys), NOT the derived input `keys` — HKDF makes inputs distinct by
# construction, so a check on `keys` only restates that; the regression R-A5 exists to catch is a
# keying-mis-wire that engages one key BOTH ways (e.g. `recv_key: Key(keys.send)`), which the input
# check passes but the engaged read-back fails closed on. Assert the engaged form is present and the
# old input-key form (`keys.send, keys.recv` in an assert) is gone.
r_a5_dist=
grep -qE 'send_key\.0,\s*recv_key\.0' libs/hbb_common/src/cpace.rs || r_a5_dist="$r_a5_dist engaged-key-assert-missing"
grep -qE 'keys\.send, keys\.recv'                     libs/hbb_common/src/cpace.rs && r_a5_dist="$r_a5_dist input-key-assert-still-present"
if [ -n "$r_a5_dist" ]; then
  echo "  FAIL R-A5: engaged-key distinctness assert incomplete:$r_a5_dist"; rc=1
else
  echo "  ok  R-A5 engaged-cipher send/recv-key distinctness asserted (engaged send_key/recv_key in split_session_keys, not derived inputs)"
fi
# R-A2/R-S2 (authorization is a single keyed-edge choke-point): `self.authorized = true` must appear
# EXACTLY ONCE in connection.rs — it lives in `send_logon_response_and_keep_alive`, reached only on
# the CPace-keyed + whitelisted + password-login path, and EVERY privileged inbound handler
# (input/clipboard/file/capture/terminal/port-forward) is gated behind the lone `else if
# self.authorized` arm of `on_message`. A second set-point is a candidate auth-bypass — fail closed.
# (Audited: only Misc::CloseReason, LoginRequest, and TestDelay dispatch pre-authorization, all
# side-effect-free.)
r_a2_n=$(grep -c 'self\.authorized = true' src/server/connection.rs 2>/dev/null || true)
if [ "${r_a2_n:-99}" -ne 1 ]; then
  echo "  FAIL R-A2/R-S2: expected EXACTLY ONE 'self.authorized = true' in connection.rs (found $r_a2_n) — a new authorization point needs an auth-bypass re-audit"; rc=1
else
  echo "  ok  R-A2/R-S2 single authorization choke-point (self.authorized=true x1; privileged handlers gated)"
fi
# Secrets-at-rest: the config writer `store_path` MUST create files mode 0o600 (owner-only). Every
# password-equivalent lives in a config file — the box's permanent-password PRS (main Config) and the
# viewer's per-peer password/password_prs + os/rdp creds (PeerConfig), all encrypted under the
# machine-UUID wrapper, but the FILE MODE is the at-rest perimeter against other local users. Audited:
# both go through `store_path` -> `confy::store_path_perms(.., from_mode(0o600))`. Assert it survives;
# a regression to a world/group-readable mode would expose the password-equivalent to any local account.
r_secrets_n=$(grep -c 'from_mode(0o600)' libs/hbb_common/src/config.rs 2>/dev/null || true)
if [ "${r_secrets_n:-0}" -lt 1 ]; then
  echo "  FAIL secrets-at-rest: config store_path must write mode 0o600 (from_mode(0o600) missing in config.rs)"; rc=1
else
  echo "  ok  secrets-at-rest config files written mode 0o600 (owner-only; permanent-password PRS + peer creds)"
fi
# R-SV4(b)/R-S13(d)/R-SV10 (no rendezvous path in either role): the initiator-side
# rendezvous/relay/NAT-punch cluster (Client::_start_inner / secure_connection /
# udp_nat_connect) AND the responder-side relay-dialer (create_relay_connection — which dialed
# a relay server via set_request_relay, a "dial nobody" violation if ever reached) are deleted,
# orphaned by the mediator excision (R-D4). This locks in R-SV10's "no path reaches
# Client::_start's rendezvous branch" so a regression cannot silently re-introduce one. (The
# proto setter set_request_relay is intentionally NOT gated — it lives in generated code.)
ra6_clean 'create_relay_connection|_start_inner|secure_connection|udp_nat_connect' 'R-SV4(b)/R-SV10 rendezvous/relay connect cluster' || rc=1
# R-SV / R-D / §18 (dial nobody): the viewer's peer-list ONLINE-STATUS query is removed — it
# connected to get_rendezvous_server() (defaulting to the built-in rs-ny.rustdesk.com) and sent an
# OnlineRequest carrying Config::get_id() + the peer ids (a box-id + peer-list leak on every list
# refresh). The egress fns (create_online_stream / the OnlineRequest send) are gone; peer_online
# now reports every peer offline with no network call. (Only `//` comments name them, filtered.)
ra6_clean 'create_online_stream|set_online_request' 'R-SV viewer online-status egress' || rc=1
# R-SV4 / §18 (dial nobody): the DEFAULT rendezvous-server list (RENDEZVOUS_SERVERS in
# hbb_common/config.rs) must stay EMPTY. Upstream baked "rs-ny.rustdesk.com" in as the fallback used
# whenever no server is configured, so a "direct-IP only" binary still carried a hardwired upstream
# broker -- one revived caller away from a phone-home. The connect paths are already neutered (the
# gates above) and the latency probe early-returns on <=1 server, so it never dialed; the const is
# now &[] for defense-in-depth -- get_rendezvous_server[s]() fall back to nothing, dialing nobody.
# Two hardened gates (presence-vs-VALUE): (a) structural -- no quoted host on the const's definition
# line, catching ANY hardwired default (rustdesk or not); (b) value -- no rs-*.rustdesk.com host
# anywhere in code, catching the host hardcoded elsewhere (`//` comments are filtered).
if grep -nE 'pub const RENDEZVOUS_SERVERS[^=]*=[^;]*"' libs/hbb_common/src/config.rs; then
  echo "  FAIL R-SV4/§18: RENDEZVOUS_SERVERS must be empty (&[]) -- no hardwired rendezvous broker baked into the direct-IP binary"; rc=1
else
  echo "  ok  R-SV4/§18 RENDEZVOUS_SERVERS default empty (no hardwired rendezvous broker; dial nobody)"
fi
ra6_clean 'rs-[a-z]+\.rustdesk\.com' 'R-SV4/§18 hardwired rs-*.rustdesk.com rendezvous host (RENDEZVOUS_SERVERS emptied)' || rc=1
# R-SV1 / §8 / §18 (no device fingerprinting): the upstream hbb_common::fingerprint module -- a
# HARDWARE fingerprint generator (sysinfo-collected cpu brand/speed/cores/mem/platform/arch/addr,
# obfuscated with a hand-rolled AES: the S-box TABLE + expand_key/gf_mul/add_round_key) that upstream
# used to identify devices to the rendezvous -- is REMOVED. The fork excised the rendezvous
# registration that consumed it, orphaning the module (declared `pub mod fingerprint` but ZERO callers
# tree-wide). Gone not disabled: no dead privacy-hostile
# device-fingerprinting machinery (or hand-rolled crypto) left compiled into the binary.
if [ -f libs/hbb_common/src/fingerprint.rs ]; then
  echo "  FAIL R-SV1/§8: the device-fingerprint module (hbb_common/fingerprint.rs) is back"; rc=1
else
  echo "  ok  R-SV1/§8 device-fingerprint module removed (hbb_common/fingerprint.rs absent)"
fi
ra6_clean 'FingerprintingInfo|get_fingerprinting_info|fn expand_key|fn gf_mul|mod fingerprint' 'R-SV1/§8 device-fingerprint (hardware-id + hand-rolled-AES) machinery' || rc=1
# R-SV6 / R-G4 / §18 (dial nobody): the whole Rust account/API HTTP family is excised.
# The old OIDC/account module POSTed device info to /api/oidc/auth, polled /api/oidc/auth-query,
# warmed /api/login-options, and the generic UI FFI could target arbitrary URLs. A direct-IP fork has
# no account server and no caller-supplied HTTP request bridge, so this is absent, not refuse-stubbed.
if [ -f src/hbbs_http/account.rs ]; then
  echo "  FAIL R-SV6/R-G4: src/hbbs_http/account.rs is back (account login/OIDC module must be absent)"; rc=1
else
  echo "  ok  R-SV6/R-G4 account module file absent"
fi
ra6_clean 'api/oidc|api/login-options|fn auth_task|pub mod account|account_auth|main_account_auth|main_get_api_server' 'R-SV6/R-G4 Rust account/OIDC FFI family' || rc=1
ra6_clean 'post_request_sync|http_request_sync|create_http_client_async|get_url_for_tls|mod http_client|HbbHttpResponse|ASYNC_HTTP_STATUS|get_async_http_status|pub fn http_request|pub fn post_request|main_http_request|main_get_http_status' 'R-SV6/R-G4 generic Rust HTTP request bridge' || rc=1
if grep -qE '^[[:space:]]*reqwest[[:space:]]*=|^name = "reqwest"$' Cargo.toml Cargo.lock; then
  echo "  FAIL R-SV6/R-G4: reqwest must not be in Cargo.toml/Cargo.lock after generic HTTP egress excision"; rc=1
else
  echo "  ok  R-SV6/R-G4 reqwest dependency graph absent"
fi
# R-G2 / R-G4 / R-SV6 (§19): the account / address-book / "Accessible devices" (group) FRONT-END and
# its Dart models are EXCISED, not runtime-disabled behind an isEnabled/isDisable* flag (the exact
# R-G4 anti-pattern). A direct-IP fork has no account server, so the abModel/groupModel/UserModel/
# login-shim subsystem is deleted end-to-end and the two account-synced peer tabs collapse to the
# local, login-free Recent/Favorites lists. Assert: the orphaned Dart files are gone; no live
# (non-comment) Dart reference to the models/widgets/login shim survives; the PeerTabIndex tab set is
# collapsed to two members (maxTabCount==2, so no stale saved tab-index can go out of bounds); and the
# Rust disable-* resolvers whose only callers were those models are absent. (flutter/lib greps filter
# `//` comment lines so the excision-rationale comments are not false hits.)
gf_dead=""
for f in flutter/lib/models/ab_model.dart flutter/lib/models/group_model.dart \
         flutter/lib/models/user_model.dart flutter/lib/common/widgets/address_book.dart \
         flutter/lib/common/widgets/my_group.dart flutter/lib/common/widgets/login.dart \
         flutter/lib/common/hbbs/hbbs.dart; do
  [ -e "$f" ] && gf_dead="$gf_dead $f"
done
if [ -n "$gf_dead" ]; then
  echo "  FAIL R-G2/R-G4/R-SV6: an excised account/AB/group file regrew:$gf_dead"; rc=1
elif grep -rnE '\b(abModel|groupModel|AbModel|GroupModel|UserModel|loginDialog|AddressBookPeerCard|MyGroupPeerCard|AddressBookPeersView|MyGroupPeerView|PeerTabIndex\.(ab|group))\b' flutter/lib/ --include='*.dart' | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  echo "  FAIL R-G2/R-G4/R-SV6: a live account/AB/group Dart reference regrew in flutter/lib"; rc=1
elif grep -rn 'gFFI.userModel' flutter/lib/ --include='*.dart' | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  echo "  FAIL R-G2/R-G4/R-SV6: gFFI.userModel regrew (account model must be absent)"; rc=1
elif ! grep -qE 'static const int maxTabCount = 2;' flutter/lib/models/peer_tab_model.dart; then
  echo "  FAIL R-G2/R-G4: peer_tab_model.dart maxTabCount != 2 (tab set not collapsed to Recent/Favorites -> out-of-bounds risk)"; rc=1
else
  echo "  ok  R-G2/R-G4/R-SV6 account/AB/group front-end + models excised (7 files gone; no live Dart ref; PeerTabIndex collapsed to 2)"
fi
ra6_clean 'fn is_disable_ab|fn is_disable_account|fn is_disable_group_panel' 'R-G4/R-SV6 Rust account/AB/group disable-* resolvers' || rc=1
# R-G4 / §8: insecure-TLS fallback is excised structurally, not just config-pinned. The old
# call-site parameter names may remain for compatibility, but no connector/verifier may disable
# certificate verification or install an assertion-only verifier.
if grep -RInE 'danger_accept_invalid_certs[[:space:]]*\([[:space:]]*true[[:space:]]*\)|NoVerifier|client_config_danger|ServerCertVerified::assertion|HandshakeSignatureValid::assertion' src libs/hbb_common --include='*.rs' 2>/dev/null >/tmp/rd_verify_tls_danger.$$; then
  echo "  FAIL R-G4/§8: invalid-certificate TLS acceptance path still present:"
  cat /tmp/rd_verify_tls_danger.$$
  rm -f /tmp/rd_verify_tls_danger.$$
  rc=1
else
  rm -f /tmp/rd_verify_tls_danger.$$
  echo "  ok  R-G4/§8 insecure-TLS fallback structurally absent (no invalid-cert connector/verifier path)"
fi
# R-SV4(b) / R-D5 / §18: the common.rs NAT-type/IPv6 STUN probes are removed — test_nat_ipv4 /
# test_ipv6 -> stun_ipv4_test/stun_ipv6_test resolved + queried hardcoded public STUN servers
# (stun.l.google.com etc.). A direct-IP fork does no NAT traversal; the probes were dead
# (test_nat_type is a no-op, df3d12f) and are deleted structurally (R-SV1), with the `stunclient`
# crate dep dropped. (The other STUN source, `webrtc.rs DEFAULT_ICE_SERVERS`, is now fully EXCISED —
# the `mod webrtc` module file, its optional `webrtc` dependency, and the whole ICE/STUN/TURN crate
# tree are removed outright; the strengthened R-SV4 gate below asserts that absence.)
ra6_clean 'STUNS_V4|STUNS_V6|stunclient|stun_ipv4_test|stun_ipv6_test|test_nat_ipv4|stun\.l\.google' 'R-SV4(b) common.rs STUN NAT-probes' || rc=1
# R-SV4(d) / R-S11 / §18: the NAT/STUN startup ENTRY symbols are cfg-ABSENT, not stubbed —
# test_nat_type (the startup probe, already a no-op after the egressing test_nat_type_/test_ipv6/
# STUNS_* leaves were excised) + CheckTestNatType (the RAII Drop-guard that fired it at arm entry, the
# R-S11 reachability concern) are EXCISED, meeting the spec's "a no-op stub is DIFFERENT from being
# cfg-absent" bar so the sound-symbol-grep holds (the leaves are R-SV4(b) above).
ra6_clean 'test_nat_type|CheckTestNatType' 'R-SV4(d) NAT/STUN entry symbols (test_nat_type/CheckTestNatType)' || rc=1
# R-SV4/R-D5/R-SV10: the hbb_common UDP helper module is physically absent now that the
# rendezvous/relay/STUN/KCP/LAN call graph has been excised for shipped artifacts. This gate is
# intentionally narrow: socket_surface.rs may still inspect /proc UDP rows for the runtime
# zero-UDP assertion, but transport-capable UDP constructors/wrappers must not return.
r_udp_helpers=
[ -f libs/hbb_common/src/udp.rs ] && r_udp_helpers="$r_udp_helpers udp.rs-present"
grep -qE '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+udp[[:space:]]*;' libs/hbb_common/src/lib.rs && r_udp_helpers="$r_udp_helpers mod-udp-in-lib"
if grep -RInE 'new_direct_udp_for|new_udp_for|rebind_udp_for|FramedSocket|Socks5UdpFramed|UdpFramed|UdpSocket::bind|into_udp_socket' src libs --include='*.rs' 2>/dev/null \
  | grep -v '//' | grep -v 'libs/pake' | grep -v 'libs/cpace_it' | grep -v 'bridge_generated' >/tmp/rd_verify_udp_helpers.$$; then
  r_udp_helpers="$r_udp_helpers helper-symbols"
fi
if [ -n "$r_udp_helpers" ]; then
  echo "  FAIL R-SV4/R-D5/R-SV10: inert hbb_common UDP helper surface must be physically absent:$r_udp_helpers"; rc=1
  if [ -s /tmp/rd_verify_udp_helpers.$$ ]; then
    sed 's/^/      /' /tmp/rd_verify_udp_helpers.$$
  fi
else
  echo "  ok  R-SV4/R-D5/R-SV10 inert hbb_common UDP helper module/constructors absent"
fi
rm -f /tmp/rd_verify_udp_helpers.$$
# R-SV4: the WebRTC transport (a second STUN/ICE source — DEFAULT_ICE_SERVERS) is fully EXCISED, not
# merely compiled-out. "removed not disabled" (§8): the `mod webrtc` module file is deleted, the
# optional `webrtc` dependency + the `webrtc` cargo feature are gone, no `mod webrtc` survives in
# lib.rs, no workspace member enables a `webrtc` feature, and the whole ICE/STUN/TURN crate tree
# (webrtc / webrtc-ice / webrtc-sctp / webrtc-util / ...) is pruned from Cargo.lock. Each is asserted
# below as presence-of-absence (a strengthening of the prior feature-not-enabled-only gate).
r_sv4_webrtc=
[ -f libs/hbb_common/src/webrtc.rs ] && r_sv4_webrtc="$r_sv4_webrtc webrtc.rs-present"
grep -qE '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+webrtc' libs/hbb_common/src/lib.rs && r_sv4_webrtc="$r_sv4_webrtc mod-webrtc-in-lib"
grep -qE '^[[:space:]]*webrtc[[:space:]]*=' libs/hbb_common/Cargo.toml && r_sv4_webrtc="$r_sv4_webrtc webrtc-dep-or-feature"
grep -qE 'features[[:space:]]*=[[:space:]]*\[[^]]*"webrtc"' Cargo.toml libs/*/Cargo.toml && r_sv4_webrtc="$r_sv4_webrtc member-enables-webrtc"
grep -qiE '^name = "webrtc(-(ice|sctp|util|srtp|data|media|mdns))?"$' Cargo.lock && r_sv4_webrtc="$r_sv4_webrtc webrtc-crates-in-lock"
if [ -n "$r_sv4_webrtc" ]; then
  echo "  FAIL R-SV4: the webrtc transport is not fully excised:$r_sv4_webrtc"; rc=1
else
  echo "  ok  R-SV4 webrtc transport fully excised (no module, no dep/feature, no ICE/STUN/TURN crates in Cargo.lock)"
fi
# R-A7 (parser-safety floor): the rust-protobuf RUNTIME crate is the FIRST code to touch attacker
# bytes — the unauthenticated pre-key `parse_from_bytes::<Cpace>` (R-S7/R-P14) and the post-key
# `Message`-union parse. With `panic = 'abort'` (release) a parser crash is a whole-process DoS, so
# the decoder MUST stay >= 3.7.2 — the version that fixes RUSTSEC-2024-0437 (uncontrolled-recursion
# crash via unknown-field parsing). Audited 2026-06-29 (cloned the v3.7.2 source): 3.7.2 enforces
# DEFAULT_RECURSION_LIMIT=100, caps the speculative reserve at 10MB (READ_RAW_BYTES_MAX_ALLOC), and
# validates a length prefix against bytes-until-limit BEFORE allocating; a downgrade below 3.7.2
# reopens the recursion DoS. `scripts/audit.sh` (cargo-audit) also catches this dynamically against the
# advisory-db; this is the self-documenting structural floor that does not depend on the db being current.
# The `$`-anchored name match excludes protobuf-codegen/parse/support (build-time, not attacker-reachable).
pb_ver=$(awk '/^name = "protobuf"$/{f=1;next} f&&/^version = /{gsub(/version = "|"/,"");print;f=0}' Cargo.lock | sort -V | head -1)
if [ -z "$pb_ver" ]; then
  echo "  FAIL R-A7: protobuf runtime crate absent from Cargo.lock — parser-safety floor uncheckable"; rc=1
elif [ "$(printf '%s\n3.7.2\n' "$pb_ver" | sort -V | head -1)" != "3.7.2" ]; then
  echo "  FAIL R-A7: rust-protobuf $pb_ver < 3.7.2 reopens RUSTSEC-2024-0437 recursion-crash DoS (parser-safety floor)"; rc=1
else
  echo "  ok  R-A7 protobuf parser-safety floor: rust-protobuf $pb_ver >= 3.7.2 (RUSTSEC-2024-0437 recursion-limit fix; pre-key Cpace + post-key Message parse; audited 2026-06-29)"
fi

# R-R3/R-A7 advisory gates are intentionally outside the fast verifier, but the
# verifier pins their fail-closed structure: both Rust advisory tools must be wired,
# pins must come from scripts/pins.env, and accept-lists must not be comment greps.
echo "== R-R3/R-A7 dependency-advisory gate wiring =="
r_r3_gate=
grep -qF '. scripts/pins.env' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-pins-env"
grep -qF 'CARGO_AUDIT_VERSION' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-cargo-audit-pin"
grep -qF 'CARGO_DENY_VERSION' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-cargo-deny-pin"
grep -qF 'ADVISORY_DB_COMMIT' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-advisory-db-pin"
grep -qF 'SHA256_BASEIMAGE_RUST_1_75_SLIM' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-base-digest-pin"
grep -qF 'cargo-audit audit --db "$ADVISORY_DB" --no-fetch "$@"' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-cargo-audit-run"
grep -qF 'cargo-deny --locked check -c "$tmp" advisories --disable-fetch' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-cargo-deny-run"
grep -qF 'tomllib.load' scripts/audit.sh || r_r3_gate="$r_r3_gate audit:no-toml-ignore-parser"
if grep -qE 'grep .*RUSTSEC.*deny[.]toml' scripts/audit.sh; then
  r_r3_gate="$r_r3_gate audit:comment-grep-ignore-parser"
fi
grep -qF 'FROM rust:${RUST_VERSION}-slim@${BASE_DIGEST}' scripts/Dockerfile.audit || r_r3_gate="$r_r3_gate docker:no-digest-pinned-rust-base"
grep -qF 'cargo install cargo-audit --version "$CARGO_AUDIT_VERSION" --locked' scripts/Dockerfile.audit || r_r3_gate="$r_r3_gate docker:no-pinned-cargo-audit"
grep -qF 'cargo install cargo-deny --version "$CARGO_DENY_VERSION" --locked' scripts/Dockerfile.audit || r_r3_gate="$r_r3_gate docker:no-pinned-cargo-deny"
grep -qF 'CARGO_DENY_DB_PATH' scripts/Dockerfile.audit || r_r3_gate="$r_r3_gate docker:no-deny-db-path"
grep -qF 'CARGO_DENY_VERSION=' scripts/pins.env || r_r3_gate="$r_r3_gate pins:no-cargo-deny-version"
grep -qF 'SHA256_BASEIMAGE_RUST_1_75_SLIM=' scripts/pins.env || r_r3_gate="$r_r3_gate pins:no-rust-audit-base-digest"
grep -qF 'accepted advisory has no reason' scripts/dart-audit.sh || r_r3_gate="$r_r3_gate dart:no-accept-reason-parser"
grep -qF 'expected exactly one advisory id' scripts/dart-audit.sh || r_r3_gate="$r_r3_gate dart:no-strict-id-parser"
if grep -qE 'no[^<]{0,30}<code>deny[.]toml</code>|cargo[- ]audit</code> is not wired|not <code>cargo[- ]audit</code>-clean today|R-A7'\''s "audit green" does <em>not</em> hold as-is|dependency tree remains <strong>outstanding work</strong> \\(#16\\)' requirements.html; then
  r_r3_gate="$r_r3_gate requirements:stale-r-r3-text"
fi
if [ -n "$r_r3_gate" ]; then
  echo "  FAIL R-R3/R-A7 advisory gate wiring regressed:$r_r3_gate"; rc=1
else
  echo "  ok  R-R3/R-A7 Rust cargo-audit+cargo-deny gate, Dart OSV gate, pinned advisory snapshots, and structured accept-list parsing are wired"
fi
# R-D5 / R-SV4 / R-G1: config-option keys + an IPC vestige orphaned by the UDP / webrtc / WebSocket
# excisions are REMOVED, not just left unread — OPTION_DISABLE_UDP (the UDP transport is gone) +
# OPTION_ICE_SERVERS (its only reader was the now-deleted webrtc.rs get_ice_servers) const keys and
# their KEYS_SETTINGS entries, plus the dead proxy-IPC paths. "removed not disabled" (§8/R-G4).
r_deadopt=
grep -qE 'OPTION_DISABLE_UDP|OPTION_ICE_SERVERS' libs/hbb_common/src/config.rs && r_deadopt="$r_deadopt config-dead-option-key"
grep -qE 'SocksWs|get_socks_ws' src/ipc.rs && r_deadopt="$r_deadopt socksws-ipc-vestige"
if [ -n "$r_deadopt" ]; then
  echo "  FAIL R-D5/R-SV4/R-G1: dead option-key / IPC vestige still present:$r_deadopt"; rc=1
else
  echo "  ok  R-D5/R-SV4/R-G1 dead UDP/ICE option keys + SocksWs proxy-IPC vestige absent"
fi
# R-G6 / R-SV4: the direct-only fork has no relay to fall back to, so the inherited
# connection-failure "relay-hint" advice (try a relay / add the "/r" suffix) is dead and
# misdirecting. on_establish_connection_error now always surfaces the plain error msgbox;
# the "relay-hint"/"relay-hint2" emission is removed. (The hyphenated token is distinct from
# the former lang key `relay_hint_tip` (underscore), whose 51-file sweep is asserted below.)
ra6_clean 'relay-hint' 'R-G6 relay-fallback hint emission' || rc=1
# §19 closing-box dead-lang-key sweep: lang keys whose UI was removed by earlier §8/§18/§19
# work and which now have NO live translate() caller. Grouped by the excision that orphaned them:
#   - R-G6 (relay/websocket UI):  relay_hint_tip, websocket_tip
#   - R-G8 ("Powered by RustDesk" badge):  powered_by_me  (also drops the lang.rs RustDesk
#     app-name substitution exclusion that existed only to protect this string)
#   - R-G8 (About-tab marketing slogan):  Slogan_tip  ("Made with heart in this chaotic world!" —
#     the upstream marketing tagline; the desktop About tab now shows the honest fork identity
#     ("RustDesk Hardened Fork") instead, and the Purslane Ltd. AGPL copyright line is PRESERVED)
#   - R-X7 (2FA UI, fully excised):  enable-2fa-title, enable-2fa-desc, enable-bot-tip,
#     wrong-2fa-code, enter-2fa-title, cancel-2fa-confirm-tip
#   - R-X1 (auto-updater UI, fully excised):  download-new-version-failed-tip, new-version-of-{}-tip,
#     upgrade_remote_rustdesk_client_to_{}_tip, upgrade_rustdesk_server_pro_to_{}_tip
# All removed from every one of the 51 lang tables. The R-X1/R-X7 RCE/feature gates above match the
# FUNCTION / quoted-key tokens (e.g. `"download-new-version"`, whose CLOSING quote excludes the
# `-failed-tip`/`-{}-tip` display-string siblings), which is why these translation entries outlived
# the original sweep. NOTE: update-failed-check-msi-tip is DELIBERATELY NOT listed — unlike the
# above it still has a live producer (flutter_ffi.rs main_get_common's `download-file-` handler, the
# §12 win/mac packaging asset-name path, returns `error:update-failed-check-msi-tip`), so deleting
# its table entries would orphan a referenced key. The `{}` placeholders are regex-escaped (\{\})
# because ra6_clean matches with grep -E.
ra6_clean '"(relay_hint_tip|websocket_tip|enable-2fa-title|enable-2fa-desc|enable-bot-tip|wrong-2fa-code|enter-2fa-title|cancel-2fa-confirm-tip|powered_by_me|Slogan_tip|download-new-version-failed-tip|new-version-of-\{\}-tip|upgrade_remote_rustdesk_client_to_\{\}_tip|upgrade_rustdesk_server_pro_to_\{\}_tip|whitelist_tip|Use IP Whitelisting|IP Whitelisting)"' '§19 dead lang keys' || rc=1
# §19 dead-lang-key sweep (R-X9/R-X11 elevation/UAC UI): the peer-triggered elevation AND the Windows
# attended-mode "accept and elevate" / UAC-prompt UI are excised — the host runs as a root systemd
# service (R-D1/R-X10), so per-session elevation is dead. These 7 keys have no live translate() caller.
# KEPT (deliberately NOT listed): elevated_foreground_window_tip — io_loop.rs (2157/2170) renders it
# LIVE to the VIEWER when a controlled host's elevated window can't take input (a direct-control tip,
# not an elevation prompt), so removing it would orphan a referenced key.
ra6_clean '"(request_elevation_tip|still_click_uac_tip|wait_accept_uac_tip|elevation_username_tip|No need to elevate|Accept and Elevate|accept_and_elevate_btn_tooltip)"' '§19 dead elevation/UAC lang keys (R-X9/R-X11)' || rc=1
# §19 systematic dead-lang-key sweep — excised-feature UI strings with NO live translate() caller, found
# by a full en.rs-key-vs-source scan (250 keys checked). Each group's UI is excised, so the key is dead:
# Wayland keyboard-input consent (R-X12 input/capture), the OTP/2FA-bot/trusted-devices UI (R-X7), the
# SOCKS/HTTP proxy editor, the address-book/account UI (R-G4/R-SV6), and the OS-credential login dialog
# (R-S18/R-X8). The `(s)` in the Socks5/Http(s) key is regex-escaped (\( \)). NOTE: dynamic `{}`-template
# keys (e.g. rel-mouse-exit-{}-tip) and the file-manager keys were deliberately EXCLUDED —
# they need per-key vetting against the translate("…{}…").replace pattern before any removal.
ra6_clean '"(wayland-keyboard-input-disabled-tip|wayland-keyboard-input-consent-tip|wayland-keyboard-input-applies-to-tip|wayland-soft-keyboard-input-label|wayland-keyboard-input-reset-choice-tip|remember-wayland-keyboard-choice-tip|doc_fix_wayland|One-time Password|enable-bot-desc|cancel-bot-confirm-tip|enable-trusted-devices-tip|Socks5 Proxy|Socks5/Http\(s\) Proxy|default_proxy_tip|push_ab_failed_tip|pull_group_failed_tip|ab_web_console_tip|OS Password|OS Account|os_account_desk_tip|login_linux_tip)"' '§19 dead excised-feature lang keys (R-X12/R-X7/R-G4/R-S18 + proxy)' || rc=1
# §19 systematic sweep, batch 2 — the remaining no-caller, NON-{}-template keys from the en.rs scan.
# UI strings for excised/simplified surfaces: network-settings / connection-status editor (R-G4 + R-G3
# badge-collapse: Direct/Secure/Insecure Connection, Direct IP Access, Local Address, Change Local Port,
# Unlock Network Settings), server/HTTP error tips (sovereign, no api-server), elevation residuals (R-X9:
# Elevation Error, Request Elevation), floating-window (R-X6), terminal-admin, the TLS-fallback tip, and
# dead file-manager variants (the manager uses translate('Delete'), never 'Confirm Delete'/'Grid View'/
# 'List View'/'Empty Directory'/'Two-Finger Tap'). All verified no-caller (never looked up) and free of
# non-{} dynamic concat. The remaining {}-template keys (rel-mouse-exit-{}-tip, {}-to-update-tip)
# are LIVE via translate("…{…}…") template-matching and are deliberately KEPT, not listed here.
ra6_clean '"(id_change_tip|invalid_http|server_not_support|Confirm Delete|Empty Directory|Local Address|Change Local Port|Auto Login|Wrong credentials|Two-Finger Tap|doc_mac_permission|Direct Connection|Secure Connection|Insecure Connection|Unlock Network Settings|Direct IP Access|Elevation Error|Request Elevation|Switch Sides|Empty Username|remember_account_tip|clipboard_wait_response_timeout_tip|logout_tip|Refresh Password|Grid View|List View|floating_window_tip|terminal-admin-login-tip|allow-insecure-tls-fallback-tip|server-oss-not-support-tip|note-at-conn-end-tip|server_requires_deployment_tip)"' '§19 dead no-caller lang keys batch 2 (network/server/elevation/file-mgr-variant)' || rc=1
# §19 dead lang keys (post-sciter-excision sweep): the rendezvous/relay/lan/WS UI that referenced these
# was excised from BOTH flutter AND sciter — empty_lan_tip (R-X5 lan tab), connecting_status/
# not_ready_status (R-G2/R-G8 status), the ID/Relay Server + ID Server + Relay Server + Relay Connection
# + API Server + setup_server_tip cluster (R-G4/R-SV1, the rendezvous/relay/API server config dialog),
# and Use WebSocket (R-G1). Removed from all 51 lang tables. Scoped to src/lang/ — the flutter excision
# COMMENTS still legitimately name "ID/Relay Server", so the tree-wide ra6_clean form would false-trip.
if grep -rqE '\("(empty_lan_tip|connecting_status|not_ready_status|ID/Relay Server|ID Server|Relay Server|Relay Connection|API Server|setup_server_tip|Use WebSocket|disable-udp-tip|Allow insecure TLS fallback|Discovered)",' src/lang/; then
  echo "  FAIL §19: a removed dead rendezvous/relay/lan/WS lang key was re-added to a src/lang/ table"; rc=1
else
  echo "  ok  §19 dead rendezvous/relay/lan/WS lang keys absent (13: empty_lan_tip + status + ID/Relay/API-server cluster + setup_server_tip + Use-WebSocket + disable-udp-tip + Allow-insecure-TLS-fallback + Discovered)"
fi
# R-G8 / R-SV9 (de-brand, SHOULD): the Android foreground-service notification title MUST NOT be the
# bare upstream brand "RustDesk" — R-G8 names the MainService.kt notification title as a de-brand
# surface (alongside the "RustDesk network" status nomenclature). It now carries the fork identity
# ("RustDesk Hardened Fork", the CHANGELOG/release name). The negative match forbids ONLY the bare
# `= "RustDesk"` form (closing quote immediately after) so any de-branded value the operator picks
# still passes. NOTE (scope): the app label / accessibility-service name (android:label / app_name =
# "RustDesk") is the app's own IDENTITY, not marketing, and is deliberately left intact — R-G8
# de-brands the notification/marketing surfaces, not the honest RustDesk lineage of the app name.
r_g8_kt=flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt
if grep -qE 'DEFAULT_NOTIFY_TITLE[[:space:]]*=[[:space:]]*"RustDesk"' "$r_g8_kt" 2>/dev/null; then
  echo "  FAIL R-G8/R-SV9: the Android foreground notification title is the bare upstream brand \"RustDesk\" — de-brand it to the fork identity (MainService.kt DEFAULT_NOTIFY_TITLE)"; rc=1
else
  echo "  ok  R-G8/R-SV9 Android notification title de-branded (not the bare upstream \"RustDesk\")"
fi
# R-G2/R-SV9 (connect-box hint, MUST): the id_input_tip/web_id_input_tip help text (rendered LIVE
# at flutter connection_page_title.dart) teaches ONLY the direct-IP accept-set (an IP, or a domain
# with a port) — NOT the stock RustDesk syntax it shipped: "<id>@public" (RustDesk's PUBLIC
# rendezvous server — a §18 sovereignty breach), "<id>@<server>?key=" (relay/other-server
# routing), or "/r" (force-relay). The 50 stale locale translations were DELETED so every locale
# falls back to the corrected en (en fallback: src/lang.rs:226); a re-add of the ID/relay/public
# syntax in ANY locale fails here.
tip_bad=
grep -rhE '\("(web_)?id_input_tip",' src/lang/*.rs | grep -qE '@public|\?key=|/r"' && tip_bad="$tip_bad relay/public-syntax"
grep -q '("id_input_tip",' src/lang/en.rs || tip_bad="$tip_bad en-id_input_tip-missing"
if [ -n "$tip_bad" ]; then
  echo "  FAIL R-G2/R-SV9: connect-box hint teaches non-direct-IP syntax / en tip missing:$tip_bad"; rc=1
else
  echo "  ok  R-G2/R-SV9 connect-box hint teaches direct-IP only (no ID/relay/@public/?key=)"
fi
# §18 / R-R2b (universal software codec): hwcodec/vram (the GPU/VRAM hardware-codec deps —
# ffmpeg amf/nvcodec/qsv) AND mediacodec (Android's MediaCodec hardware decode/encode) — each a
# native attack surface (Appendix C #2b) AND a build-reproducibility hazard — are compiled out of
# EVERY build path; the fork is CPU-only software vpx/aom. The optional
# feature DEFINITIONS in Cargo.toml/scrap are inert (never selected) — what this forbids is
# any build script / CI job / driver that ENABLES them: a `--features …hwcodec/vram…`, a
# `--hwcodec`/`--vram` flag, a RUSTDESK_FEATURES/extra_features carrying them, or a
# features.append('hwcodec'). Full-line comments (the R-R2b "dropped" notes) are exempt;
# `nvram` (a libvirt term in cleanup.sh) is not a match. The desktop scripts dropped it
# early, but the flutter mobile scripts + the CI matrix + build.py's own flags still
# selected it until 575859a's follow-on — this locks the universal drop in tree-wide.
hw_hits=$(grep -RInE 'hwcodec|vram|mediacodec' \
            --include='*.sh' --include='*.py' --include='*.yml' --include='*.yaml' --include='*.ps1' . 2>/dev/null \
          | grep -vE '/target/|requirements\.html|scripts/verify\.sh' \
          | grep -vE ':[0-9]+:[[:space:]]*#' \
          | grep -viE 'nvram' || true)
if [ -n "$hw_hits" ]; then
  echo "  FAIL §18/R-R2b: a build path still ENABLES hwcodec/vram/mediacodec (must be universally compiled out):"
  echo "$hw_hits" | sed 's/^/      /'; rc=1
elif grep -E '^default *=' Cargo.toml | grep -qiE 'hwcodec|vram|mediacodec'; then
  echo "  FAIL §18/R-R2b: the Cargo.toml default feature pulls in hwcodec/vram/mediacodec"; rc=1
else
  echo "  ok  §18/R-R2b hwcodec/vram/mediacodec never selected in any build path (CPU-only software codec)"
fi
# R-R2b (native deps): the vcpkg manifest must not pull the hardware-codec native
# libraries — ffmpeg (the amf/nvcodec/qsv hwaccel backend) and mfx-dispatch (Intel
# MediaSDK/QSV) — nor their hwaccel override pins (ffnvcodec, amd-amf). The fork's
# vcpkg.json carries ONLY the CPU-only software set: aom libvpx libyuv opus
# libjpeg-turbo (+ android oboe/cpu-features). This locks the prune so a manifest edit
# can't silently re-introduce the GPU/hardware-codec native attack surface — and the
# multi-hour ffmpeg build that made the §12.2 Windows VM build infeasible. (The
# hwcodec gate above covers the Rust/feature side; this covers the native-dep side.)
if [ -f vcpkg.json ] && grep -qE '"(ffmpeg|mfx-dispatch|ffnvcodec|amd-amf)"' vcpkg.json; then
  echo "  FAIL §18/R-R2b: vcpkg.json still lists a hardware-codec native dep (ffmpeg/mfx-dispatch/ffnvcodec/amd-amf):"
  grep -nE '"(ffmpeg|mfx-dispatch|ffnvcodec|amd-amf)"' vcpkg.json | sed 's/^/      /'; rc=1
else
  echo "  ok  §18/R-R2b vcpkg.json native set is CPU-only software codec (no ffmpeg/mfx-dispatch)"
fi
# R-R3 / Appendix D native-codec watch: cargo-audit/RustSec and Dart OSV scan do
# not cover vcpkg C/C++ libraries. Keep this as an offline source/ledger sync
# gate, not as a live network advisory query and not as a decoder-sandbox claim.
native_watch_log=$(mktemp)
if bash scripts/native-codec-watch.sh >"$native_watch_log" 2>&1; then
  echo "  ok  R-R3 native codec advisory watch is wired for the exact vcpkg native set (separate from Cargo/Dart audits; not the decoder sandbox)"
else
  echo "  FAIL R-R3 native codec advisory watch regressed:"
  sed 's/^/      /' "$native_watch_log"
  rc=1
fi
rm -f "$native_watch_log"
# R-S11a/R-S8 companion: Linux clipboard-file FUSE mount setup uses /tmp by
# design, so every path component must be explicit, no-follow, current-euid
# owned, and non-world-writable. Never silently adopt or chmod a pre-existing
# /tmp path from a hostile local namespace.
r_fuse_mount=
grep -qF 'prepare_fuse_mount_point(&mount_point)?' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount init-not-fail-closed"
grep -qF 'fn fuse_component_cstring(component: &OsStr, label: &str) -> Result<CString, CliprdrError>' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount component-validator"
grep -qF 'bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount component-dot-slash-guard"
grep -qF 'CString::new(bytes)' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount component-nul-guard"
grep -qF 'libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount nofollow-directory-open"
grep -qF 'libc::mkdirat(parent_fd, name.as_ptr(), 0o755 as libc::mode_t)' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount mkdirat-0755"
grep -qF 'libc::openat(' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount openat"
grep -qF 'let current_euid = unsafe { libc::geteuid() };' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount geteuid"
grep -qF 'if stat.st_uid != current_euid' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount foreign-owner-reject"
grep -qF 'libc::fchmod(guard.0, 0o755 as libc::mode_t)' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount fchmod-0755"
grep -qF 'FUSE mount point must stay under /tmp/<app>' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount tmp-app-boundary"
grep -qF 'fuse_mount_component_rejects_empty_dot_dotdot_slash_and_nul' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_mount="$r_fuse_mount component-reject-test"
if grep -qF 'fs::create_dir(mount_point).ok()' libs/clipboard/src/platform/unix/fuse/mod.rs; then
  r_fuse_mount="$r_fuse_mount silent-create-dir"
fi
if grep -qF 'Permissions::from_mode(0o777)' libs/clipboard/src/platform/unix/fuse/mod.rs; then
  r_fuse_mount="$r_fuse_mount world-writable-chmod"
fi
if [ -n "$r_fuse_mount" ]; then
  echo "  FAIL R-S11a/R-S8: Linux FUSE clipboard mount-point no-follow/no-adoption hardening regressed:$r_fuse_mount"; rc=1
else
  echo "  ok  R-S11a/R-S8 Linux FUSE clipboard mount-point setup is fail-closed, no-follow, current-euid-owned, and non-world-writable"
fi
r_fuse_response_queue=
grep -qF 'pub(crate) const FUSE_RESPONSE_QUEUE_CAPACITY: usize = 8;' libs/clipboard/src/platform/unix/fuse/cs.rs ||
  r_fuse_response_queue="$r_fuse_response_queue capacity"
grep -qF 'std::sync::mpsc::sync_channel(FUSE_RESPONSE_QUEUE_CAPACITY)' libs/clipboard/src/platform/unix/fuse/cs.rs ||
  r_fuse_response_queue="$r_fuse_response_queue sync-channel"
grep -qF 'SyncSender<ClipboardFile>' libs/clipboard/src/platform/unix/fuse/cs.rs ||
  r_fuse_response_queue="$r_fuse_response_queue cs-sync-sender"
grep -qF 'tx: SyncSender<ClipboardFile>' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_response_queue="$r_fuse_response_queue context-sync-sender"
grep -qF '.try_send(clip)' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_response_queue="$r_fuse_response_queue nonblocking-admission"
grep -qF 'FUSE file-content response queue is full; dropping peer response' libs/clipboard/src/platform/unix/fuse/mod.rs ||
  r_fuse_response_queue="$r_fuse_response_queue full-shed-log"
grep -qF 'fuse_response_queue_is_bounded' libs/clipboard/src/platform/unix/fuse/cs.rs ||
  r_fuse_response_queue="$r_fuse_response_queue bounded-queue-test"
if grep -qF 'std::sync::mpsc::channel()' libs/clipboard/src/platform/unix/fuse/cs.rs; then
  r_fuse_response_queue="$r_fuse_response_queue unbounded-channel"
fi
if grep -qF '.send(clip)' libs/clipboard/src/platform/unix/fuse/mod.rs; then
  r_fuse_response_queue="$r_fuse_response_queue blocking-send"
fi
if [ -n "$r_fuse_response_queue" ]; then
  echo "  FAIL R-T0/R-S7: Linux FUSE file-content response queue bound regressed:$r_fuse_response_queue"; rc=1
else
  echo "  ok  R-T0/R-S7 Linux FUSE file-content responses use a bounded queue with nonblocking peer admission"
fi
# R-R2a (§12 / sovereignty): the .deb + systemd is the SOLE Linux package model. The AppImage
# recipe (whose `update-information` self-updater collides with R-X1 "the fork ships its own
# releases") and the Flatpak manifest (a portal-sandbox, no-systemd posture colliding with
# R-D1/R-D3a "the systemd confinement IS the model") are DELETED from the tree — not merely
# unbuilt — so that sovereignty/sandbox-model drift cannot regress in. Gate their absence (the
# appimage/ + flatpak/ dirs gone) AND that no workflow builds them. PHASE 2 (also done): the
# non-Debian distro packaging — res/PKGBUILD (Arch) + res/rpm*.spec (Fedora/SUSE) + build.py's
# pacman/yum/zypper branches + the CI rpmbuild/makepkg (arch) steps — is excised too, so the .deb
# is the ONLY Linux artifact (the harmless apt-get `rpm` tooling install is not a build step).
# PHASE 3: the runtime self-relaunch helper cannot resurrect the AppImage launcher model through
# APPDIR/AppRun; child processes relaunch the committed current executable only.
rr2a_bad=
[ -e appimage ] && rr2a_bad="$rr2a_bad appimage-dir"
[ -e flatpak ]  && rr2a_bad="$rr2a_bad flatpak-dir"
[ -e res/PKGBUILD ] && rr2a_bad="$rr2a_bad PKGBUILD"
ls res/rpm*.spec >/dev/null 2>&1 && rr2a_bad="$rr2a_bad rpm-spec"
if grep -RInE 'APPDIR|AppRun|appimage_cmd|std::env::var\("APPDIR"\)' src/common.rs >/tmp/rd_verify_rr2a_runtime.$$; then
  cat /tmp/rd_verify_rr2a_runtime.$$
  rm -f /tmp/rd_verify_rr2a_runtime.$$
  rr2a_bad="$rr2a_bad runtime-AppImage-relaunch"
else
  rm -f /tmp/rd_verify_rr2a_runtime.$$
fi
if grep -rqIE 'build-appimage:|build-flatpak:|appimage-builder|flatpak-builder|rpmbuild|makepkg|arch-makepkg|"appimage/\*\*"|"flatpak/\*\*"' .github/workflows/ 2>/dev/null; then
  rr2a_bad="$rr2a_bad CI-ref"
fi
if [ -n "$rr2a_bad" ]; then
  echo "  FAIL R-R2a: non-.deb Linux packaging must be ABSENT (.deb+systemd is the sole model):$rr2a_bad"; rc=1
else
  echo "  ok  R-R2a non-.deb Linux packaging/runtime launch paths excised — AppImage/Flatpak + PKGBUILD/rpm (.deb+systemd is the sole Linux model)"
fi
# R-SV8 (§18 sovereignty, MUST): no Firebase / FCM / Google-services on ANY artifact (iOS source +
# Android). The iOS GoogleService-Info.plist shipped LIVE Google creds (API_KEY / GCM_SENDER_ID /
# GOOGLE_APP_ID) + DATABASE_URL https://rustdesk.firebaseio.com, bundled at the Xcode/CocoaPods
# layer — invisible to cargo/cfg. The push entitlements (aps-environment APNs + wifi-info SSID
# fingerprint) are already stripped (Runner.entitlements is an empty dict) and Android is
# google-services-free; this locks in the residual creds-plist deletion. (build_fdroid.sh's
# gms/firebase STRIP sed, the spec, and the entitlements R-SV8 comment legitimately NAME the
# tokens — the checks below target the actual creds/endpoint/entitlement, not those mentions.)
rsv8_bad=
[ -e flutter/ios/Runner/GoogleService-Info.plist ] && rsv8_bad="$rsv8_bad ios-creds-plist"
[ -n "$(find flutter/android -name google-services.json 2>/dev/null)" ] && rsv8_bad="$rsv8_bad android-google-services"
grep -rqIE 'firebaseio\.com|IS_GCM_ENABLED|GOOGLE_APP_ID' flutter 2>/dev/null && rsv8_bad="$rsv8_bad firebase-creds/endpoint"
grep -qE '<key>' flutter/ios/Runner/Runner.entitlements 2>/dev/null && rsv8_bad="$rsv8_bad ios-push-entitlement"
grep -qE '^[[:space:]]*firebase_' flutter/pubspec.yaml 2>/dev/null && rsv8_bad="$rsv8_bad firebase-dep"
# R-SV8 per-pod allow-list (R-SV1 enforces sovereignty on the cfg-checked Apple source too): no
# auto-updater or telemetry rides the macOS/iOS source — no Sparkle (the macOS phone-home-and-
# fetch-run auto-updater, an R-X1 surface), no Crashlytics/Fabric, no Sentry, no AppCenter.
# Verified ZERO mentions (code AND comments) in flutter/macos + flutter/ios; this locks it in.
grep -rqIE 'Sparkle|Crashlytics|Fabric|Sentry|AppCenter' flutter/macos flutter/ios 2>/dev/null && rsv8_bad="$rsv8_bad apple-telemetry/updater-pod"
if [ -n "$rsv8_bad" ]; then
  echo "  FAIL R-SV8: Firebase/telemetry/auto-updater residue on an artifact or the Apple source (MUST be absent):$rsv8_bad"; rc=1
else
  echo "  ok  R-SV8 no Firebase/FCM/Google-services + no Sparkle/Crashlytics/Sentry telemetry (iOS plist + push entitlements + Android + Apple source all clean)"
fi
# R-R2/R-A6 Apple gate shape: Linux cargo cannot see the Apple cfg or Xcode layer, so the
# companion gate must not regress into a single-target grep script. This verifies the
# checker itself still defaults to the full target matrix, uses the real Apple Flutter
# feature sets, positively allow-lists plist/entitlements/pods/PBX shell phases, and
# proves the cargo check does not silently mutate generated source.
apple_gate_bad=
apple_gate=scripts/apple-conform-check.sh
grep -qF 'DEFAULT_APPLE_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios)' "$apple_gate" || apple_gate_bad="$apple_gate_bad target-matrix"
grep -qF 'APPLE_TARGETS' "$apple_gate" || apple_gate_bad="$apple_gate_bad APPLE_TARGETS-override"
grep -qF 'flutter,unix-file-copy-paste' "$apple_gate" || apple_gate_bad="$apple_gate_bad macos-real-features"
grep -qF 'target_features()' "$apple_gate" || apple_gate_bad="$apple_gate_bad feature-dispatch"
grep -qF 'plistlib' "$apple_gate" || apple_gate_bad="$apple_gate_bad plist-parser"
grep -qF 'duplicate plist key' "$apple_gate" || apple_gate_bad="$apple_gate_bad plist-duplicate-check"
grep -qF 'APPLE_POD_ALLOWLISTS' "$apple_gate" || apple_gate_bad="$apple_gate_bad pod-allowlist"
grep -qF 'PBXShellScriptBuildPhase allow-list' "$apple_gate" || apple_gate_bad="$apple_gate_bad pbx-shell-allowlist"
grep -qF 'SOURCE_DATE_EPOCH=1700000000' "$apple_gate" || apple_gate_bad="$apple_gate_bad source-date-epoch"
grep -qF 'src/version.rs hash unchanged' "$apple_gate" || apple_gate_bad="$apple_gate_bad non-mutating-version-proof"
grep -qF 'VCPKG_ROOT="$stub"' "$apple_gate" || apple_gate_bad="$apple_gate_bad apple-vcpkg-stub"
if [ -n "$apple_gate_bad" ]; then
  echo "  FAIL R-R2/R-A6 Apple companion gate lost required hardening structure:$apple_gate_bad"; rc=1
else
  echo "  ok  R-R2/R-A6 Apple companion gate covers target matrix + real features + plist/pod/PBX allow-lists + non-mutating cargo proof"
fi
# R-SV9 (§18 sovereignty): the front-ends MUST carry no PLAINTEXT-http link (a downgrade/MITM
# vector), and the sovereign SHOULD removes the live upstream docs/download helper links until an
# operator-owned docs/privacy target exists. The remaining RustDesk brand strings are app/driver
# nomenclature or comments; this gate targets live string-literal links in the front-end link path
# plus the config.rs HELPER_URL expansion map.
rsv9_http=$(grep -rInE 'http://[^ ]*(rustdesk|github)' flutter/lib --include='*.dart' 2>/dev/null || true)
if ! grep -qF "pub static ref HELPER_URL: HashMap<&'static str, &'static str> = HashMap::new();" libs/hbb_common/src/config.rs; then
  rsv9_http="$rsv9_http
libs/hbb_common/src/config.rs:HELPER_URL is not empty"
fi
rsv9_upstream_link_literals=$(rg -n '"https?://[^"]*(rustdesk\.com|github\.com/rustdesk)[^"]*"' src/client.rs libs/hbb_common/src/config.rs flutter/lib --glob '*.rs' --glob '*.dart' 2>/dev/null || true)
if [ -n "$rsv9_upstream_link_literals" ]; then
  rsv9_http="$rsv9_http
$rsv9_upstream_link_literals"
fi
if [ -n "$rsv9_http" ]; then
  echo "  FAIL R-SV9: upstream RustDesk/GitHub link remains live in a front-end/helper path:"; echo "$rsv9_http" | sed '/^$/d; s/^/      /'; rc=1
else
  echo "  ok  R-SV9 front-end/helper paths carry no plaintext or live upstream RustDesk/GitHub URL literals"
fi
# R-S11a / R-S8 (cross-uid IPC authorization + parent-dir hardening): two MUSTs over the world-mode
# 0o0666 `_service`/`_uinput_*` sockets. (a) AUTHORIZATION — the `_service` UID gate authorizes the
# peer against a FRESH active-user lookup (active_uid_fresh, src/ipc/auth.rs), NOT the service-loop
# cache, so a just-switched-out user cannot pass in the cache-lag window (matching uinput); the cached
# active_uid() stays only for config-sync routing. (b) the parent dir the root service owns + locks
# down BEFORE binding — opened O_NOFOLLOW (symlink-TOCTOU, R-S8), the opened FD fchmod'd to the
# expected mode (0o0711 service / 0o0700 else) + fchown'd, stale artifacts scrubbed — so a local user
# cannot pre-stage a world-traversable dir/socket the service trusts. Gate both present + wired.
# R-S11a(b) reject-and-recreate (a foreign-owned service dir is rmdir'd + recreated on a FRESH inode,
# never fchown-adopted, so a pre-set ACL cannot survive) is DONE (commit b46e427) + behavior-tested at (3b).
r_s11a_missing=
grep -q 'fn active_uid_fresh' src/ipc/auth.rs                      || r_s11a_missing="$r_s11a_missing fresh-auth-fn"
grep -q 'let active_uid = active_uid_fresh()' src/ipc/auth.rs      || r_s11a_missing="$r_s11a_missing fresh-auth-wire"
grep -q 'ensure_secure_ipc_parent_dir(&path, postfix)' src/ipc.rs || r_s11a_missing="$r_s11a_missing new_listener-wire"
grep -q 'scrub_secure_ipc_parent_dir(&path, postfix)'  src/ipc.rs || r_s11a_missing="$r_s11a_missing scrub-wire"
grep -q 'fn ensure_secure_ipc_parent_dir' src/ipc/fs.rs           || r_s11a_missing="$r_s11a_missing ensure-fn"
grep -q 'O_NOFOLLOW' src/ipc/fs.rs                                 || r_s11a_missing="$r_s11a_missing O_NOFOLLOW"
grep -q 'fn expected_ipc_parent_mode' src/ipc/fs.rs               || r_s11a_missing="$r_s11a_missing expected-mode"
grep -qE '0o0?711' src/ipc/fs.rs                                   || r_s11a_missing="$r_s11a_missing 0o711"
if [ -n "$r_s11a_missing" ]; then
  echo "  FAIL R-S11a/R-S8: IPC fresh-auth or parent-dir hardening incomplete/unwired:$r_s11a_missing"; rc=1
else
  echo "  ok  R-S11a(a) fresh _service active-uid auth + R-S11a(b)/R-S8 parent-dir hardening (O_NOFOLLOW+0o0711+scrub) present & wired"
fi
# R-S8 / R-A5 (file-transfer write-path no-follow — DISTINCT from the IPC parent-dir O_NOFOLLOW above):
# the receive-WRITE opens in hbb_common/src/fs.rs MUST no-follow the parent path and the target
# (mkdirat/openat parent walk + openat(O_NOFOLLOW)), and finalization must use renameat under the
# same no-follow parent boundary. This closes both the original final-component symlink TOCTOU and
# the later defense-in-depth intermediate-directory race tracked in HARDENING_STATUS.md.
# The spec mandates "openat + O_NOFOLLOW / Windows equivalent", so BOTH branches are asserted:
# the Unix openat walk AND the Windows reparse-safe, handle-relative NT walk. (The Unix tokens sit
# behind #[cfg(unix)] and are present in the source on every host, so grepping only them would
# FALSE-GREEN on a Windows build while the cfg(not(unix)) receive-write branch went entirely
# unasserted — the Windows tokens below close that blind spot.)
r_s8ft_missing=
grep -q 'fn open_parent_dir_no_follow' libs/hbb_common/src/fs.rs                         || r_s8ft_missing="$r_s8ft_missing parent-openat-walk"
grep -q 'mkdirat' libs/hbb_common/src/fs.rs                                               || r_s8ft_missing="$r_s8ft_missing mkdirat"
grep -q 'openat' libs/hbb_common/src/fs.rs                                                || r_s8ft_missing="$r_s8ft_missing openat"
grep -q 'O_DIRECTORY' libs/hbb_common/src/fs.rs                                           || r_s8ft_missing="$r_s8ft_missing O_DIRECTORY"
grep -q 'O_NOFOLLOW' libs/hbb_common/src/fs.rs                                           || r_s8ft_missing="$r_s8ft_missing O_NOFOLLOW"
grep -q 'fn open_recv_write_no_follow' libs/hbb_common/src/fs.rs                         || r_s8ft_missing="$r_s8ft_missing helper"
grep -q 'open_recv_write_no_follow(Path::new(&path), true)' libs/hbb_common/src/fs.rs    || r_s8ft_missing="$r_s8ft_missing data-write-wired"
grep -q 'fn finish_recv_write_no_follow' libs/hbb_common/src/fs.rs                       || r_s8ft_missing="$r_s8ft_missing finish-helper"
grep -q 'renameat' libs/hbb_common/src/fs.rs                                             || r_s8ft_missing="$r_s8ft_missing renameat"
grep -q 'set_file_handle_times' libs/hbb_common/src/fs.rs                                || r_s8ft_missing="$r_s8ft_missing handle-mtime"
grep -q 'read_recv_sidecar_to_string_no_follow' libs/hbb_common/src/fs.rs                || r_s8ft_missing="$r_s8ft_missing sidecar-read-nofollow"
if grep -qE 'File::create\(&path\)' libs/hbb_common/src/fs.rs; then r_s8ft_missing="$r_s8ft_missing raw-File::create-remains"; fi
# --- Windows equivalent: the reparse-safe, handle-relative NT walk (mirrors the Unix openat walk) ---
grep -q 'mod nt_nofollow' libs/hbb_common/src/fs.rs                                      || r_s8ft_missing="$r_s8ft_missing win-nt-module"
grep -q 'NtCreateFile' libs/hbb_common/src/fs.rs                                         || r_s8ft_missing="$r_s8ft_missing win-NtCreateFile(openat)"
grep -q 'OBJECT_ATTRIBUTES' libs/hbb_common/src/fs.rs                                    || r_s8ft_missing="$r_s8ft_missing win-OBJECT_ATTRIBUTES"
grep -q 'oa.RootDirectory = parent' libs/hbb_common/src/fs.rs                            || r_s8ft_missing="$r_s8ft_missing win-RootDirectory-relative"
grep -q 'FILE_OPEN_REPARSE_POINT' libs/hbb_common/src/fs.rs                              || r_s8ft_missing="$r_s8ft_missing win-open-reparse(nofollow)"
grep -q 'FILE_DIRECTORY_FILE' libs/hbb_common/src/fs.rs                                  || r_s8ft_missing="$r_s8ft_missing win-dir-file"
grep -q 'FILE_ATTRIBUTE_REPARSE_POINT' libs/hbb_common/src/fs.rs                         || r_s8ft_missing="$r_s8ft_missing win-reject-reparse(junction+symlink)"
grep -q 'FileRenameInformation' libs/hbb_common/src/fs.rs                                || r_s8ft_missing="$r_s8ft_missing win-renameat(FileRenameInformation)"
grep -q 'nt_nofollow::open_recv_write' libs/hbb_common/src/fs.rs                         || r_s8ft_missing="$r_s8ft_missing win-write-wired"
grep -q 'nt_nofollow::finish_recv_write' libs/hbb_common/src/fs.rs                       || r_s8ft_missing="$r_s8ft_missing win-finish-wired"
grep -q 'nt_nofollow::read_recv_sidecar' libs/hbb_common/src/fs.rs                       || r_s8ft_missing="$r_s8ft_missing win-sidecar-wired"
grep -q 'nt_nofollow::remove_recv_artifacts' libs/hbb_common/src/fs.rs                   || r_s8ft_missing="$r_s8ft_missing win-remove-wired"
grep -q 'fn is_symlink_or_reparse_point' libs/hbb_common/src/fs.rs                       || r_s8ft_missing="$r_s8ft_missing win-junction-inclusive-validate"
grep -q 'fn recv_write_no_follow_refuses_junction_parent_component' libs/hbb_common/src/fs.rs || r_s8ft_missing="$r_s8ft_missing win-junction-parent-test"
grep -q 'fn recv_write_no_follow_refuses_junction_final_component' libs/hbb_common/src/fs.rs  || r_s8ft_missing="$r_s8ft_missing win-junction-final-test"
grep -qE '^ntapi = ' libs/hbb_common/Cargo.toml                                          || r_s8ft_missing="$r_s8ft_missing win-ntapi-dep"
if [ -n "$r_s8ft_missing" ]; then
  echo "  FAIL R-S8/R-A5: file-transfer receive-write parent/target no-follow is incomplete:$r_s8ft_missing"; rc=1
else
  echo "  ok  R-S8/R-A5 file-transfer receive-write uses no-follow parent walk + no-follow target open + renameat finalize on BOTH Unix (openat/O_NOFOLLOW, behavior-tested at (3c)) AND Windows (NtCreateFile RootDirectory-relative reparse-safe walk, junction-tested in the §12.2 VM)"
fi
# R-S8/R-T0 defense-in-depth: peer-triggered filesystem metadata enumeration must be budgeted
# BEFORE traversal/materialization, and peer-triggered transfer jobs must be admitted before
# filesystem/CM worker state grows. This closes post-key hostile-peer DoS paths where AllFiles,
# ReadDir, ReadEmptyDirs, Send, or Receive could force unbounded traversal, spawn_blocking work,
# file-list vectors, or active transfer-job state before a late count check.
r_fsbudget_missing=
grep -q 'pub const DEFAULT_FILE_TRANSFER_MAX_FILES: usize = 10_000;' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing default-file-limit"
grep -q 'pub struct FileEnumerationBudget' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing budget-struct"
grep -q 'pub fn read_dir_with_budget' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing read-dir-budget"
grep -q 'pub fn get_recursive_files_with_budget' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing recursive-budget"
grep -q 'pub fn get_empty_dirs_recursive_with_budget' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing empty-dirs-budget"
grep -q 'FILE_ENUMERATION_BUDGET_EXCEEDED' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing entry-budget-error"
grep -q 'budgeted_read_dir_rejects_too_many_entries_before_returning_vector' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing read-dir-budget-test"
grep -q 'budgeted_recursive_listing_rejects_excessive_depth' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing recursive-depth-test"
grep -q 'pub fn new_read_with_budget' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing new-read-budget"
grep -q 'pub fn validate_transfer_file_list' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing file-list-validator"
grep -q 'pub fn set_files_with_limit' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing set-files-limit"
grep -q 'const DEFAULT_MAX_VALIDATED_FILES: usize = fs::DEFAULT_FILE_TRANSFER_MAX_FILES;' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing ui-default-limit"
grep -q 'unwrap_or(DEFAULT_MAX_VALIDATED_FILES)' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing invalid-limit-default"
grep -q 'MAX_CONCURRENT_FILE_METADATA_SCANS' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing metadata-scan-cap"
grep -q 'try_acquire_file_metadata_scan' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing metadata-scan-try-acquire"
grep -q 'file_transfer_enumeration_budget()' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing metadata-budget-helper"
grep -q 'spawn_blocking(move || fs::get_recursive_files_with_budget' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-allfiles-budget"
grep -q 'fs::get_empty_dirs_recursive_with_budget' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-emptydirs-budget"
grep -q 'fs::read_dir_with_budget' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-readdir-budget"
grep -q 'fs::TransferJob::new_read_with_budget' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-readjob-budget"
grep -q 'fs::TransferJob::new_read_with_budget' src/server/connection.rs ||
  r_fsbudget_missing="$r_fsbudget_missing conn-readjob-budget"
grep -q 'fs::get_recursive_files_with_budget' src/server/connection.rs ||
  r_fsbudget_missing="$r_fsbudget_missing conn-allfiles-budget"
grep -q 'fn reserve_cm_read_job' src/server/connection.rs ||
  r_fsbudget_missing="$r_fsbudget_missing reserve-cm-read"
grep -q 'fn reserve_write_job' src/server/connection.rs ||
  r_fsbudget_missing="$r_fsbudget_missing reserve-write"
grep -q 'MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing read-job-cap"
grep -q 'MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN' libs/hbb_common/src/fs.rs ||
  r_fsbudget_missing="$r_fsbudget_missing write-job-cap"
grep -q 'has_job_for_connection(read_jobs, id, conn_id)' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-read-duplicate"
grep -q 'active_jobs_for_connection(read_jobs, conn_id)' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-read-active-count"
grep -q 'has_job_for_connection(write_jobs, id, conn_id)' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-write-duplicate"
grep -q 'active_jobs_for_connection(write_jobs, conn_id)' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-write-active-count"
grep -q 'WriteJobRejected {' src/ipc.rs ||
  r_fsbudget_missing="$r_fsbudget_missing write-reject-ipc"
grep -q 'conn.write_job_ids.remove(&id)' src/server/connection.rs ||
  r_fsbudget_missing="$r_fsbudget_missing write-reject-release"
grep -q 'fs::validate_transfer_file_list' src/server/connection.rs ||
  r_fsbudget_missing="$r_fsbudget_missing conn-write-list-validator"
grep -q 'job.set_files_with_limit(file_entries, get_max_validated_files())' src/ui_cm_interface.rs ||
  r_fsbudget_missing="$r_fsbudget_missing cm-write-list-validator"
if grep -q 'usize::MAX.*no limit' src/ui_cm_interface.rs libs/hbb_common/src/config.rs; then
  r_fsbudget_missing="$r_fsbudget_missing unsafe-no-limit-doc"
fi
if awk '/file_action::Union::AllFiles/,/file_action::Union::Send/' src/server/connection.rs | grep -q 'fs::get_recursive_files(&'; then
  r_fsbudget_missing="$r_fsbudget_missing conn-allfiles-unbudgeted"
fi
if awk '/async fn read_all_files/,/^}/' src/ui_cm_interface.rs | grep -q 'fs::get_recursive_files(&'; then
  r_fsbudget_missing="$r_fsbudget_missing cm-allfiles-unbudgeted"
fi
if awk '/async fn read_empty_dirs/,/^}/' src/ui_cm_interface.rs | grep -q 'fs::get_empty_dirs_recursive(&'; then
  r_fsbudget_missing="$r_fsbudget_missing cm-emptydirs-unbudgeted"
fi
if awk '/async fn read_dir/,/^}/' src/ui_cm_interface.rs | grep -q 'fs::read_dir(&'; then
  r_fsbudget_missing="$r_fsbudget_missing cm-readdir-unbudgeted"
fi
if [ -n "$r_fsbudget_missing" ]; then
  echo "  FAIL R-S8/R-T0: peer-triggered file-transfer metadata/job admission is not fully bounded:$r_fsbudget_missing"; rc=1
else
  echo "  ok  R-S8/R-T0 peer-triggered file-transfer metadata scans and read/write jobs are budgeted before traversal/allocation"
fi
# R-S8/R-S11 defense-in-depth: incoming FileResponse carries peer-chosen write data for a CM/FS write
# job. FileAction is session-gated, but the shared FS worker historically looked up write_jobs only by
# peer-chosen id, so a cross-session id collision could target the wrong write job. Gate FileResponse
# before forwarding and carry conn_id through the write-side FS IPC messages; the worker must match
# (id, conn_id), not id alone.
r_fileresp_missing=
grep -q 'write_job_ids: HashSet<i32>' src/server/connection.rs                                  || r_fileresp_missing="$r_fileresp_missing connection-write-id-set"
grep -q 'self.reserve_write_job(r.id)' src/server/connection.rs                                  || r_fileresp_missing="$r_fileresp_missing receive-reserve"
grep -q 'self.accepts_file_response_write_job(block.id, "Block")' src/server/connection.rs       || r_fileresp_missing="$r_fileresp_missing block-gate"
grep -q 'self.accepts_file_response_write_job(d.id, "Done")' src/server/connection.rs            || r_fileresp_missing="$r_fileresp_missing done-gate"
grep -q 'self.accepts_file_response_write_job(d.id, "Digest")' src/server/connection.rs          || r_fileresp_missing="$r_fileresp_missing digest-gate"
grep -q 'self.accepts_file_response_write_job(e.id, "Error")' src/server/connection.rs           || r_fileresp_missing="$r_fileresp_missing error-gate"
grep -q 'conn_id: self.inner.id()' src/server/connection.rs                                      || r_fileresp_missing="$r_fileresp_missing file-response-conn-id"
grep -q 'fn get_write_job_for_connection' src/ui_cm_interface.rs                                 || r_fileresp_missing="$r_fileresp_missing worker-id-conn-helper"
grep -q 'job.id() == id && job.conn_id == conn_id' src/ui_cm_interface.rs                        || r_fileresp_missing="$r_fileresp_missing worker-id-conn-match"
grep -q 'remove_write_job_for_connection(write_jobs, id, conn_id)' src/ui_cm_interface.rs         || r_fileresp_missing="$r_fileresp_missing worker-id-conn-remove"
for variant in 'WriteBlock' 'WriteDone' 'WriteError' 'CheckDigest'; do
  awk "/$variant \\{/,/\\}/" src/ipc.rs | grep -q 'conn_id: i32' || r_fileresp_missing="$r_fileresp_missing ipc-${variant}-conn_id"
done
if grep -nE 'FS::Write(Done|Error) \{ id, file_num \}' src/ui_cm_interface.rs src/server/connection.rs | grep -q .; then
  r_fileresp_missing="$r_fileresp_missing done-error-id-only-pattern"
fi
if [ -n "$r_fileresp_missing" ]; then
  echo "  FAIL R-S8/R-S11: FileResponse write forwarding is not same-session/job gated:$r_fileresp_missing"; rc=1
else
  echo "  ok  R-S8/R-S11 FileResponse forwarding is gated by same-connection write-job provenance and FS worker matches write jobs by (id, conn_id)"
fi
# R-S14 (screen capture bound to a PAKE session — a reused grant must not capture outside one): the
# controlled-side capture is per-connection — started only in the authorized (CPace-keyed) Connection
# setup (try_add_primay_video_service, after the R-A2 single self.authorized point) and torn down in
# its Drop (R-T4: stop capture / unblank on disconnect). The Android "reused grant" vector — a
# foreground-service AUTO-RESTART re-entering capture WITHOUT a fresh PAKE session — is closed by
# MainService.onStartCommand returning START_NOT_STICKY (not START_STICKY): a restart never resumes
# capture on its own. Gate that the Android capture service stays NOT_STICKY.
r_s14_kt=flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt
if grep -q 'START_NOT_STICKY' "$r_s14_kt" 2>/dev/null && ! grep -qE 'return[[:space:]]+START_STICKY\b' "$r_s14_kt" 2>/dev/null; then
  echo "  ok  R-S14 Android capture service is START_NOT_STICKY (an auto-restart never re-enters capture outside a fresh PAKE session; desktop capture is per-Connection via R-A2 + R-T4)"
else
  echo "  FAIL R-S14: MainService.onStartCommand must return START_NOT_STICKY (not START_STICKY) so an auto-restart cannot resume capture outside a PAKE session"; rc=1
fi
# R-X7a / R-G1 (no inert pinned-policy SELECTOR survives — removed, not greyed): verification-method +
# approve-mode are R-S16-pinned (use-permanent-password / password), so a UI that PRESENTS+WRITES them
# is the exact "defaulted-off-but-present" hazard R-G1 forbids — the funnel overrides the write and
# is_option_can_save rejects it, leaving a divergent dead presentation. The fork REMOVES the
# verification-method/approve-mode/one-time-password selectors (desktop Safety tab + Android server
# page), leaving only "Set permanent password". Gate that NO flutter UI WRITES those pinned keys — no
# mainSetOption with verification-method/approve-mode (literal or kOption* const) and no
# setVerificationMethod/setApproveMode model setter. (Reading them for display via mainGetOption is fine.)
rx7a_hits=$(grep -rInE 'setVerificationMethod|setApproveMode|mainSetOption[^;]*verification-method|mainSetOption[^;]*approve-mode|mainSetOption[^;]*kOptionVerificationMethod|mainSetOption[^;]*kOptionApproveMode' flutter/lib --include='*.dart' 2>/dev/null | grep -v 'generated_bridge' | grep -vE ':[0-9]+:[[:space:]]*//' || true)
if [ -n "$rx7a_hits" ]; then
  echo "  FAIL R-X7a/R-G1: a flutter UI still WRITES the pinned verification-method/approve-mode policy (remove the selector, do not disable it):"; echo "$rx7a_hits" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-X7a/R-G1 no flutter UI writes the pinned verification-method/approve-mode selectors (removed not greyed; display-reads only)"
fi
# (The former R-X7a SCITER-parity OTP gate on src/ui/index.tis is retired — the entire Sciter UI is
# deleted, R-B6, so its excised-OTP controls are gone by construction; the flutter R-X7a gate above stays.)
# R-S5 / R-A3 / R-A9 / R-F1 / R-D6 (the port-forward/RDP tunnel rides the SEALED session stream): the
# tunnel is RESTORED and WORKS ENCRYPTED. R-F1 makes "port-forward (incl. RDP) fully available" a MUST;
# R-D6 pins enable-tunnel ON and requires the forward to "ride the sealed encrypted channel (R-S5)"; R-A9
# requires the port-forwarded bytes to be "indistinguishable from random" on the wire. R-S5 itself permits
# EITHER "keep the bytes inside the secretbox" OR "refuse the forward" — and R-F1/R-D6/R-A9 OVERRIDE the
# refuse, so the fork takes R-S5 option 1: restore the relay but seal every byte. Upstream downgraded the
# keyed stream with FramedStream::set_raw AFTER login to pass RAW plaintext (Appendix C #4, a Tier-1
# finding); the fork MUST NOT. So the invariant to gate is NOT "the relay is deleted" (the prior gate,
# which contradicted R-F1/R-D6/R-A9) but: the relay is PRESENT on both sides, rides send_bytes(seal)/next
# (open) on the KEYED stream, NEVER calls set_raw in app code (which would panic on a keyed stream anyway),
# the viewer asserts is_secured() before tunnelling, and an R-A9 test proves the actual wire bytes are
# ciphertext. The hbb_common set_raw definition + its R-A3 keyed-stream panic remain the fail-closed backstop.
r_s5_missing=
# The libs/hbb_common set_raw backstop is intact (definition + Unkeyed-only downgrade + keyed-stream panic).
grep -q 'fn set_raw' libs/hbb_common/src/tcp.rs                                || r_s5_missing="$r_s5_missing set_raw-fn"
grep -qF 'Unkeyed(framed) => framed.codec_mut().set_raw()' libs/hbb_common/src/tcp.rs || r_s5_missing="$r_s5_missing unkeyed-only-raw"
grep -qF 'R-A3: set_raw on a keyed session stream' libs/hbb_common/src/tcp.rs   || r_s5_missing="$r_s5_missing a3-assert"
# (a) ZERO set_raw CALLERS in the app tree (src/): the only set_raw is the libs backstop above; the relay
#     must never downgrade the keyed stream to raw plaintext (that raw passthrough IS the R-S5 escape).
#     -rIn keeps the filename so the trailing comment-line filter (`:N: //…`) excludes doc mentions.
if grep -rIn '\.set_raw(' src --include='*.rs' 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  r_s5_missing="$r_s5_missing app-set_raw-caller-present"
fi
# (b) SERVER relay is RESTORED and rides the KEYED stream: try_port_forward_loop dials the local target
#     (connect_port_forward_if_needed) then shuttles bytes with self.stream.send_bytes (SEALS -> ciphertext)
#     and self.stream.next (DECRYPTS) — no raw passthrough — and PortForward gets its own AuthConnType.
grep -qF 'async fn try_port_forward_loop' src/server/connection.rs          || r_s5_missing="$r_s5_missing server-relay-loop-missing"
grep -qF 'async fn connect_port_forward_if_needed' src/server/connection.rs || r_s5_missing="$r_s5_missing server-dial-missing"
grep -qF 'self.stream.send_bytes(' src/server/connection.rs                 || r_s5_missing="$r_s5_missing server-relay-not-sealed"
grep -qF 'AuthConnType::PortForward' src/server/connection.rs               || r_s5_missing="$r_s5_missing server-portforward-authtype-missing"
# (c) VIEWER relay is RESTORED and rides the KEYED stream: run_forward relays local <-> keyed session via
#     stream.send_bytes (SEALS) and stream.next (DECRYPTS).
grep -qF 'async fn run_forward' src/port_forward.rs || r_s5_missing="$r_s5_missing viewer-relay-missing"
grep -qF '.send_bytes(' src/port_forward.rs         || r_s5_missing="$r_s5_missing viewer-relay-not-sealed"
# (d) The VIEWER asserts the stream is PAKE-keyed BEFORE tunnelling a single byte (R-S5 note / R-S13, §4.4).
grep -qF 'is_secured()' src/port_forward.rs || r_s5_missing="$r_s5_missing viewer-is-secured-assertion-missing"
# (e) R-A9 wire-ciphertext PROOF: a keyed-stream test captures the ACTUAL bytes on the underlying socket and
#     asserts the plaintext canary is ABSENT (sealed). Lives in libs/cpace_it/tests, run by `cargo test -p
#     cpace_it` above — so this gate + that test together prove the tunnel is ciphertext, not just structure.
grep -rqF 'ciphertext_on_the_wire' libs/cpace_it/tests/ || r_s5_missing="$r_s5_missing a9-wire-ciphertext-proof-missing"
if [ -n "$r_s5_missing" ]; then
  echo "  FAIL R-S5/R-A9: the SEALED port-forward/RDP tunnel invariant regressed (the relay must be present on both sides, ride the keyed Stream via send_bytes/next and NEVER set_raw in app code; the viewer must assert is_secured() before tunnelling; the R-A9 wire-ciphertext test must exist):$r_s5_missing"; rc=1
else
  echo "  ok  R-S5/R-A9/R-F1/R-D6 port-forward/RDP tunnel restored INSIDE the secretbox — relay rides send_bytes(seal)/next(open) on the keyed Stream (both sides), zero set_raw callers in app code, viewer asserts is_secured() pre-tunnel, R-A9 wire-ciphertext test present, hbb_common set_raw stays an assert-only backstop"
fi
# R-X7 (Rust OTP excision): the rotating one-time (temporary) password is EXCISED from the Rust tree
# — the permanent password is the sole credential and sole CPace PRS (R-S9/R-P1). R-A6 lists
# TEMPORARY_PASSWORD/update_temporary_password/check_update_temporary_password/get_auto_*numeric* as
# must-be-ZERO; the 2FA half of R-X7 was already gated above, this closes the OTP half. The whole
# chain is gone: the TEMPORARY_PASSWORD store + numeric generator (password_security/config), the
# FFI/IPC/sciter forwarders (ui_interface/ipc/ui/flutter_ffi), the consecutive-wrong-attempt rotation
# (connection.rs TEMPORARY_PASSWORD_FAILURES), and the dead option keys. `Config::get_auto_password`
# STAYS (shared with the Hash challenge — R-T15(c) deferred — and salt generation). The FRB-generated
# bridge is excluded (gitignored, regenerated from flutter_ffi.rs, so it tracks this automatically).
# NOTE (gate-hole fix): R-A6 also lists the OPTION token `use-temporary-password` grep-zero, but the
# underscore-only pattern below historically missed the hyphenated key AND the CamelCase resolver
# variant `OnlyUseTemporaryPassword`, letting a dead OTP resolver branch survive. Both forms are now
# covered here (Rust) and in the Dart check that follows.
rx7otp_hits=$(grep -rInE 'TEMPORARY_PASSWORD|TEMPORARY_PASSWD|temporary_password|temporary_enabled|get_auto_numeric_password|use-temporary-password|OnlyUseTemporaryPassword' src libs --include='*.rs' 2>/dev/null | grep -vE 'bridge_generated' | grep -vE ':[0-9]+:[[:space:]]*//|R-X7' || true)
if [ -n "$rx7otp_hits" ]; then
  echo "  FAIL R-X7: the temporary/one-time-password machinery must be absent from the Rust tree (the OTP half of R-X7 — permanent password is the sole credential):"; echo "$rx7otp_hits" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-X7 temporary/one-time-password machinery excised (Rust: store/generator/FFI/IPC/rotation/dead-keys + the use-temporary-password token/OnlyUseTemporaryPassword variant; get_auto_password kept for salt)"
fi
# R-X7/R-A6 (Dart side of the same token): the `use-temporary-password` option key and its Dart const
# `kUseTemporaryPassword` are excised from the flutter tree too (the OTP verification-method is gone;
# the selector UI was removed by R-X7a/R-G4). Comment lines and the gitignored FRB bridge are excluded.
rx7otp_dart=$(grep -rInE 'use-temporary-password|kUseTemporaryPassword' flutter/lib 2>/dev/null | grep -vE 'bridge_generated|generated_bridge' | grep -vE ':[0-9]+:[[:space:]]*//|R-X7' || true)
if [ -n "$rx7otp_dart" ]; then
  echo "  FAIL R-X7/R-A6: the use-temporary-password token must be absent from flutter/lib (OTP verification-method excised):"; echo "$rx7otp_dart" | sed 's/^/      /'; rc=1
else
  echo "  ok  R-X7/R-A6 Dart use-temporary-password token excised (no kUseTemporaryPassword const, no hyphen key)"
fi
# R-F4 (the direct port is a single PINNED compile-time constant, never a runtime knob): the listener
# binds exactly one port, pinned to the literal 21118 (config::DIRECT_PORT) — NOT the inherited
# RENDEZVOUS_PORT+2 derivation (which would silently shift the port and desync the §10.4 CPace CI KAT
# be16(21118)=527e), and NOT a runtime `direct-access-port` option (an override R-S12 forbids). The
# spec's R-A6 mandates exactly this check. Assert the const is 21118, get_direct_port returns the const,
# and no direct-access-port config read exists anywhere.
r_f4_missing=
grep -qE 'pub const DIRECT_PORT: i32 = 21118;' libs/hbb_common/src/config.rs || r_f4_missing="$r_f4_missing const-21118"
grep -qF 'config::DIRECT_PORT' src/direct_service.rs                     || r_f4_missing="$r_f4_missing get_direct_port-returns-const"
if grep -rInE 'get_option\([^)]*direct-access-port|OPTION_DIRECT_ACCESS_PORT' src libs --include='*.rs' 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q .; then
  r_f4_missing="$r_f4_missing direct-access-port-read-present"
fi
# (fork-specific) the CLIENT connect-default port is the pinned DIRECT_PORT literal too — client.rs
# once derived it as `RELAY_PORT + 1` (the same forbidden derivation the listener avoids); and the
# excised relay/WebSocket transports leave NO port const (RELAY_PORT/WS_RENDEZVOUS_PORT/WS_RELAY_PORT).
grep -q 'check_port(peer, DIRECT_PORT)' src/client.rs || r_f4_missing="$r_f4_missing client-connect-default-not-DIRECT_PORT"
grep -qE 'check_port\([^,]+,[[:space:]]*[A-Z_]+_PORT[[:space:]]*\+' src/client.rs && r_f4_missing="$r_f4_missing client-derived-connect-port"
grep -qE 'pub const (RELAY_PORT|WS_RENDEZVOUS_PORT|WS_RELAY_PORT)\b' libs/hbb_common/src/config.rs && r_f4_missing="$r_f4_missing relay/ws-port-vestige"
if [ -n "$r_f4_missing" ]; then
  echo "  FAIL R-F4: the direct port must be the pinned compile-time literal 21118 (config::DIRECT_PORT), never the RENDEZVOUS_PORT+2 derivation or a runtime direct-access-port option:$r_f4_missing"; rc=1
else
  echo "  ok  R-F4 direct port pinned to the literal 21118 (listener get_direct_port + client connect-default both = config::DIRECT_PORT, no derivation; no direct-access-port config read; no relay/ws port vestige; CI KAT be16=527e holds)"
fi

echo "== (6) .msi generator determinism (R-B2) =="
# The WiX .msi generator (res/msi/preprocess.py) MUST emit DETERMINISTIC GUIDs + a sorted component
# order, so a same-host same-version .msi rebuild is byte-identical (the recorded-SHA bar, R-B2). Every
# GUID is a uuid5 of a STABLE key (ProductCode=name+version, components=relpath, UpgradeCode/upgrade-id=
# name) and the dist glob is sorted; NO uuid.uuid4() call (random per build) survives -- incl. the
# rename-path replace_component_guids_in_wxs. Package.wxs pins the ProductCode attr (else WiX 4
# auto-generates a fresh ProductCode each build). Guards the f2f7eb2 + line-541 determinism fixes.
r_b2msi=
grep -qF 'uuid.uuid4(' res/msi/preprocess.py                            && r_b2msi="$r_b2msi uuid4-call-present"
grep -qF 'product_code = uuid.uuid5' res/msi/preprocess.py              || r_b2msi="$r_b2msi ProductCode-not-uuid5"
grep -qF 'comp_guid = uuid.uuid5' res/msi/preprocess.py                 || r_b2msi="$r_b2msi component-not-uuid5"
grep -qF 'sorted(path.glob' res/msi/preprocess.py                       || r_b2msi="$r_b2msi glob-not-sorted"
grep -qF 'upgrade_id = uuid.uuid5' res/msi/preprocess.py                || r_b2msi="$r_b2msi upgradeid-not-uuid5"
grep -qF 'ProductCode="$(var.ProductCode)"' res/msi/Package/Package.wxs || r_b2msi="$r_b2msi wxs-ProductCode-unpinned"
# R-B2 (2026-07-03 InstallDate fix): NO wall-clock date may enter the .msi. The ARP InstallDate and the
# MSI revision version MUST derive from SOURCE_DATE_EPOCH -- a wall-clock date is DATE-granular, so it
# slips PAST the in-run double-build (both halves run the same calendar day) yet breaks the recorded-SHA
# bar ACROSS days (proven: a Jul-2 vs Jul-3 rebuild of byte-identical source diverged in this ONE field).
grep -qF 'installDate = _reproducible_utc_date' res/msi/preprocess.py         || r_b2msi="$r_b2msi InstallDate-not-SDE-derived"
grep -qE 'installDate[[:space:]]*=[[:space:]]*datetime' res/msi/preprocess.py && r_b2msi="$r_b2msi InstallDate-wallclock-form-present"
grep -qF 'os.environ.get("SOURCE_DATE_EPOCH")' res/msi/preprocess.py          || r_b2msi="$r_b2msi no-SOURCE_DATE_EPOCH-honored"
# Behavioral proof: with a pinned SDE the date is a FIXED function of SDE, independent of today's clock.
if command -v python3 >/dev/null 2>&1; then
  SOURCE_DATE_EPOCH=1700000000 python3 - <<'PY' >/dev/null 2>&1 || r_b2msi="$r_b2msi InstallDate-behaviorally-nondeterministic"
import sys; sys.path.insert(0, 'res/msi')
import preprocess
assert preprocess._reproducible_utc_date('%Y%m%d') == '20231114'   # SDE 1700000000 -> 2023-11-14 UTC (NOT today)
assert preprocess.default_revision_version() == 28333333
PY
else
  echo "  note R-B2 .msi date behavioral proof skipped (python3 absent on this host); token guards still enforced"
fi
if [ -n "$r_b2msi" ]; then echo "  FAIL R-B2 .msi-generator determinism:$r_b2msi"; rc=1; else
  echo "  ok  R-B2 .msi generator -> deterministic GUIDs+order (ProductCode/component/upgrade uuid5, sorted glob, no uuid4 calls, Package.wxs pins ProductCode; InstallDate+revision from SOURCE_DATE_EPOCH, no wall-clock date)"; fi

echo "== (6b) R-B2 post-process canonicalizers (.exe + .msi) =="
# The host-side canonicalizers (run in build-windows-vm.sh extract()) MUST normalize the residual
# build-non-determinism a same-commit double-build exposed AFTER the vendor-path fix: (1) canonicalize-pe.py
# recomputes the VS_VERSION_INFO StringFileInfo/StringTable parent wLengths AFTER sorting the String
# children -- winres 0.1.12 HashMap-orders them AND computes those wLengths excluding the last child's
# trailing pad, so the order shifts them +/-2 (commit b7feea2); (2) canonicalize-msi.py zeroes every CAB
# CFFILE DOS date/time + the OLE2 Root Entry modify FILETIME, both WiX build wall-clock (commit aa8e65a).
# Proven: with these the real double-build .exe AND .msi converge byte-identically.
r_b2post=
grep -qF 'new_st_len' scripts/canonicalize-pe.py          || r_b2post="$r_b2post pe-no-wLength-recompute"
grep -qF 'sfi_start' scripts/canonicalize-pe.py           || r_b2post="$r_b2post pe-no-sfi-recompute"
grep -qF '_zero_cab_filetimes' scripts/canonicalize-msi.py || r_b2post="$r_b2post msi-no-cab-zero"
grep -qF '_zero_root_filetime' scripts/canonicalize-msi.py || r_b2post="$r_b2post msi-no-root-zero"
if [ -n "$r_b2post" ]; then echo "  FAIL R-B2 post-process canonicalizers:$r_b2post"; rc=1; else
  echo "  ok  R-B2 post-process -> canonicalize-pe recomputes VS_VERSION_INFO wLengths; canonicalize-msi zeroes CAB+OLE2-root timestamps"; fi
# (6c) R-B5b/B8/B9/B10 build-reproducibility STRUCTURE (MUST): each automated build splits a network-on
# fetch from a `--network=none` COMPILE (so "no fetch at compile time", R-B5b, is structural not
# trusted), off a DIGEST-pinned base image (R-B8), resolves cargo from the vendored lockfile set
# (R-B10), and self-verifies the artifact SHA-256 (R-B2). And NO build stage binds 0.0.0.0 (R-D3
# loopback-only). The R-B2 gates above cover .exe/.msi byte-determinism; this covers the SCRIPT shape.
echo "== (6c) build-reproducibility structure (R-B5b/B8/B9/B10 two-stage, digest-pinned, offline compile) =="
rb_struct=
for f in scripts/build-debian.sh scripts/build-android.sh; do
  grep -q -- '--network=none' "$f" || rb_struct="$rb_struct ${f##*/}:no-offline-compile"
done
grep -qE 'FROM ubuntu:[0-9.]+@' scripts/Dockerfile.deb-builder     || rb_struct="$rb_struct deb-base-not-digest-pinned"
grep -qE 'FROM ubuntu:[0-9.]+@' scripts/Dockerfile.android-builder || rb_struct="$rb_struct android-base-not-digest-pinned"
grep -q 'cargo-vendor' scripts/build-debian.sh                     || rb_struct="$rb_struct debian:no-vendored-cargo"
grep -qE 'sha256sum|\.sha256' scripts/build-android.sh             || rb_struct="$rb_struct android:no-self-verify"
grep -rq '0\.0\.0\.0' scripts/build-debian.sh scripts/build-android.sh scripts/build-windows.ps1 scripts/run-build.ps1 2>/dev/null && rb_struct="$rb_struct external-listener-in-build"
# R-B2: Debian AND Windows MUST assert byte-reproducibility by a DOUBLE BUILD (build the same source
# twice, require byte-identical SHA-256). Android is EXEMPT (§12.1 line: "Integrity is the recorded
# SHA-256, NOT cross-rebuild byte-identity" — apksigner re-padding makes byte-identity impractical).
{ grep -q 'DOUBLE_BUILD' scripts/build-debian.sh    && grep -q 'double-build SHA mismatch' scripts/build-debian.sh; }        || rb_struct="$rb_struct debian:no-double-build-assert"
{ grep -q 'DOUBLE_BUILD' scripts/build-windows-vm.sh && grep -q 'double-build .* SHA mismatch' scripts/build-windows-vm.sh; } || rb_struct="$rb_struct windows:no-double-build-assert"
{ grep -q 'WINDOWS_BUILD_SOURCE' scripts/build-windows-vm.sh && grep -qE 'git ls-files .*--cached .*--others .*--exclude-standard .* -z|git ls-files --cached --others --exclude-standard -z' scripts/build-windows-vm.sh; } || rb_struct="$rb_struct windows:no-worktree-source-mode"
grep -qF 'Dockerfile.win-helper' scripts/online-fetch.sh          || rb_struct="$rb_struct windows:helper-image-not-built-online"
git ls-files --error-unmatch scripts/Dockerfile.win-helper >/dev/null 2>&1 || rb_struct="$rb_struct windows:helper-dockerfile-not-tracked"
[ -s scripts/Dockerfile.win-helper ]                              || rb_struct="$rb_struct windows:helper-dockerfile-missing"
grep -qF 'WIN_HELPER_IMAGE' scripts/build-windows-vm.sh           || rb_struct="$rb_struct windows:no-helper-image-build"
grep -qF 'WIN_HELPER_IMAGE' scripts/provision-windows-vm.sh       || rb_struct="$rb_struct windows:no-helper-image-provision"
grep -qF 'WIN_HELPER_IMAGE' scripts/verify-windows-golden.sh      || rb_struct="$rb_struct windows:no-helper-image-verify"
grep -qF -- '--network=none' scripts/build-windows-vm.sh          || rb_struct="$rb_struct windows:helper-not-offline-build"
grep -qF -- '--network=none' scripts/provision-windows-vm.sh      || rb_struct="$rb_struct windows:helper-not-offline-provision"
grep -qF -- '--network=none' scripts/verify-windows-golden.sh     || rb_struct="$rb_struct windows:helper-not-offline-verify"
if grep -Eq 'provision_pkg[[:space:]]+libvirt-daemon-system' scripts/host-provision.sh; then
  rb_struct="$rb_struct host-provision:installs-system-libvirt"
fi
grep -qF 'assert_no_system_libvirt_network' scripts/host-provision.sh || rb_struct="$rb_struct host-provision:no-libvirt-network-audit"
grep -qF 'forbid_system_libvirt_package' scripts/host-provision.sh    || rb_struct="$rb_struct host-provision:no-system-libvirt-package-guard"
grep -qF 'non_loopback_listeners' scripts/host-provision.sh           || rb_struct="$rb_struct host-provision:no-new-listener-audit"
grep -qF 'require_cmd ip ss' scripts/host-provision.sh                || rb_struct="$rb_struct host-provision:no-ip-ss-preflight"
grep -qF 'assert_no_build_host_network_residual' scripts/lib.sh       || rb_struct="$rb_struct lib:no-build-host-network-residual-helper"
grep -qF 'virbr0 exists' scripts/lib.sh                               || rb_struct="$rb_struct lib:no-virbr0-residual-check"
grep -qF '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67' scripts/lib.sh || rb_struct="$rb_struct lib:no-libvirt-listener-residual-check"
grep -qF 'net.ipv4.ip_forward=1' scripts/lib.sh                       || rb_struct="$rb_struct lib:no-ip-forward-residual-check"
for f in scripts/build-windows-vm.sh scripts/provision-windows-vm.sh scripts/verify-windows-golden.sh; do
  grep -qF 'assert_no_build_host_network_residual' "$f" || rb_struct="$rb_struct ${f##*/}:no-build-host-network-preflight"
done
grep -qF 'provision_pkg libvirt-daemon-driver-qemu' scripts/host-provision.sh || rb_struct="$rb_struct host-provision:no-session-qemu-driver"
grep -qF 'provision_pkg libvirt-daemon ' scripts/host-provision.sh           || rb_struct="$rb_struct host-provision:no-session-libvirt-daemon"
grep -qF 'cleanup_build_host_network' scripts/cleanup.sh              || rb_struct="$rb_struct cleanup:no-build-host-network-cleanup"
grep -qF 'harness_installed_pkg libvirt-daemon-system' scripts/cleanup.sh || rb_struct="$rb_struct cleanup:no-manifest-gated-system-libvirt-cleanup"
grep -qF -- '--build-host-network' scripts/cleanup.sh                 || rb_struct="$rb_struct cleanup:no-build-host-network-flag"
if grep -qF 'apt-get' scripts/build-windows-vm.sh scripts/provision-windows-vm.sh scripts/verify-windows-golden.sh; then
  rb_struct="$rb_struct windows:networked-helper-apt-get-present"
fi
if grep -qE 'debian:stable-slim|ubuntu:24\.04' scripts/build-windows-vm.sh scripts/provision-windows-vm.sh scripts/verify-windows-golden.sh; then
  rb_struct="$rb_struct windows:ad-hoc-helper-base-present"
fi
grep -q '^SHA256_WIN11_GOLDEN_QCOW2=' scripts/pins.env                                                  || rb_struct="$rb_struct windows:golden-hash-unpinned"
grep -qF 'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"' scripts/build-windows-vm.sh            || rb_struct="$rb_struct windows:build-no-golden-hash"
grep -qF 'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"' scripts/provision-windows-vm.sh        || rb_struct="$rb_struct windows:provision-no-golden-hash"
grep -qF 'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"' scripts/verify-windows-golden.sh       || rb_struct="$rb_struct windows:verify-no-golden-hash"
if [ -n "$rb_struct" ]; then echo "  FAIL R-B5b/B8/B9/B10 build-reproducibility structure regressed:$rb_struct"; rc=1; else
  echo "  ok  R-B5b/B8/B9/B10 builds: digest-pinned base + --network=none offline compile + SHA self-verify + R-B2 double-build A==B assertion (debian & windows; android exempt §12.1); Windows helper image is built only during online-fetch then used offline; golden qcow2 hash is enforced; Windows can validate tracked worktree snapshots; no 0.0.0.0 (R-D3)"; fi

echo "== (6c-b) Flutter/Dart lockfile is authoritative (R-R1/R-B12) =="
dart_lock_bad=
if grep -qE 'NOT consistent|DOES NOT build from the committed lock|open R-B12|RESTORES the committed pubspec.lock|flutter pub get RESOLVES A DIFFERENT' scripts/dart-verify.sh scripts/online-fetch.sh scripts/build-debian.sh scripts/android-apk-build.sh scripts/build-windows.ps1 scripts/run-build.ps1; then
  dart_lock_bad="$dart_lock_bad stale-lockfile-drift-language"
fi
grep -q 'dart pub get --offline' scripts/dart-verify.sh          || dart_lock_bad="$dart_lock_bad dart-verify:no-offline-pub-resolve"
grep -q 'pubspec.lock changed during offline pub resolution' scripts/build-debian.sh      || dart_lock_bad="$dart_lock_bad debian:no-pub-lock-drift-assert"
grep -q 'pubspec.lock changed during offline pub resolution' scripts/android-apk-build.sh || dart_lock_bad="$dart_lock_bad android:no-pub-lock-drift-assert"
grep -q 'pubspec.lock changed during offline pub resolution' scripts/build-windows.ps1    || dart_lock_bad="$dart_lock_bad windows:no-pub-lock-drift-assert"
grep -q 'pubspec.lock drifted during pub cache staging' scripts/online-fetch.sh           || dart_lock_bad="$dart_lock_bad online-fetch:no-pub-lock-drift-assert"
if grep -RInE 'ref:[[:space:]]*HEAD' flutter/pubspec.yaml flutter/pubspec.lock >/tmp/rd_verify_pub_head.$$; then
  dart_lock_bad="$dart_lock_bad flutter-git-ref-head"
fi
rm -f /tmp/rd_verify_pub_head.$$
grep -qF 'ref: bd6b5b41254e57c5bcece202ebfb234de63e6487' flutter/pubspec.yaml ||
  dart_lock_bad="$dart_lock_bad dash-chat-ref-not-commit"
grep -qF 'ref: 85789bfe6e4cfaf4ecc00c52857467fdb7f26879' flutter/pubspec.yaml ||
  dart_lock_bad="$dart_lock_bad window-manager-ref-not-commit"
grep -qF 'ref: b47e8385e5a75d38319ad706a64b0ead3108b093' flutter/pubspec.yaml ||
  dart_lock_bad="$dart_lock_bad desktop-multi-window-ref-not-commit"
if ! awk '
  function clean(value) {
    gsub(/"/, "", value)
    return value
  }
  function check_pkg() {
    if (pkg != "" && source == "git" && resolved != "") {
      if (length(ref) != 40 || ref !~ /^[0-9a-f]+$/ || ref != resolved) {
        print pkg ":" ref "!=" resolved
        bad = 1
      }
    }
  }
  /^  [A-Za-z0-9_]+:/ {
    check_pkg()
    pkg = $1
    sub(":", "", pkg)
    source = ""
    ref = ""
    resolved = ""
  }
  /^[[:space:]]+source:[[:space:]]+git/ {
    source = "git"
  }
  /^[[:space:]]+ref:/ {
    ref = clean($2)
  }
  /^[[:space:]]+resolved-ref:/ {
    resolved = clean($2)
  }
  END {
    check_pkg()
    exit bad
  }
' flutter/pubspec.lock >/tmp/rd_verify_pub_git_refs.$$; then
  dart_lock_bad="$dart_lock_bad flutter-git-ref-not-resolved-commit:$(tr '\n' ',' </tmp/rd_verify_pub_git_refs.$$)"
fi
rm -f /tmp/rd_verify_pub_git_refs.$$
if [ -n "$dart_lock_bad" ]; then echo "  FAIL R-R1/R-B12 Dart lockfile authority regressed:$dart_lock_bad"; rc=1; else
  echo "  ok  R-R1/R-B12 Dart lockfile authority: pub cache staging, verifier, and all offline build paths fail if pubspec.lock drifts; Flutter git deps use commit refs, not HEAD, and lockfile refs match resolved refs"; fi

# (6c-a) Android build pins must be a single manifest, not a grab bag of inherited literals.
# The settings.gradle/plugin pins and the app-level stdlib/runtime pin must match scripts/pins.env;
# otherwise the R-B5a/R-B9 "exact toolchain" claim is false even if the APK happens to compile.
echo "== (6c-a) Android Gradle/Kotlin pins match scripts/pins.env (R-B5a/R-B9) =="
android_pin_bad=
pin_val() { grep -E "^$1=" scripts/pins.env | sed -E 's/^[^"]*"([^"]*)".*/\1/'; }
agp_pin="$(pin_val ANDROID_AGP_VERSION)"
kotlin_pin="$(pin_val ANDROID_KOTLIN_VERSION)"
kotlin_stdlib_pin="$(pin_val ANDROID_KOTLIN_STDLIB_VERSION)"
gradle_pin="$(pin_val ANDROID_GRADLE_WRAPPER)"
compile_sdk_pin="$(pin_val ANDROID_COMPILE_SDK)"
target_sdk_pin="$(pin_val ANDROID_TARGET_SDK)"
min_sdk_pin="$(pin_val ANDROID_MIN_SDK)"
grep -qF "id \"com.android.application\" version \"${agp_pin}\"" flutter/android/settings.gradle || android_pin_bad="$android_pin_bad agp"
grep -qF "id \"org.jetbrains.kotlin.android\" version \"${kotlin_pin}\"" flutter/android/settings.gradle || android_pin_bad="$android_pin_bad kotlin-plugin"
grep -qF "gradle-${gradle_pin}-all.zip" flutter/android/gradle/wrapper/gradle-wrapper.properties || android_pin_bad="$android_pin_bad gradle-wrapper"
grep -qE "compileSdkVersion[[:space:]]+${compile_sdk_pin}\\b" flutter/android/app/build.gradle || android_pin_bad="$android_pin_bad compile-sdk"
grep -qE "targetSdkVersion[[:space:]]+${target_sdk_pin}\\b" flutter/android/app/build.gradle || android_pin_bad="$android_pin_bad target-sdk"
grep -qE "minSdkVersion[[:space:]]+${min_sdk_pin}\\b" flutter/android/app/build.gradle || android_pin_bad="$android_pin_bad min-sdk"
grep -qF "strictly(\"${kotlin_stdlib_pin}\")" flutter/android/app/build.gradle || android_pin_bad="$android_pin_bad kotlin-stdlib"
if [ -n "$android_pin_bad" ]; then
  echo "  FAIL R-B5a/R-B9: Android build pins drift from scripts/pins.env:$android_pin_bad"; rc=1
else
  echo "  ok  Android AGP/Kotlin plugin/Gradle/SDK pins and app kotlin-stdlib runtime pin match scripts/pins.env"
fi

# (6c-i) R-B10 the offline-build network CANARY (MUST — "proven, not trusted"): the spec mandates a
# canary build.rs that attempts an outbound connect and FAILS the compile if the network is reachable,
# so the --network=none isolation is positively proven, not merely assumed. build.rs carries the
# env-gated canary (RUSTDESK_CANARY_OFFLINE=1 -> probe a literal IP; a SUCCESSFUL connect panics) and
# EVERY offline compile stage arms it. The env-gate makes it a no-op in dev/verify builds (which have
# network), so it can only fire when a build CLAIMING to be offline can in fact reach the network.
echo "== (6c-i) R-B10 offline-build network canary (proven, not trusted) =="
r_b10=
grep -q 'fn r_b10_offline_canary' build.rs                                  || r_b10="$r_b10 canary-fn-missing"
grep -q 'RUSTDESK_CANARY_OFFLINE' build.rs                                  || r_b10="$r_b10 canary-not-env-gated"
grep -q 'r_b10_offline_canary()' build.rs                                   || r_b10="$r_b10 canary-not-called"
grep -q 'RUSTDESK_CANARY_OFFLINE=1' scripts/build-debian.sh                 || r_b10="$r_b10 debian-not-armed"
grep -q 'RUSTDESK_CANARY_OFFLINE=1' scripts/build-android.sh                || r_b10="$r_b10 android-not-armed"
grep -q "RUSTDESK_CANARY_OFFLINE = '1'" scripts/build-windows.ps1          || r_b10="$r_b10 windows-not-armed"
if [ -n "$r_b10" ]; then echo "  FAIL R-B10 offline-build canary:$r_b10"; rc=1; else
  echo "  ok  R-B10 offline-build network canary present (build.rs, env-gated) + armed in every offline compile stage (debian/android/windows) — a reachable network during an --network=none build fails the compile"; fi

# (6d) R-B12(a): the aom + libyuv vcpkg overlay distfiles are SHA512-pinned, not fetched by a bare
# git REF. gitiles `+archive` is empirically non-reproducible (so a URL SHA-pin is impossible) and
# R-R1 forbids vendoring — so online-fetch's stage_vcpkg_distfiles captures a REPRODUCIBLE
# `git archive | gzip -n` of the pinned commit into ./online and the portfiles consume it
# SHA512-verified (file://), with vcpkg_from_git as the capture-less (Windows-VM) fallback. Assert
# each portfile carries a 128-hex SHA512 (the captured pin) AND a 40-hex commit REF (the fallback
# anchor), the SHA512 equals the non-sentinel pins.env value, and the capture stage is defined+wired.
echo "== (6d) R-B12(a) aom/libyuv vcpkg distfile SHA512 pinning =="
r_b12a=
for port in aom libyuv; do
  pf="res/vcpkg/$port/portfile.cmake"
  grep -qE 'vcpkg_download_distfile' "$pf" || r_b12a="$r_b12a $port-no-download_distfile"
  grep -qE 'SHA512 [0-9a-f]{128}' "$pf"    || r_b12a="$r_b12a $port-no-sha512"
  grep -qE 'REF [0-9a-f]{40}' "$pf"         || r_b12a="$r_b12a $port-no-full-commit-fallback"
done
for var in SHA512_AOM_3_12_1 SHA512_LIBYUV; do
  val=$(grep -E "^$var=" scripts/pins.env | sed -E 's/^[^"]*"([^"]*)".*/\1/')
  case "$val" in
    ""|*PENDING*|*__*) r_b12a="$r_b12a $var-unset-or-sentinel" ;;
    *) grep -qE "SHA512 $val" res/vcpkg/aom/portfile.cmake res/vcpkg/libyuv/portfile.cmake || r_b12a="$r_b12a $var-not-in-portfile" ;;
  esac
done
grep -qE '^stage_vcpkg_distfiles\(\)' scripts/online-fetch.sh        || r_b12a="$r_b12a capture-stage-undefined"
grep -qE '^[[:space:]]*stage_vcpkg_distfiles$' scripts/online-fetch.sh || r_b12a="$r_b12a capture-stage-not-wired"
if [ -n "$r_b12a" ]; then
  echo "  FAIL R-B12(a): aom/libyuv distfile pinning incomplete:$r_b12a"; rc=1
else
  echo "  ok  R-B12(a) aom/libyuv vcpkg distfiles SHA512-pinned via ./online capture + full-commit fallback + stage wired"
fi

echo "== (7) remote-configuration UI blocking excised (R-S16(d)/R-G1/R-D2) =="
remote_config_blocker_hits=$(rg -n \
  'allow-remote-config-modification|AllowRemoteConfigModification|kOptionAllowRemoteConfigModification|OPTION_ALLOW_REMOTE_CONFIG_MODIFICATION|Enable remote configuration modification|canBeBlocked|shouldBeBlocked|buildRemoteBlock|preventMouseKeyBuilder|ControlPermissionsRemoteModify|MouseMoveTime|MOUSE_MOVE_TIME|VideoConnCount|videoConnCount|video_conn_count|main(CheckMouseTime|GetMouseTime|GetConnectStatus)|wire_main_(check_mouse_time|get_mouse_time|get_connect_status)|is-remote-modify-enabled-by-control-permissions' \
  src libs flutter/lib 2>/dev/null || true)
if [ -n "$remote_config_blocker_hits" ]; then
  echo "  FAIL R-S16(d)/R-G1: remote-configuration UI blocker remnants survived:"
  echo "$remote_config_blocker_hits"
  rc=1
else
  echo "  ok  R-S16(d)/R-G1 remote-configuration UI blocking option and plumbing absent"
fi
if rg -q 'allow-remote-[c]m-modification|AllowRemoteCm|allowRemoteCMModification' \
  src libs flutter/lib; then
  echo "  FAIL R-G1: hidden connection-manager remote-modification gate survived"; rc=1
else
  echo "  ok  R-G1 connection-manager remote modification follows the single remote-config policy; no hidden local gate"
fi

echo "== pending excisions =="
# NONE remain (both former informational-TODO entries resolved 2026-06-25, confirmed by a full-spec
# completion audit):
#  - R-X4 custom_server: REMOVED — the R-A6 hard gate above asserts mod custom_server /
#    get_custom_server_from_string / get_license_from_exe_name / CustomServer / EXE_RENDEZVOUS_SERVER all
#    absent; get_key() returns the baked RS_PUB_KEY unconditionally (override ignored, regression-tested).
#    (The old TODO was a FALSE POSITIVE: its `mod custom_server` grep matched the removal-COMMENT this gate left.)
#  - R-X8 terminal_helper/terminal_service: these modules remain and the terminal is now GRANTED to the
#    authenticated owner (full access — the one mode, R-D8/R-X8/R-F1: enable-terminal=Y pinned, the
#    LoginRequest.Terminal arm honored). R-X8's surviving MUST is the immutable enable-terminal=Y pin
#    (a value, no runtime flip) + the still-excised os_login/LogonUserW SECOND-credential path (R-S18,
#    hard-gated above) — granting the plain terminal adds NO second credential. NOT a module excision.
echo "  ok  no pending excisions (R-X4 custom_server removed + hard-gated; R-X8 terminal granted to the owner, second-credential path still excised)"

if [ "$rc" -ne 0 ]; then
  echo "VERIFY: FAILED (a completed-excision R-A6 gate regressed)"; exit 1
fi
echo "VERIFY: all gates green (KATs + handshake + policy funnel + main-crate compile + R-A6 done-set)"
