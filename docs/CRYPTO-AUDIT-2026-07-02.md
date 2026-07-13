# AI Cryptographic Review — CPace PAKE

**Date:** 2026-07-02
**Scope:** the in-tree CPace balanced-PAKE and its integration — §10 (the PAKE), §11
(verification), and the wire/at-rest crypto it depends on.
**Tree:** `master`, audit base `0c7442e`, re-reviewed through `b6f5eea`, findings resolved
at `4eb6912`.
**Requirement status:** this review does not fulfill R-V3's independent external expert-audit requirement.

> ⚠️ **PARTIALLY SUPERSEDED (2026-07-04).** After this audit, the **host-key / host-proof
> identity layer** it covers (R-S17 — the Ed25519 host-proof + the no-TOFU pin) was **retired
> entirely** (`16b67a2` spec, `8fbdecb` code): the fork is now a **pure balanced password-PAKE**
> with **no per-box identity key**. As part of that, the CPace PRS salt changed from the
> host-key-bound `SHA256(DSI‖host_pubkey)` to a **fixed** domain-separation constant
> `SHA256("rustdesk-cpace-prs-salt-v1")`. This report is left intact as the truthful record of the
> construction **as audited on 2026-07-02**; for the current design see `requirements.html`
> (§10/§11). The CPace core, the two-key AEAD channel, and the Argon2id memory-hardness reviewed
> here are unchanged — only the host-identity layer and the salt source were removed/changed.

## Provenance & nature of this review (read first)

This is an **AI-conducted review** performed by **Claude Opus 4.8**. It includes a byte-level
reproduction using a separately implemented stack and first-principles protocol analysis, and
it found and drove the resolution of real defects. It is nonetheless a **single-model** review,
not an organizationally independent professional audit and not equivalent to the multi-party,
decades-deep scrutiny that SSH's channel crypto enjoys. This report is evidence available to a
future auditor, not the external sign-off R-V3 requires.

## Verdict

**SOUND.** The CPace construction is correct (proven by independent reproduction), the
protocol composition is sound (first-principles analysis), and the three findings raised
below are **resolved**. No wire-exploitable cryptographic defect was found. On the wire the
fork meets or exceeds SSH-password-auth; the residual axis where SSH leads is *maturity*
(above) and the universal in-process media-decode residual when acting as a viewer
(Appendix C #2b), not the keyed channel.

## Methodology

1. **Independent construction reproduction (the decisive check).** The spec warns (R-V2/R-V3)
   that the fork's own KATs "cannot catch a self-consistently-wrong composition." To rule that
   out, every pinned byte was re-derived with an *independent* stack:
   - curve math: **libsodium** `crypto_core_ristretto255_*` (a separate C codebase from the
     fork's `curve25519-dalek`);
   - encoding (`lv_cat`/`leb128`/`o_cat`/`generator_string`) and HKDF: re-implemented from the
     draft, not copied from the Rust.

   This reproduced, byte-for-byte: the **official CFRG draft-21 ristretto255 vector**
   (`G_Coffee25519`: `g`, `Ya`, `Yb`, `K` both DH directions, `ISK_SY`) loaded from the
   published `testvectors.json`, **and** fork anchor A (16-byte draft sid) **and** fork anchor B
   (32-byte production sid) — all fields each. Two independent curve libraries + two independent
   encoders cannot share an identical bug *and* both hit the CFRG-published values, so the
   construction is proven, not merely self-consistent.

2. **First-principles protocol analysis** of the parts no vector covers: the R-P3
   key-confirmation MAC composition, the two-key directional AEAD/nonce discipline, the R-P14a
   state machine, the R-S17 host-proof + no-TOFU pin, the Argon2id PRS binding, the per-source
   limiter, and forward secrecy — attacked from the MITM / replay / downgrade / reflection /
   substitution / relay-splice (triple-handshake) / identity-and-small-subgroup lenses.

3. **Line-by-line integration review** of `libs/pake/src/{lib,tests}.rs`,
   `libs/hbb_common/src/{cpace,tcp}.rs`, `libs/hbb_common/src/config/permanent_password.rs`,
   `libs/hbb_common/src/host_pin.rs`, `src/client.rs`, and `src/server.rs`.

4. **Execution:** `libs/pake` KATs (16 pass) and, via `scripts/verify.sh` in Docker, the
   wire-level `cpace_it` handshake + two-key-cipher + adversarial-injection tests, the policy
   funnel, the main-crate compile, and the R-A6 gates; `scripts/audit.sh` for the dependency
   ledger. (The credential-flow fix below was researched with three independent Opus subagents —
   lifecycle map, F-2/F-3, and recovery/precedence — before any edit.)

## What was verified sound

- **Construction (KAT + independent reproduction):** generator zero-pad, the "raw transcript
  append" ISK trap, `mac_key` bare-concat, HKDF label separation (`k_c2s ≠ k_s2c`), `o_cat`
  symmetric ordering (→ `ISK_SY`), CI byte-encoding, NFC PRS handling.
- **Two-key AEAD (closes Appendix C #1, the un-CVE'd two-time-pad):** distinct per-direction
  keys, monotonic non-wrapping counters (first nonce `LE64(1)`), engaged-key distinctness
  asserted (`split_session_keys`), authenticate-every-frame (no ≤1-byte bypass),
  poison-on-error (no nonce reuse after a send error), replay/reorder → MAC fail → teardown.
- **R-P3 mutual confirmation:** reflection-resistant (AD equality check), verify-before-authorize
  ordering at the responder, HMAC-SHA512 via constant-time `verify_slice`.
- **R-P14a state machine:** consuming type-states + single-variant match ⇒ duplicate/out-of-order
  frames abort fail-closed; `set_key` reachable only from the tag-verify success edge; bounded
  reads (4 KiB cap, per-step timeout).
- **R-S17 host-proof + no-TOFU:** Ed25519 over `DSI‖sid‖CI‖Ya‖Yb` (all fixed-length ⇒
  unambiguous), verified as the first post-key frame before the viewer sends anything;
  fail-closed pin-compare; first pin established only out-of-band (`--pin-host`) — no
  trust-on-first-use. Welding to `sid`/`Ya`/`Yb` forecloses cross-session relay/splice.
- **Two-factor by construction:** password (PRS) ⊕ pinned Ed25519 key — compromising either
  alone cannot impersonate; forward secrecy holds (ephemerals zeroized; a host-key leak does
  not expose past sessions).
- **PRS at rest:** `Argon2id(NFC(pw), salt = SHA256(dsi‖hostkey)[..16])`, INTERACTIVE limits,
  reusing the *identical* `pake::nfc_normalize`, salt genuinely bound to the host key.
- **Randomness:** the PAKE uses `getrandom` (OS CSPRNG) directly, so RUSTSEC-2026-0097
  (`rand::thread_rng`) does not touch the scalars.

## Findings (as raised) and resolution

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| **F-1** | LOW–MODERATE | The **viewer** persisted the RAW plaintext password in `PeerConfig.password_prs`, not the derived Argon2id PRS R-S9 mandates — so a config read (+ machine UUID) recovered the reusable plaintext (Appendix C #14 / CVE-2026-30785 class); the controlled side already avoids this. | **Fixed `@4eb6912`.** The viewer twin is now the derived PRS: `key_initiator` feeds a stored PRS to the PAKE *verbatim* and derives only fresh plaintext (a `credential_is_derived` flag; re-Argon2id-ing an already-derived PRS would silently fail keying); both staging sites stage the derived value; `_start` precedence inverted so a re-entered password overrides a stale twin (prevents an endless prompt loop after a re-pin — the derived PRS is pin-bound, so a key rotation invalidates it, per R-S9 re-provision); `forget_password`/`peer_has_password` cover the twin. |
| **F-2** | LOW | R-P12's machine-checked constant-time test was absent (property rested only on the type-level `subtle`/`dalek`/`verify_slice` guarantees). | **Fixed `@4eb6912`.** Deterministic constant-time gate added to `scripts/verify.sh` (`verify_tag` uses `verify_slice`, no `==`/`!=` on the tag, `sample_scalar` uses the wide reduction, no `Scalar::from_bits` in `libs/pake`) — regression-tested against synthetic mutations — plus an `#[ignore]d` dudect-style probe (honestly low-power vs the dominating HMAC; the gate + type-level guarantees are the real check). |
| **F-3** | LOW | `sodiumoxide` unmaintained (RUSTSEC-2021-0137); `rand` should be ≥ 0.8.6 (RUSTSEC-2026-0097). | **Already resolved in-tree** (my initial report over-stated it): `rand` is already 0.8.6 in `Cargo.lock`, RUSTSEC-2026-0097 documented as fixed in `deny.toml`, `sodiumoxide` already in the accept-list. Confirmed green by `scripts/audit.sh`. No edit. |

**Non-live observations (documented, no behavioral change):**
- The Argon2id salt is deterministic/public (a function of the box's public host key). This is a
  *deliberate* no-salt-exchange serverless design (R-P1): both ends must derive the identical PRS
  with no exchange, and the host key is the value both already hold. It yields memory-hardness but
  not precomputation-resistance for a targeted, already-compromised box — acceptable under §2
  (plaintext recovery requires prior endpoint compromise, at which point the PRS is already
  connect-equivalent). A random exchanged salt would break the design; **not changed**, now
  **documented** in `permanent_password.rs`.
- An imprecise `pending_host_pk` comment (it is stashed on a host-key *mismatch*, not on a no-pin
  abort) was corrected.

## Scope & limitations (what this audit is not)

1. **Single reviewer, AI-conducted** (see Provenance) — one model's assessment, not a
   multi-party review.
2. **Timing/side-channels are covered at the type level, not empirically.** No serious
   dudect/ctgrind campaign on target hardware was run (and is argued low-value here, since the tag
   compare is dominated by the HMAC recompute). Power/cache/fault channels were not assessed.
3. **Primitives are trusted, not re-audited:** `curve25519-dalek`, `libsodium`/`sodiumoxide`, and
   the CPace security proof (Abdalla–Haase–Hesse, adaptive UC) are taken as given, as the spec
   intends ("zero novel curve math"). This review confirms the *implementation faithfully matches*
   the proven construction, not the proof or the primitives themselves.
4. **No formal-methods proof** (e.g. a Tamarin/ProVerif protocol model or a verified
   implementation).
5. **Scope was the crypto/wire boundary.** The other trust boundaries (protobuf parser,
   file-transfer taint, local IPC/CM authorization) were covered by prior in-house audits recorded
   in `HARDENING_STATUS.md`, not re-done here.

## Conclusion

This review found the mathematics correct and the protocol composition sound, and its findings
were resolved in writing and in code. It does not establish independent expert assurance and
does not satisfy R-V3. The residuals above — single-model review, trusted primitives, no formal
proof, and type-level timing — define the evidence and limitations an external auditor must
evaluate before exposed production operation.

*Verification artifacts:* `scripts/verify.sh` (all gates green — KATs, wire handshake, main-crate
compile, R-P12 gate), `scripts/audit.sh` (green), `libs/pake` (16 passed / 1 ignored; the
constant-time probe passes). Reviewer: Claude Opus 4.8 (1M context).
