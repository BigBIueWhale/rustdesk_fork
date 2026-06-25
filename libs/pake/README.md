# `pake` — balanced CPace, the fork's sole transport authenticator

This crate is the cryptographic core of the hardened RustDesk fork: a balanced
**CPace** PAKE (`draft-irtf-cfrg-cpace-21`, suite `CPACE-RISTR255-SHA512`) run
unconditionally at the connection choke point, before any application byte is
parsed (`requirements.html` §10, §20). A successful run is the *only* way a
session is authorized, and it simultaneously yields the two per-direction
secretbox keys that encrypt every subsequent frame. There is no password-hash
challenge, no "secure flag", no plaintext fallback, and no key-override path —
those were all excised (R-S6/R-T15c, R-A4).

This document is the **R-V3 audit entry point**. The spec mandates an
independent expert audit of *"the §10.4 construction, the state machine, the
constant-time paths, and the KDF/secretbox parameters"* before exposed
operation (R-V3); until then the box ships with the "not independently audited"
disclosure (README.md, §11). The four sections below are organized to match
exactly those four audit obligations, each pointing at the precise code.

All line references are to `src/lib.rs` unless noted; the test vectors live in
`src/tests.rs`.

---

## 0. Scope, dependencies, and what is *not* here

* **Novel math: none.** `curve25519-dalek` supplies every constant-time
  primitive — `RistrettoPoint::from_uniform_bytes` (the hash-to-group map),
  scalar×point, `compress`/`decompress`, and `is_identity`. This crate writes
  only *encoding and transcript* glue: `lv_cat`/`o_cat`, the 64-byte generator
  string, the ISK hash input, the HKDF labels, and the R-P3 confirmation MACs.
  An auditor's curve-level trust therefore reduces to `curve25519-dalek`; this
  crate is auditable as byte-shuffling around it.
* **Pure Rust, no OpenSSL/native.** The crate is protobuf-agnostic and links no
  native code, so it builds and KAT-tests independently of the OpenSSL-linked
  workspace crates. This is deliberate: the security-critical code is isolable.
* **Out of scope here (audited elsewhere):**
  * The on-wire mapping of `Step1`–`Step4` to the `Cpace` protobuf oneof and
    the choke-point driver — `create_tcp_connection` / `secure_tcp`
    (`libs/hbb_common/src/tcp.rs`), R-P14.
  * The AEAD transport that *consumes* `DirectionalKeys` — XSalsa20-Poly1305
    `secretbox`, the `SealCipher`/`OpenCipher` split, the dedicated writer task,
    and per-frame sequencing (R-T2/T3/T5/T7, `tcp.rs`).
  * The online-guess limiter that `PakeError::Confirmation` feeds (R-S10).
  * The host-key pin / host-proof that binds the responder's long-term identity
    on top of this PAKE (R-S17, `src/client.rs`).

---

## 1. The §10.4 construction

One suite, one draft version, one DSI set — **no negotiation, no downgrade**
(R-P11). All constants are pinned at lines 38–63:

| Element | Value | Code |
|---|---|---|
| Suite DSI | `CPaceRistretto255` | `SUITE_DSI` |
| ISK DSI | `CPaceRistretto255_ISK` | `ISK_DSI` |
| MAC DSI | `CPaceMac` | `MAC_DSI` |
| Channel-id tag | `rustdesk-fork/CPACE-RISTR255-SHA512/v1` | `CI_TAG` |
| HKDF salt | `…/v1/hkdf` | `HKDF_SALT` |
| HKDF info (c2s / s2c) | `…/CPace/secretbox/c2s` · `…/s2c` | `HKDF_INFO_*` |
| Role AD (initiator / responder) | `viewer` · `server` | `AD_INITIATOR` / `AD_RESPONDER` |
| Pinned port (folded into CI) | `21118` | `CI_PORT` |

**Channel identifier (CI), `channel_identifier`, l.230.**
`CI = lv_cat(CI_TAG, be16(port))`. CI is byte-identical on both peers and
**never transmitted** — the port is the *compile-time* `CI_PORT`, never read
from the live socket, so NAT/port-forwarding cannot desync it (l.60–63). A CI
mismatch makes the generator differ and the handshake fails closed.

**Generator string → generator point, `generator_string` l.216 / `derive_generator` l.241.**
`gs = lv_cat(SUITE_DSI, PRS, zpad, CI, sid)`, where the zero-pad fills the first
SHA-512 input block (`S_IN_BYTES = 128`) and **the pad field is itself
length-prefixed** by `lv_cat` (§10.4 trap — see §3). Then
`g = from_uniform_bytes(SHA512(gs))`.

**ISK, `compute_isk` l.254.**
`ISK = SHA512( lv_cat(ISK_DSI, sid, K) ‖ o_cat(lv_cat(Ya,ADa), lv_cat(Yb,ADb)) )`.
The transcript half is appended **raw** — re-wrapping it in `lv_cat` yields a
different, wrong ISK and fails the published vector (§3 trap #2).

**Session keys, `derive_session_keys` l.269.**
Two 32-byte keys via `HKDF-SHA512(salt=HKDF_SALT, ikm=ISK)` expanded under two
distinct info labels → `(k_c2s, k_s2c)` (R-P2/R-P9). Distinct labels are what
make the two directions cryptographically independent.

**Key-confirmation MAC, `derive_mac_key` l.281 / `compute_tag` l.293.**
`mac_key = SHA512(MAC_DSI ‖ sid ‖ ISK)` — a **bare concat**, deliberately *not*
`lv_cat`, *not* HKDF (R-P3). `T = HMAC-SHA512(mac_key, lv_cat(Y, AD))`.

---

## 2. The state machine

Expressed as **consuming type-states**, so each step is consumed exactly once
and a misordered or duplicate frame is a compile-time or fail-closed error,
never silently buffered (l.344–348). Two round trips, four messages:

```
Initiator (viewer)            Responder (controlled)
  Initiator::new ──Step1{sid_a,ADa}────────────►  Responder::new → recv_step1
  recv_step2  ◄───Step2{sid_b,ADb,Yb}──────────
  ─Step3{Ya,Ta}────────────────────────────────►  recv_step3
  recv_step4  ◄───Step4{Tb}─────────────────────
       ▼                                              ▼
  DirectionalKeys{send=k_c2s, recv=k_s2c}        DirectionalKeys{send=k_s2c, recv=k_c2s}
```

Key authorization-ordering invariant (R-P3/R-A1): the responder verifies the
initiator's `Ta` in constant time **before** emitting `Tb` or returning keys
(`recv_step3`, l.598) — a wrong password never gets a usable response. The
initiator verifies `Tb` before returning keys (`recv_step4`, l.472).

The `DirectionalKeys` returned to each side are **role-oriented** (R-P2): the
viewer seals with `k_c2s`/opens with `k_s2c`; the controlled side mirrors. A
single keying call therefore cannot reproduce the same-key-both-ways reuse the
old symmetric `set_key` allowed.

Fail-closed aborts (`PakeError`, l.74): `Confirmation` (the **only** online
password guess — `is_password_guess` true, the sole event that may feed the
R-S10 limiter, l.99), `Decode`, `Identity`, `AdMismatch`, `EmptyPassword`,
`Rng`. The classification matters operationally (R-P14c): treating a
malformed-frame flood as a guess would let an attacker trip the *owner's* own
block, so only `Confirmation` counts.

---

## 3. Constant-time paths & the draft footguns avoided

Audit focus per R-V3. The four documented `draft-21` traps and the defenses:

1. **Scalar sampling (`sample_scalar`, l.327).** Uses the wide reduction
   `Scalar::from_bytes_mod_order_wide` over 64 CSPRNG bytes — *never* the
   deprecated, Edwards-only, bit-masking `from_bits`. A masked/clamped scalar
   would bias the group element.
2. **Raw transcript in ISK (`compute_isk`, l.258–259).** The `o_cat(...)`
   transcript is appended raw to `lv_cat(ISK_DSI, sid, K)`; re-`lv_cat`-wrapping
   it computes a *valid-looking but wrong* ISK (`49ddbd…`) — caught by the
   published-vector KAT.
3. **Length-prefixed zero-pad (`generator_string`, l.216–223).** `lv_cat`
   length-prefixes the zpad field itself; omitting that prefix is the classic
   CPace generator-string mistake.
4. **`o_cat` ordering (l.201).** Order-independent concat with the `b"oc"`
   prefix, larger operand first (`lexicographically_larger`, ties by length,
   l.187) — so both peers compute an identical transcript without exchanging an
   ordering.

**Constant-time comparisons.** Peer tags are verified only via HMAC's own
`verify_slice` (`verify_tag`, l.304/307) — never a `==` byte compare. There is
no other secret-dependent branch on attacker-supplied bytes.

**Identity check after the multiply (l.437, l.579).** `K`'s all-zeros encoding
*decodes* successfully, so the degenerate-key check is `is_identity()` on the
computed point, not a decode check (R-P7) — and it is applied on both sides.

**Sender-binding (R-P5).** `ADa`/`ADb` are checked for **literal equality**
against the pinned role tags (l.410, l.536), not merely folded into the
transcript — this is what makes each confirmation tag sender-bound and defeats
loopback/reflection of a peer's own frames.

**Empty-PRS guard (`normalize_prs`, l.312).** PRS = NFC(password) (an NFC-only
subset of RFC 8265 OpaqueString, no case-fold, R-P1); rejected if empty after
normalization. CPace itself has no empty-PRS guard, so the fork adds one
(R-P1/R-S9).

**Secret-zeroization (R-T15a/R-P12).** Every PRS-laden or key-laden
intermediate is wiped on *every* exit path, including attacker-triggerable early
returns and timeouts:
* The generator point `g`, the SHA-512 generator digest, the DH point `K`, and
  the ISK are wrapped in `Zeroizing` (l.242–247, 420, 435, 444, 546, 578, 586).
* Ephemeral scalars are explicitly `zeroize()`d on the malformed-element
  early-returns (l.411, 429, 436, 537, 573, 599, 603) — the `?` shorthand would
  skip the wipe and leak `ya`/`yb` on an attacker-triggered abort.
* `DirectionalKeys` (l.145) and the await-states (`InitiatorAwaitConfirm`
  l.366, `ResponderAwaitConfirm` l.500) implement `Drop` to wipe derived keys /
  the ephemeral scalar — closing the R-P14b *stall-after-step-N* timeout leak
  where a half-open handshake's secrets would otherwise linger in freed memory.

---

## 4. KDF / secretbox parameters & the test basis

* **KDF:** HKDF-SHA512, non-secret fixed salt `HKDF_SALT`, IKM = the 64-byte
  ISK, two 32-byte outputs under distinct info labels (§1). 32-byte expansion
  never fails (l.273).
* **Secretbox keys:** the `DirectionalKeys` are consumed by the
  XSalsa20-Poly1305 transport (out of scope here; `tcp.rs`). This crate's
  contract is only that the two keys are independent and role-oriented.

**Vectors (`src/tests.rs`):**
* **R-V2 — CFRG draft conformance:** the published ristretto255 vector
  (`G_Coffee25519`): generator `g = 222b6b19…`, `ISK_SY = 544199d7…`. This
  pins the construction byte-for-byte against the draft. *(Note: these are the
  draft's own published intermediate values — the upstream cross-check — not
  fork-runtime session values; do not confuse the two.)*
* **R-A10 — fork KAT anchor A:** a 16-byte draft-style sid at port 21118.
* **R-A10 — fork KAT anchor B:** a 32-byte production sid, driven through the
  full `Initiator`/`Responder` R-P14a state machine end to end.

These run inside `cargo test -p pake` and are gated by `scripts/verify.sh`
(the KAT block), so a construction regression fails CI. The broader
adversarial suite — replay/reorder/duplicate first frame, oversize pre-PAKE
frame, wrong-password refusal, identical-key refusal, host-proof binding — lives
in the integration `cpace_it` tests and is likewise gated.

---

## Summary for the auditor

The trust surface is small and isolable: ~600 lines of pure-Rust encoding and
transcript glue over `curve25519-dalek`'s audited constant-time primitives, with
every §10.4 byte pinned by a published-vector KAT and every secret wiped on
every path. The four R-V3 obligations map to §1 (construction), §2 (state
machine), §3 (constant-time paths + the four avoided draft traps), and §4
(KDF/secretbox params + vectors). Findings should be filed against
`requirements.html` §10.4 / §11 and resolved or risk-accepted in writing before
the "not independently audited" disclosure is removed.
