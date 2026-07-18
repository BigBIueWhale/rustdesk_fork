# R-V3 external cryptographic audit handoff

This is the current handoff contract for the independent expert audit required
by `requirements.html` R-V3. It identifies the minimum code and evidence that
must be reviewed, but it is not an audit report and it is not a project-authored
substitute for one.

**Current status: R-V3 is outstanding.** Repository tests, the 2026-07-02 AI
review, this scope document, and the scope-drift verifier do not satisfy R-V3.
Only an independently authored expert review of an exact public Git commit,
followed by publication of the resulting report and disposition of every
finding, can satisfy it.

## 1. Object being audited

The review object is one exact, clean public Git commit from
<https://github.com/BigBIueWhale/rustdesk_fork>, not a project-prepared source
archive or a curated subset. Before analysis begins, the auditor's report must
record:

- the full commit ID and `HEAD^{tree}` ID;
- the recursive submodule status and every lockfile/build-input revision used;
- whether the checkout was clean and detached at that commit;
- compiler, target, operating-system, dependency-audit, static-analysis, and
  dynamic-analysis tool versions; and
- any code, configuration, generated file, patch, or build option that differed
  from the recorded commit.

The entire repository remains in scope for call-graph and contradiction checks.
The roots below are a mandatory minimum, not an exclusion list. If a listed
symbol calls into another source file, generated binding, dependency, platform
adapter, or unsafe/native boundary, the auditor follows that edge far enough to
validate the security claim.

Suggested checkout identity record:

```sh
git status --porcelain=v1
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
git submodule status --recursive
git diff --exit-code
git diff --cached --exit-code
```

An audit of a dirty tree, an unpublished commit, or only a copied directory is
not an audit of the release candidate.

## 2. Normative and primitive references

The fork deliberately pins **`draft-irtf-cfrg-cpace-21`**, suite
`CPACE-RISTR255-SHA512`. Later CPace revisions and any eventual RFC are useful
comparison material, but they must not silently redefine the construction being
audited. A standards update requires a deliberate code, requirements, and
vector change.

Primary references:

- CPace draft-21, including Sections 4, 7, 9, 10, and the ristretto255 vectors
  in Appendix B: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21>
- CFRG source and reference implementation used to generate the vectors:
  <https://github.com/cfrg/draft-irtf-cfrg-cpace/tree/draft-irtf-cfrg-cpace-21>.
  The pinned annotated tag object is
  `65e7a118161f57f29b8ef2ed6cf7eb48da9a6a3e`; it peels to commit
  `8fb4056e1b9201927d9f651b9970d9d5660c7892` (reverified from the primary
  repository on 2026-07-18). The auditor must record and compare both rather
  than trusting a movable tag name alone.
- RFC 8265 OpaqueString rules, against which the fork's intentionally narrower
  NFC-only password preparation must be compared:
  <https://www.rfc-editor.org/rfc/rfc8265>
- libsodium `crypto_secretbox` construction and nonce requirements:
  <https://doc.libsodium.org/secret-key_cryptography/secretbox>
- the exact dependency graph and checksums in `Cargo.lock`, including
  `curve25519-dalek` 4.1.3, `unicode-normalization` 0.1.23,
  `sodiumoxide`/`libsodium-sys` 0.2.7, `hkdf` 0.12.4, `hmac` 0.12.1,
  `sha2` 0.10.8, and `zeroize` 1.8.1.

The draft's published vectors stop at CPace outputs such as `ISK`; they do not
validate the fork-specific channel identifier, HKDF labels, confirmation-MAC
composition, transport key installation, or nonce lifecycle. The fork KATs and
adversarial tests cover regressions in those choices, but self-consistency is
not an independent proof that the choices are sound.

## 3. Mandatory minimum review roots

### Credential to PRS

- `requirements.html`: R-P1, R-P3, R-P5, R-P7, R-P8, R-P9, R-P11, R-P12,
  R-P14, R-A5, R-A10, R-S9, R-S10, Section 10.4, Section 11, and R-V3.
- `libs/hbb_common/src/config/permanent_password.rs`:
  `CPACE_PRS_SALT_DSI`, `CPACE_PRS_OPSLIMIT`, `CPACE_PRS_MEMLIMIT`,
  `derive_cpace_prs_raw`, `derive_cpace_prs`,
  `derive_permanent_password_storages`, and the storage reconstruction tests.
- `libs/pake/src/lib.rs`: `canonical_decomposition_len`,
  `fill_canonical_decomposition`, `canonical_order`, `canonical_compose`,
  `encode_normalized`, `try_nfc_normalize`, `nfc_normalize`, and
  `normalize_prs`.
- `src/client.rs`: `key_initiator` and the distinction between a freshly typed
  password and an already-derived remembered PRS.
- `src/server.rs`: `effective_permanent_password_credential_snapshot` and
  `authenticate_tcp_stream`, including credential-generation rechecks around
  handshake completion and key installation.
- `src/direct_service.rs`: the password/PRS availability check that parks or
  drops the public listener when no usable credential exists.

The auditor must treat the local NFC implementation as handwritten
security-relevant code. It uses Unicode decomposition/class/composition tables
from `unicode-normalization`, but the fixed-allocation decomposition, stable
canonical ordering, composition, encoding, checked-length behavior, zeroizing
buffers, and abort-on-internal-failure policy are implemented in this fork.
Review its equivalence to the intended NFC-only policy, its Unicode-version
dependency, its work and allocation bounds, its secret lifetime, and its error
behavior. Do not infer full RFC 8265 OpaqueString conformance: the fork
intentionally omits the non-ASCII-space mapping and FreeformClass rejection.

### CPace construction and state machine

- `libs/pake/Cargo.toml` and `Cargo.lock`: exact primitive selection, features,
  versions, and transitive dependency/unsafe surface.
- `libs/pake/src/lib.rs`: `generator_string`, `channel_identifier`,
  `derive_generator`, `compute_isk`, `derive_session_keys`, `derive_mac_key`,
  `compute_tag`, `verify_tag`, `sample_scalar`, `decompress`,
  `Initiator::recv_step2`, `InitiatorAwaitConfirm::recv_step4`,
  `Responder::recv_step1`, `ResponderAwaitConfirm::recv_step3`, and every
  secret-bearing `Drop`/`Zeroizing` path.
- `libs/pake/src/tests.rs`: the draft-21 `G_Coffee25519` vector, both fork KAT
  anchors, role-oriented key checks, wrong-password behavior, AD mismatch,
  identity/decode rejection, replay behavior, NFC behavior, and the explicitly
  limited ignored timing probe.

Review every byte boundary and domain-separation value, the draft-to-fork
composition, scalar generation, Ristretto decode/identity handling, explicit
role binding, confirmation-before-authorization order, error classification,
and all success, error, timeout, and drop paths for secret erasure. Verify the
published vector independently rather than trusting the expected constants in
the same source tree.

### Wire choreography and authorization edge

- `libs/hbb_common/protos/message.proto`: `CpaceStep1` through `CpaceStep4` and
  the `Cpace` oneof.
- `libs/hbb_common/src/cpace.rs`: `exact`, `send_cpace`, `recv_cpace`,
  `run_initiator_with_transcript`, `run_responder_with_transcript`,
  `HandshakeError::is_password_guess`, `guess_limiter_allows`, and
  `record_handshake_failure`.
- `libs/hbb_common/src/stream.rs`: the sole transport variant and the
  `set_session_keys`/`is_secured` forwarding boundary.
- `src/client.rs`: `key_initiator`, its `run_initiator` call, and its one key
  installation edge.
- `src/server.rs`: `create_tcp_connection`, `authenticate_tcp_stream`, the
  `run_responder` call, online-guess accounting, credential-generation checks,
  `set_session_keys`, and the post-handshake `is_secured` guard.
- `src/server/connection.rs`: the single `self.authorized = true` edge and the
  credential-generation condition that guards it.

Review malformed lengths and protobuf behavior, exact step ordering, duplicate
and replay handling, every per-step send/receive deadline, partial
I/O/cancellation behavior, whether any application parser or authorization
edge is reachable before confirmed key installation, and whether any
non-confirmation input can poison the owner's online-guess budget.

### Key derivation and encrypted frame lifecycle

- `libs/hbb_common/src/cpace.rs`: `cipher_nonce`, `SealCipher::seal`,
  `OpenCipher::open`, `split_session_keys`, and `DirectionalCipher`.
- `libs/hbb_common/src/tcp.rs`: `SecretboxCodec::decode`,
  `FramedStream::send_bytes`, `FramedStream::next`,
  `FramedStream::set_session_keys`, `writer_task`, and `FramedStream::drop`.
- `docs/TRANSPORT-SECURITY.md`: the current claim map; verify every claim from
  code rather than treating this project-authored document as evidence.

Review HKDF-SHA512 extraction/expansion and labels, role-to-direction mapping,
XSalsa20-Poly1305 key/nonce/tag parameters, distinct-key enforcement, monotonic
counter exhaustion, authenticate-before-parse order, replay/reorder behavior,
frame caps, poison semantics, cancellation safety, seal/channel/wire ordering,
back-pressure, graceful drain, task teardown, and every path that can retain or
reuse a key or nonce after an error.

### Evidence and residuals

- `libs/cpace_it/tests/handshake.rs` and
  `libs/cpace_it/tests/guess_limiter_cap.rs`.
- `libs/config_it/tests/prs_derivation.rs` and the PRS/storage tests in
  `libs/config_it/tests/lockdown.rs`.
- `scripts/verify.sh`, `scripts/audit.sh`, `deny.toml`, and the relevant pinned
  inputs in `scripts/pins.env`.
- `docs/CRYPTO-AUDIT-2026-07-02.md`: historical AI review only. It is partially
  superseded by retirement of host identity/pinning and must not be imported as
  independent evidence.
- `HARDENING_STATUS.md`, `README.md`, and release disclosure text: check that
  status and limitations agree with the code and with the external findings.

The normal repository assurance run is `scripts/verify.sh`; its focused PAKE
and wire tests execute in the pinned development-check container. Dependency
advisory review is `scripts/audit.sh`. The auditor should also use independent
implementations, vectors, static/dynamic analysis, fuzzing or property tests,
and platform/runtime checks appropriate to the findings. Passing project tests
is necessary evidence of the reviewed commit, not the audit conclusion.

**Behavioral R-A10 evidence now present:**
`partial_prekey_frame_times_out_without_key_or_guess_charge` in
`libs/cpace_it/tests/handshake.rs` sends a valid 64-byte pre-key frame header and
only one payload byte while holding the raw TCP peer open. With Tokio's paused
test clock, it proves the responder remains pending until the exact 5-second
R-P14b WAIT_1 deadline, returns `HandshakeError::Io`, never engages the
`FramedStream` cipher, and drops the connection. The test passes that actual
error through the production accounting choke after priming a unique source to
nine confirmed guesses and proves the source remains allowed; the companion
wrong-password test proves a tenth `HandshakeError::Confirmation` is recorded
and blocks. The same no-key/no-charge assertions now cover the oversize,
out-of-order, duplicate, and malformed wire negatives.
**This closes the known project-test evidence gap.** It is not independent
review evidence and does not satisfy R-V3.

## 4. Required questions and deliverable

At minimum, the published external report must answer:

1. Does the exact byte construction conform to the pinned draft-21 suite and
   the fork's explicitly documented extensions?
2. Can any network input reach application parsing, authorization, or a usable
   transport key before both confirmation checks and all credential-generation
   conditions succeed?
3. Are password preparation, Argon2id parameters, PRS storage/use, scalar and
   group operations, confirmation comparisons, and secret erasure correct for
   every success and abort path?
4. Can key/nonce reuse, direction inversion, counter reset/wrap, replay,
   reordering, cancellation, back-pressure, poisoning, or task teardown break
   confidentiality or integrity?
5. Do parser, allocation, timeout, limiter, and listener/keying boundaries fail
   closed without creating a remotely useful denial-of-service amplification?
6. Are all security claims and residuals accurate, including the fixed global
   Argon2id salt, NFC-only (not OpaqueString) preparation, balanced-PAKE stored
   PRS equivalence, draft status, dependency assumptions, ignored timing probe,
   and lack of post-quantum security?

The report must include methodology, exact scope, independence/conflict
disclosure, limitations, severity definitions, reproducible evidence for each
finding, and a finding-by-finding disposition. Findings are resolved by code
and evidence or explicitly risk-accepted in writing; they are not closed by
editing the report. The final report and its reviewed commit must be publicly
linked from the release record before the R-V3 disclosure can be removed.

## 5. What this handoff proves—and does not

`scripts/verify-crypto-audit-scope.py` checks that these living audit entry
points still name the current mandatory roots and symbol anchors, contain no
brittle source line-number citations, and do not claim project-authored
independent sign-off while R-V3 is outstanding. Its mutation self-test proves
those checks fail when representative scope, symbol, citation, or status facts
are removed or falsified.

That gate prevents a repeat of the documentation drift that this handoff
corrects. It cannot assess cryptographic soundness, reviewer competence or
independence, call-graph completeness, runtime behavior, or finding severity.
It therefore does not satisfy R-V3.
