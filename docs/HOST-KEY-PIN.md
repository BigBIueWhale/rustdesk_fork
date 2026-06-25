# Host-key pinning — the R-S17 host-identity binding

Third of the security-surface audit-scope docs (with
[`libs/pake/README.md`](../libs/pake/README.md) and
[`TRANSPORT-SECURITY.md`](TRANSPORT-SECURITY.md)). The PAKE proves both sides
know the password and keys the channel; **this** layer binds the controlled
box's *long-term identity* (an Ed25519 host key) on top of it — the fork's
SSH-`known_hosts` analog (R-S17).

**The threat it closes.** A balanced PAKE alone authenticates *whoever holds the
password*. If the password leaks, or an attacker who learned it stands up a
look-alike box at the same address, the PAKE succeeds. R-S17 adds a second,
independent factor the attacker cannot forge without the box's Ed25519 *private*
key: a session-welded host-proof, pin-compared against a key the operator
verified out-of-band — exactly as SSH refuses a server whose host key changed.

Code: `libs/hbb_common/src/cpace.rs` (the proof), `src/client.rs` (the viewer's
verify + pin-compare), `libs/hbb_common/src/host_pin.rs` (the pin store),
`src/server.rs` (the responder's emit).

---

## 1. The host-proof

* **Signed message (`host_proof_message`, `cpace.rs:311`):**
  `DSI ‖ sid ‖ CI ‖ Ya ‖ Yb`, where `DSI = "rustdesk-fork/host-proof/v1"`
  (`cpace.rs:304`). The domain separator means this Ed25519 signature can serve
  no other purpose — it cannot be confused with or relayed into any other
  signing context.
* **Emit (responder, `build_host_identity`, `cpace.rs:328`; called at
  `server.rs:396`):** the controlled box signs the message with its Ed25519
  secret key (`Config::get_key_pair().0`) and sends `HostIdentity{pk, sig}` as
  the **first post-keyed frame** — encrypted under the freshly-derived session
  key.
* **Verify (viewer, `verify_host_identity`, `cpace.rs:347`; called at
  `client.rs:395`):** parse the frame, verify the Ed25519 signature over the
  *locally reconstructed* message against the carried `pk`. Missing proof, a
  forged signature, a mutated `pk` (a substitute that merely *saw* the key), or
  a signature from another session all fail closed (`client.rs:391-400`).

The proof is read and verified **before any other post-key frame** is processed
(`client.rs:389-390`) — identity is established before anything trusts the
channel.

---

## 2. Why the proof is session-welded

Folding `sid` and **both** ephemerals (`Ya`, `Yb`) into the signed message welds
the proof to *this* PAKE session (`cpace.rs:306-310`). A different session has a
different `sid` and different ephemerals, so a captured host-proof **cannot be
relayed, spliced, or replayed** into another session. This is what forecloses
the tunneled-/compound-authentication MITM class: an attacker who proxies a
victim's handshake to the real box cannot lift the box's host-proof and present
it on a *different* session to the victim — the ephemerals won't match. A
present-only or merely-MAC-bound check could not catch this; the
transcript-bound signature does.

---

## 3. The pin compare — `known_hosts`, fail-closed, no TOFU

After the proof verifies, `key_initiator` (`client.rs:403`) looks up the pinned
key for the (normalized) address and takes one of three branches:

| Branch | Condition | Behavior |
|---|---|---|
| **Known, match** | a pin exists and `pinned == pk_b` | proceed — the box proved the *same* key the operator pinned (`client.rs:405`) |
| **Known, mismatch** | a pin exists, `pinned != pk_b` | **fail closed.** Stash the verified new key; abort with a stark old-vs-new-fingerprint warning (`client.rs:413-420`) |
| **First contact** | no pin | **fail closed.** Stash the verified key; abort printing the fingerprint to verify out-of-band (`client.rs:424-432`) |

There is **no trust-on-first-use** — first contact refuses and requires an
explicit, out-of-band-verified seed (`--get-fingerprint` on the box, compared
over a trusted channel, then `--pin-host <addr> <fingerprint>`). A mismatch
never offers a default-OK: the CLI requires `--forget-host` + reconnect; the GUI
(R-G5) requires the operator to **type** the new fingerprint to re-pin
(`flutter/lib/common/widgets/dialog.dart` `hostMismatchDialog`). Both are the
deliberate friction SSH's `@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED`
imposes.

---

## 4. Pin-store integrity

* **Never peer-seeded (R-S15).** The pin is set only by the keying path *after*
  the proof verified; `pending_host_pk` (`client.rs:1253-1255`, set at `:416`
  /`:428`) holds the verified key for the GUI to commit, and is never written
  from a peer-supplied message. A connected peer cannot inject or overwrite a
  pin.
* **Address-normalized (`host_pin::get_pinned_pk`, `host_pin.rs:97`; shared with
  R-SV5).** The lookup normalizes the address so a spelling/format variant of
  the same host cannot silently re-seed a fresh "first contact."
* **Fail-closed throughout.** Every non-match path `bail!`s; the connection does
  not proceed unpinned or mispinned.

---

## 5. The fingerprint

`pk_to_fingerprint` (`src/common.rs:1305`) renders the **full** 32-byte Ed25519
public key as hex, space-grouped every 4 chars for readability. It is the whole
key, **not a truncated digest** — so there is no fingerprint-collision or
second-preimage concern: two distinct host keys always show distinct
fingerprints. The box prints its own via `--get-fingerprint`; the operator
compares that string, byte-for-byte, against what the viewer shows.

---

## Audit pointers and test basis

| Concern | Where |
|---|---|
| Signed message / DSI | `cpace.rs:304`, `:311` |
| Sign (responder) | `cpace.rs:328`, `server.rs:396` |
| Verify (viewer) | `cpace.rs:347`, `client.rs:395` |
| Read-before-trust ordering | `client.rs:389-400` |
| Pin compare (3 branches) | `client.rs:403-433` |
| Pin store / normalize | `host_pin.rs:97`, `:113` |
| GUI seed/mismatch/manage (R-G5) | `flutter/lib/common/widgets/dialog.dart`, `…/desktop_setting_page.dart`, `…/mobile/pages/settings_page.dart` |
| Fingerprint format | `common.rs:1305` |

**Test basis.** `verify_host_identity` round-trips (valid proof, forged
signature, mutated `pk`, cross-session replay) are unit-tested in `cpace.rs`;
the `cpace_it` integration suite drives the proof over a real keyed stream and
asserts the encrypted-first-frame ordering and the fail-closed pin branches; a
verify.sh R-G5 gate asserts all three GUI surfaces (seed + mismatch + manage)
ship on both front-ends with no silent trust-on-first-use.

Note R-S17 sits in the R-V1 in-house adversarial-review scope (the host-proof
state machine and binding), distinct from R-V3's CPace-construction scope; the
in-tree adversarial tests are its day-to-day assurance basis until the external
review. Findings file against `requirements.html` §7 (R-S17) / §11.
