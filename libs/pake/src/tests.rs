//! KAT + adversarial test harness (R-A10, R-V2/R-V3). Gates the construction on
//! the CFRG draft-21 published ristretto255 vector and on the fork anchors A & B
//! pinned byte-for-byte in `requirements.html` §10.4. Anchor B is additionally
//! driven through the full R-P14a state machine, so the machine — not only the
//! free functions — is vector-checked.

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn a32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}
fn a16(s: &str) -> [u8; 16] {
    let v = unhex(s);
    let mut a = [0u8; 16];
    a.copy_from_slice(&v);
    a
}
/// CPace test vectors encode scalars as a 32-byte little-endian canonical value.
fn scalar_le(s: &str) -> Scalar {
    Scalar::from_bytes_mod_order(a32(s))
}
/// Extract the error from a `Result` whose `Ok` type is not `Debug` (the
/// state-machine success types and the secret-bearing `DirectionalKeys`
/// deliberately do not derive `Debug`, so `unwrap_err` is unavailable).
fn expect_err<T>(r: Result<T, PakeError>) -> PakeError {
    match r {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(e) => e,
    }
}

// The draft-21 published ristretto255 scalars (identical across testvectors.json
// and testvectors.md; the codename in the JSON is `G_Coffee25519`).
const YA_DRAFT: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
const YB_DRAFT: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";
// The draft vector's 16-byte sid.
const SID_DRAFT: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
const PRS: &str = "Password"; // OpaqueString("Password") — ASCII, NFC-invariant.

/// Reproduce the canonical published vector (R-V2): the generator and the
/// symmetric-mode ISK, byte-for-byte. CI here is the draft's own
/// `lv_cat("A_initiator","B_responder")` and AD = "ADa"/"ADb" (the published
/// values), *not* the fork runtime values — this is the upstream cross-check.
#[test]
fn published_ristretto255_vector() {
    let ci = lv_cat(&[b"A_initiator", b"B_responder"]);
    let sid = unhex(SID_DRAFT);
    let g = derive_generator(PRS.as_bytes(), &ci, &sid);
    assert_eq!(
        hex(&g.compress().to_bytes()),
        "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
        "published generator g"
    );

    let ya = scalar_le(YA_DRAFT);
    let yb = scalar_le(YB_DRAFT);
    let ya_pt = (ya * g).compress().to_bytes();
    let yb_pt = (yb * g).compress().to_bytes();
    let k = (ya * decompress(&yb_pt).unwrap()).compress().to_bytes();
    let isk = compute_isk(&ya_pt, b"ADa", &yb_pt, b"ADb", &sid, &k);
    assert_eq!(
        hex(&isk),
        "544199d71f62f8d9a1fee55727e24fe4a45844593c2b6013c4fa3969d0e5debb\
         2244675c0b43397cbb68d342b01fc0f98fc961469a25134de9f0f813c1a57476",
        "published ISK_SY"
    );
}

struct Anchor {
    sid: &'static str,
    ci: &'static str,
    g: &'static str,
    ya: &'static str,
    yb: &'static str,
    k: &'static str,
    isk: &'static str,
    k_c2s: &'static str,
    k_s2c: &'static str,
    mac_key: &'static str,
    ta: &'static str,
    tb: &'static str,
}

const ANCHOR_A: Anchor = Anchor {
    sid: SID_DRAFT, // 16-byte draft sid, reused so anchor A reproduces from the vector
    ci: "26727573746465736b2d666f726b2f43504143452d52495354523235352d5348413531322f763102527e",
    g: "d2ab818fcab24168d41f8320c9183772c8c2692dcaacb477d55ef915beb00040",
    ya: "78dbae529bf637a0586ba0c6670f086761546f164ff2f91b2729dbf2eff8b127",
    yb: "96658248c744243356b34d4245ca1f1b264b6838d6bf94708efe7af3c2667d38",
    k: "e63952c64358d604c4ed485285672e32739fc5b736ee7b215906b76f83787d37",
    isk: "0421d692336d1184bb5a46a350c103d4cfd23f67c8b613536f5993d29da8488e\
          2c467f672d8692a35faf3fc852eb60bace6b4804717338969660059a35ced06c",
    k_c2s: "0529cc72fd60eef4860c93e473c709a90293f6e9e89e340481d1fcbc14421b85",
    k_s2c: "abb9739b8094006863991bfd8d9ac46013b93e0f5021858f24ef94051599e366",
    mac_key: "cd4f777e963300209fab04538096fb3b4f15aa7be1663098ad685fd632de4551\
              b6ff06cfce250d8ae206e7d1a21899467751f1fb6f4fa5d611dcd08a4740a36b",
    ta: "e5661d8a304f294afdb8a4e23a999044fe4ecd584da01fbe300a4c728a52e757\
         fc929b923ebe010af34efc112fffc82775f8c34339d177b8e5b1c66586d9f44f",
    tb: "709ad1aa449cbfa89b760e931d337fa9e460310c3306daee0d790fe3157f07d1\
         755bea5cd237509044ca18ab5f168e7a85a07a2728a8a009a500c1929b72d594",
};

const ANCHOR_B: Anchor = Anchor {
    sid: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    ci: "26727573746465736b2d666f726b2f43504143452d52495354523235352d5348413531322f763102527e",
    g: "206bc585b022ef280748542efbb037e168832a10c8442903afa3896176acb529",
    ya: "28b0c1c4d3414d5099bde6be0ea6919fae21f727d55a529c933e3e1355276261",
    yb: "a60e28003226199aa9f0a2d66b54463bf2c9ab7a6bd55b8d61d583ca65acc91b",
    k: "74a92fb8f03e105b5e6308e3427b0db09b67efa4fc89e9dbe6f8c0d677639330",
    isk: "d34d998221ac1764b2e3c9262ed1eff005e8023a950124fe7c7f8725d32af3cf\
          e21feaaba6ff5f12208fad5bf508b50cc5ad5c40f1220097fffdb14874be8541",
    k_c2s: "24ab1b177c7d8c7c967f8bf3a8f5db6e1d14b29c127152c9a9ac26aca53fad77",
    k_s2c: "1fb5ac56d1012486125217d136cb025feea0b5afac9b845d60201793a5793c54",
    mac_key: "3e2515aadabb8cdb6e3f637d056ce25dc9dd891effab709bde74a5d83cc7417a\
              c4881771d2bee6668d559bbc239c89eb7857e6fe153b9b22eb7f5d2aafb00812",
    ta: "1c7a7069e9c72e477be518bc419d79c73b08d89e29d7bf87ddc9528887f5f442\
         16ebd4ee5cc35ffbe5b18469a8d3577e1032aea31c79a33d0857a3abea1a4767",
    tb: "f1a57e115ca01fdc9e1127076c2ee736b28ca781f76fcfa3819beb19341336f4\
         4286077c15fca56823398ef5eeee3a55dca0e3090d9832a4d072910aff22cbd3",
};

// Strip the line-continuation whitespace the long hex literals use for layout.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Construction-level KAT: recompute every §10.4 intermediate from the pinned
/// scalars and assert byte-equality with the anchor.
fn check_anchor_construction(an: &Anchor) {
    let sid = unhex(an.sid);
    let ci = unhex(an.ci);
    assert_eq!(hex(&channel_identifier(CI_PORT)), an.ci, "CI (port 21118)");

    let g = derive_generator(PRS.as_bytes(), &ci, &sid);
    let g_bytes = g.compress().to_bytes();
    assert_eq!(hex(&g_bytes), an.g, "generator g");

    let ya = scalar_le(YA_DRAFT);
    let yb = scalar_le(YB_DRAFT);
    let ya_pt = (ya * g).compress().to_bytes();
    let yb_pt = (yb * g).compress().to_bytes();
    assert_eq!(hex(&ya_pt), an.ya, "Ya");
    assert_eq!(hex(&yb_pt), an.yb, "Yb");

    let k_pt = ya * decompress(&yb_pt).unwrap();
    assert!(!k_pt.is_identity(), "K must not be identity");
    let k = k_pt.compress().to_bytes();
    assert_eq!(hex(&k), an.k, "K");

    let isk = compute_isk(&ya_pt, AD_INITIATOR, &yb_pt, AD_RESPONDER, &sid, &k);
    assert_eq!(hex(&isk), clean(an.isk), "ISK");

    let (k_c2s, k_s2c) = derive_session_keys(&isk);
    assert_eq!(hex(&k_c2s), an.k_c2s, "k_c2s");
    assert_eq!(hex(&k_s2c), an.k_s2c, "k_s2c");

    let mac_key = derive_mac_key(&sid, &isk);
    assert_eq!(hex(&mac_key[..]), clean(an.mac_key), "mac_key");

    let ta = compute_tag(&mac_key, &ya_pt, AD_INITIATOR);
    let tb = compute_tag(&mac_key, &yb_pt, AD_RESPONDER);
    assert_eq!(hex(&ta), clean(an.ta), "Ta");
    assert_eq!(hex(&tb), clean(an.tb), "Tb");

    // Constant-time verifier accepts the right tag, rejects a flipped bit.
    assert!(verify_tag(&mac_key, &ya_pt, AD_INITIATOR, &ta));
    let mut bad = ta;
    bad[0] ^= 1;
    assert!(!verify_tag(&mac_key, &ya_pt, AD_INITIATOR, &bad));
}

#[test]
fn anchor_a_construction() {
    check_anchor_construction(&ANCHOR_A);
}

#[test]
fn anchor_b_construction() {
    check_anchor_construction(&ANCHOR_B);
}

/// Anchor B (32-byte production sid) driven end-to-end through the R-P14a state
/// machine with the pinned scalars — pins the emitted wire bytes (Ya, Yb, Ta,
/// Tb) and the mirrored directional keys.
#[test]
fn anchor_b_state_machine() {
    let an = &ANCHOR_B;
    let sid_a = a16(&an.sid[..32]);
    let sid_b = a16(&an.sid[32..]);
    let ya = scalar_le(YA_DRAFT);
    let yb = scalar_le(YB_DRAFT);

    let (init, s1) = Initiator::from_parts(PRS, CI_PORT, sid_a).unwrap();
    assert_eq!(s1.ada, AD_INITIATOR);
    assert_eq!(s1.sid_a, sid_a);

    let resp = Responder::new(PRS, CI_PORT).unwrap();
    let (resp2, s2) = resp.recv_step1_with(&s1, sid_b, yb).unwrap();
    assert_eq!(hex(&s2.yb), an.yb, "Step2.Yb");
    assert_eq!(s2.adb, AD_RESPONDER);

    let (init2, s3) = init.recv_step2_with(&s2, ya).unwrap();
    assert_eq!(hex(&s3.ya), an.ya, "Step3.Ya");
    assert_eq!(hex(&s3.ta), clean(an.ta), "Step3.Ta");

    let (keys_resp, s4) = resp2.recv_step3(&s3).unwrap();
    assert_eq!(hex(&s4.tb), clean(an.tb), "Step4.Tb");

    let keys_init = init2.recv_step4(&s4).unwrap();

    // Role→direction binding (R-P2): viewer seals with k_c2s, controlled with k_s2c.
    assert_eq!(hex(&keys_init.send), an.k_c2s, "viewer send = k_c2s");
    assert_eq!(hex(&keys_init.recv), an.k_s2c, "viewer recv = k_s2c");
    assert_eq!(hex(&keys_resp.send), an.k_s2c, "controlled send = k_s2c");
    assert_eq!(hex(&keys_resp.recv), an.k_c2s, "controlled recv = k_c2s");
    // Mirrored slots: each side's send key is the other's recv key.
    assert_eq!(hex(&keys_init.send), hex(&keys_resp.recv));
    assert_eq!(hex(&keys_init.recv), hex(&keys_resp.send));
}

/// Full random round-trip: a matching password authenticates both sides and
/// yields mirrored keys (the R-P3 self-consistency KAT, R-A10).
#[test]
fn round_trip_random_matching_password() {
    let (init, s1) = Initiator::new("hunter2-correct-horse", CI_PORT).unwrap();
    let resp = Responder::new("hunter2-correct-horse", CI_PORT).unwrap();
    let (resp2, s2) = resp.recv_step1(&s1).unwrap();
    let (init2, s3) = init.recv_step2(&s2).unwrap();
    let (keys_resp, s4) = resp2.recv_step3(&s3).unwrap();
    let keys_init = init2.recv_step4(&s4).unwrap();
    assert_eq!(hex(&keys_init.send), hex(&keys_resp.recv));
    assert_eq!(hex(&keys_init.recv), hex(&keys_resp.send));
    // Two independent runs use fresh sids/scalars ⇒ different keys (R-P8).
    let (i2, t1) = Initiator::new("hunter2-correct-horse", CI_PORT).unwrap();
    let r2 = Responder::new("hunter2-correct-horse", CI_PORT).unwrap();
    let (r2b, t2) = r2.recv_step1(&t1).unwrap();
    let (i2b, t3) = i2.recv_step2(&t2).unwrap();
    let (kr2, t4) = r2b.recv_step3(&t3).unwrap();
    let ki2 = i2b.recv_step4(&t4).unwrap();
    assert_ne!(hex(&ki2.send), hex(&keys_init.send), "fresh sid/scalar ⇒ fresh key");
    let _ = (kr2,);
}

/// A wrong password fails at the responder's R-P3 check and is the sole
/// limiter-feeding event (R-P14c).
#[test]
fn wrong_password_is_confirmation_failure() {
    let (init, s1) = Initiator::new("right-password", CI_PORT).unwrap();
    let resp = Responder::new("WRONG-password", CI_PORT).unwrap();
    let (resp2, s2) = resp.recv_step1(&s1).unwrap();
    let (_init2, s3) = init.recv_step2(&s2).unwrap();
    let err = expect_err(resp2.recv_step3(&s3));
    assert_eq!(err, PakeError::Confirmation);
    assert!(err.is_password_guess(), "only confirmation feeds the limiter");
}

/// Every non-confirmation abort must NOT feed the limiter (R-P14c).
#[test]
fn non_confirmation_aborts_do_not_feed_limiter() {
    for e in [
        PakeError::Decode,
        PakeError::Identity,
        PakeError::AdMismatch,
        PakeError::EmptyPassword,
        PakeError::Rng,
    ] {
        assert!(!e.is_password_guess(), "{:?} must not feed limiter", e);
    }
    assert!(PakeError::Confirmation.is_password_guess());
}

/// Responder rejects a Step1 whose ADa is not the pinned initiator role (R-P5).
#[test]
fn responder_rejects_wrong_ada() {
    let (_init, mut s1) = Initiator::new("pw", CI_PORT).unwrap();
    s1.ada = b"server".to_vec(); // a reflected responder role
    let resp = Responder::new("pw", CI_PORT).unwrap();
    assert_eq!(expect_err(resp.recv_step1(&s1)), PakeError::AdMismatch);
}

/// Initiator rejects a Step2 whose ADb is not the pinned responder role (R-P5).
#[test]
fn initiator_rejects_wrong_adb() {
    let (init, s1) = Initiator::new("pw", CI_PORT).unwrap();
    let resp = Responder::new("pw", CI_PORT).unwrap();
    let (_resp2, mut s2) = resp.recv_step1(&s1).unwrap();
    s2.adb = b"viewer".to_vec();
    assert_eq!(expect_err(init.recv_step2(&s2)), PakeError::AdMismatch);
}

/// The all-zeros encoding decodes to the identity; the post-multiply
/// `is_identity` check (R-P7), not decode alone, must catch it.
#[test]
fn identity_element_aborts() {
    let (init, s1) = Initiator::new("pw", CI_PORT).unwrap();
    let resp = Responder::new("pw", CI_PORT).unwrap();
    let (_resp2, mut s2) = resp.recv_step1(&s1).unwrap();
    // ristretto255 all-zeros decodes successfully to the identity point.
    assert!(decompress(&[0u8; 32]).unwrap().is_identity());
    s2.yb = [0u8; 32];
    assert_eq!(expect_err(init.recv_step2(&s2)), PakeError::Identity);
}

/// A non-canonical / non-decodable element aborts with Decode (R-P7).
#[test]
fn bad_element_aborts_decode() {
    let (init, s1) = Initiator::new("pw", CI_PORT).unwrap();
    let resp = Responder::new("pw", CI_PORT).unwrap();
    let (_resp2, mut s2) = resp.recv_step1(&s1).unwrap();
    s2.yb = [0xff; 32]; // not a valid ristretto255 encoding
    assert_eq!(expect_err(init.recv_step2(&s2)), PakeError::Decode);
}

/// Empty PRS after NFC is rejected (R-P1/R-S9). CPace has no empty-PRS guard.
#[test]
fn empty_password_rejected() {
    assert_eq!(expect_err(Initiator::new("", CI_PORT)), PakeError::EmptyPassword);
    assert_eq!(expect_err(Responder::new("", CI_PORT)), PakeError::EmptyPassword);
}

/// Non-ASCII PRS: NFC normalization makes a composed and a decomposed spelling
/// of the same password agree, so the handshake authenticates across them — and
/// exercises the non-ASCII path R-A10 requires.
#[test]
fn nfc_non_ascii_password() {
    // U+00E9 (é, composed) vs U+0065 U+0301 (e + combining acute, decomposed).
    let composed = "café-p\u{00e9}";
    let decomposed = "cafe\u{0301}-pe\u{0301}";
    assert_ne!(composed, decomposed, "distinct code points pre-normalization");

    let (init, s1) = Initiator::new(composed, CI_PORT).unwrap();
    let resp = Responder::new(decomposed, CI_PORT).unwrap();
    let (resp2, s2) = resp.recv_step1(&s1).unwrap();
    let (init2, s3) = init.recv_step2(&s2).unwrap();
    let (keys_resp, s4) = resp2.recv_step3(&s3).unwrap();
    let keys_init = init2.recv_step4(&s4).unwrap();
    assert_eq!(hex(&keys_init.send), hex(&keys_resp.recv), "NFC makes them agree");
}

/// The full-handshake replay of a recorded sid/Ya is harmless: the responder's
/// fresh sid_b/yb diverge the ISK, so it aborts at R-P3 with no replay state
/// (R-P14c).
#[test]
fn replayed_initiator_flow_aborts() {
    let (init, s1) = Initiator::new("pw", CI_PORT).unwrap();
    let resp1 = Responder::new("pw", CI_PORT).unwrap();
    let (_r1, s2a) = resp1.recv_step1(&s1).unwrap();
    let (_i2, s3) = init.recv_step2(&s2a).unwrap();
    // Replay the captured Step3 against a *fresh* responder instance.
    let resp2 = Responder::new("pw", CI_PORT).unwrap();
    let (resp2b, _s2b) = resp2.recv_step1(&s1).unwrap();
    assert_eq!(expect_err(resp2b.recv_step3(&s3)), PakeError::Confirmation);
}

/// LEB128 / lv_cat encoding sanity, including the multi-byte length boundary.
#[test]
fn lv_cat_encoding() {
    assert_eq!(leb128(0), vec![0x00]);
    assert_eq!(leb128(127), vec![0x7f]);
    assert_eq!(leb128(128), vec![0x80, 0x01]);
    assert_eq!(leb128(300), vec![0xac, 0x02]);
    assert_eq!(lv_cat(&[b"abc"]), vec![0x03, b'a', b'b', b'c']);
    // The CI KAT is itself an lv_cat fixture (38-byte tag, then 02 ‖ be16(21118)).
    assert_eq!(hex(&channel_identifier(21118)), clean(ANCHOR_A.ci));
}

/// o_cat is order-independent (R-P6): swapping operands yields identical bytes.
#[test]
fn o_cat_order_independent() {
    let a = b"alpha";
    let b = b"beta-longer";
    assert_eq!(o_cat(a, b), o_cat(b, a));
    assert!(o_cat(a, b).starts_with(b"oc"));
}
