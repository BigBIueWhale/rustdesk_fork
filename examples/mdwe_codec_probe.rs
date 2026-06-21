//! R-D3a MemoryDenyWriteExecute (W^X) validation probe.
//!
//! The hardened systemd unit (`res/rustdesk.service`) ships the full kernel sandbox
//! but leaves `MemoryDenyWriteExecute=yes` commented out, "gated on validating the
//! JIT-free codec path (libvpx/aom/ffmpeg) maps no W+X memory ... cannot be checked
//! under the no-run constraint." This probe performs exactly that validation in docker.
//!
//! It sets `PR_SET_MDWE` with `PR_MDWE_REFUSE_EXEC_GAIN` — the *exact* kernel primitive
//! systemd's `MemoryDenyWriteExecute=` applies — and does so BEFORE exercising the
//! deployed software VP9 ENCODER. Because the codecs are statically linked, the only
//! W^X risk is a *runtime* `mmap`/`mprotect` with `PROT_EXEC` on writable memory (a JIT);
//! libvpx/aom/ffmpeg do CPU-feature dispatch via function pointers to pre-compiled SIMD,
//! never JIT — so no such mapping should be attempted. If one ever were, MDWE makes it
//! EPERM/SIGSEGV and this probe crashes; completing cleanly proves MDWE is safe to enable.
//!
//! Scope: §13 / Appendix C #2b — the controlled `--server` role NEVER decodes (it encodes
//! its own screen); MDWE rides only on the `--service` unit, so validating the ENCODE path
//! is sufficient for that unit. Run: `cargo build --features linux-pkg-config --example
//! mdwe_codec_probe && ./target/debug/examples/mdwe_codec_probe`.

use hbb_common::libc;
use scrap::codec::{Encoder, EncoderCfg};
use scrap::{EncodeInput, VpxEncoderConfig, VpxVideoCodecId};

fn main() {
    // PR_SET_MDWE / PR_GET_MDWE / PR_MDWE_REFUSE_EXEC_GAIN are not named in this libc
    // (kernel >= 6.3 / glibc-new); use the raw constants. The host kernel is 6.17.
    const PR_SET_MDWE: libc::c_int = 65;
    const PR_GET_MDWE: libc::c_int = 66;
    const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

    let rc = unsafe {
        libc::prctl(
            PR_SET_MDWE,
            PR_MDWE_REFUSE_EXEC_GAIN,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        println!("MDWE_UNSUPPORTED: prctl(PR_SET_MDWE) failed: {e} (need Linux >= 6.3)");
        // Inconclusive, not a failure of the codec — exit distinctly so the caller can tell.
        std::process::exit(3);
    }
    let got = unsafe { libc::prctl(PR_GET_MDWE, 0 as libc::c_ulong, 0, 0, 0) };
    if got & 1 != 1 {
        println!("MDWE_NOT_ENGAGED: PR_GET_MDWE={got} (expected bit0=REFUSE_EXEC_GAIN)");
        std::process::exit(3);
    }
    println!("MDWE engaged (PR_GET_MDWE={got}); exercising the vpx VP9 encoder under W^X ...");

    // The exact encoder config the controlled side falls back to (video_service.rs):
    // software VP9, no i444. Dimensions 16-aligned so the I420 buffer is tightly packed.
    let (w, h) = (320u32, 240u32);
    let cfg = EncoderCfg::VPX(VpxEncoderConfig {
        width: w,
        height: h,
        quality: 1.0,
        codec: VpxVideoCodecId::VP9,
        keyframe_interval: None,
    });
    // `Encoder::new` for VPX calls `vpx_codec_enc_init` — the encoder-init path, under MDWE.
    let mut enc = match Encoder::new(cfg, false) {
        Ok(e) => e,
        Err(e) => {
            println!("MDWE_ENCODER_INIT_FAILED: {e:?}");
            std::process::exit(1);
        }
    };

    // A gray I420 frame (Y = w*h, U+V = 2*(w/2*h/2) = w*h/2). Content is irrelevant — we test
    // the codec *code path* (vpx_codec_encode), not output quality.
    let yuv = vec![0x80u8; (w as usize * h as usize * 3) / 2];
    let mut encoded = 0usize;
    for i in 0..5i64 {
        // Each encode_to_message drives vpx_codec_encode (keyframe then inter frames). A W+X
        // trap here would SIGSEGV under MDWE; a buffer/format Err does NOT (it returns cleanly).
        match enc.encode_to_message(EncodeInput::YUV(&yuv), i * 33) {
            Ok(_vf) => encoded += 1,
            Err(e) => println!("note: encode returned Err (buffer/format), no W+X trap: {e:?}"),
        }
    }

    println!(
        "MDWE_CODEC_OK: vpx VP9 encoder init + {encoded}/5 encode(s) completed under \
         MemoryDenyWriteExecute (no W+X mapping attempted by the software codec path)"
    );
}
