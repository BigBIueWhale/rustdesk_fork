# Native Codec Advisory Watch

Native-Codec-Watch-Version: 1
Requirements hash: defb467f61db2528b686af1bfc53e02759f952e514f0330289938d85fb49095c

This ledger covers the native C/C++ codec and media-adjacent libraries pulled by
`vcpkg.json`. Cargo/RustSec and Dart/OSV gates do not cover these vcpkg C/C++
libraries, so this watch is separate from `scripts/audit.sh` and
`scripts/dart-audit.sh`.

This gate is not the decoder sandbox. It only makes native-codec advisory review
explicit and tied to the pinned source set. The viewer residual from
Appendix C #2b remains open until the video, audio, clipboard, and compression
decode paths cross an out-of-process, length-bounded, killable boundary.

## Source Set

The root vcpkg manifest currently allows only these native packages:

- Package: cpu-features
- Package: libjpeg-turbo
- Package: libvpx
- Package: libyuv
- Package: oboe
- Package: opus

Forbidden native decoder expansion remains: no `ffmpeg`, no `mfx-dispatch`, no
`ffnvcodec`, and no `amd-amf` in `vcpkg.json`.

VCPKG_BASELINE: 120deac3062162151622ca4860575a33844ba10b

## Retired Libraries

Retired library: aom
Status: removed
Disposition: AV1/libaom dependency removal (closed 2026-07-11). The prior
AV1/libaom runtime quarantine remains the product behavior, but the library is no
longer linked or watched as a native package: `vcpkg.json` no longer lists `aom`,
`res/vcpkg/aom` is deleted, `libs/scrap` has no `aom` module or FFI binding,
`scrap` bindgen no longer generates `aom_ffi.rs`, and the offline Linux,
Android, Windows, Apple source-conformance, dev-check, build-Dockerfile, and
tracked build scaffolds do not install, stub, or reference `aom`. AV1 remains a
protocol/wire enum only. It is not advertised, selected, encoded, decoded,
benchmarked, or exposed in UI; inbound peer `Av1s` frames are locally
unsupported before any native decoder or recorder worker. `verify.sh` and this
ledger gate the removal so a future manifest, source, FFI, overlay,
build-Dockerfile, or build-scaffold reintroduction fails closed.

Historical rationale: CVE-2026-56208/56209/56210/56211 were recorded against
libaom while the fork still carried the dependency. Current public records
localize the reviewed issues to encoder/control surfaces, but this fork has no
design requirement for AV1, so the correct final state is deletion rather than a
permanent linked quarantine.

## Overlay-Pinned Libraries

Package: libvpx
Status: reviewed — OPEN ADVISORY (CVE-2026-1861, see below)
Disposition: source-pinned overlay; monitor upstream libvpx advisories and treat
VP8/VP9 decoder-memory-safety advisories as release-blocking until patched or
isolated by the decoder sandbox.
libvpx version: 1.15.2
libvpx SHA512: 824fe8719e4115ec359ae0642f5e1cea051d458f09eb8c24d60858cf082f66e411215e23228173ab154044bafbdfbb2d93b589bb726f55b233939b91f928aae0
Watch sources: webmproject/libvpx release/security notes, NVD/CVE, OSV, distro
security trackers.
OPEN ADVISORY (recorded 2026-06-29): CVE-2026-1861 — a VP8/VP9 *decoder* heap
buffer overflow (malformed video -> out-of-bounds heap write), fixed in Chrome
144.0.7559.132 via "enhanced bounds checking in the libvpx decoder". The exact
fixed libvpx version is not published in the CVE (Chrome bundles its own libvpx),
so the pinned 1.15.2 (a 2025 release) most likely predates the fix. This is the
Appendix C #2b viewer-side native-decode surface, which the spec ACCEPTS (bounded
operationally — connect only to peers you trust — + SHOULD-sandbox), so it is NOT
a spec-MUST blocker; but per this watch's release-blocking-until-updated policy it
is an ACTION ITEM (a deliberate build-infra change, deferred):
  (1) determine the CVE-2026-1861-fixed libvpx commit/version (webmproject/libvpx
      git history + the Chromium issue tracker referenced from the CVE);
  (2) bump the overlay pin (res/vcpkg) + re-capture the SHA512 archive into
      ./online per the R-B12(a) git-archive-capture pattern;
  (3) re-test the vcpkg `libvpx` build and re-run the reproducible release builds.
  (CVE-2025-5283, a libvpx *encoder* double-free in WebRTC's enc_init_multi, is
   N/A: the encoder processes the box's own screen, not attacker data, and the
   WebRTC path it lives in is excised — R-SV4.)

Package: libyuv
Status: reviewed
Disposition: source-pinned overlay; monitor upstream libyuv advisories and treat
image conversion/scaling memory-safety advisories as release-blocking until
patched or isolated by the decoder sandbox.
libyuv version: 1857
LIBYUV_COMMIT: 0faf8dd0e004520a61a603a4d2996d5ecc80dc3f
libyuv SHA512: be6b343ab6c62e8f2d1571fedf25f5facbf7cd7fe8e1cc4949dab7549ad15f962c91ea43bf567785e54382d7689514f6b66d61bd56b3f38ba54ef51c5fd0da9b
Watch sources: chromium libyuv changes/security notes, NVD/CVE, OSV, distro
security trackers.

Package: opus
Status: reviewed
Disposition: source-pinned overlay; monitor upstream Opus advisories and treat
audio decoder-memory-safety advisories as release-blocking until patched or
isolated by the decoder sandbox.
opus version: 1.5.2
opus SHA512: 4ffefd9c035671024f9720c5129bfe395dea04f0d6b730041c2804e89b1db6e4d19633ad1ae58855afc355034233537361e707f26dc53adac916554830038fab
Watch sources: xiph/opus release/security notes, NVD/CVE, OSV, distro security
trackers.

## Baseline-Resolved Libraries

Package: libjpeg-turbo
Status: reviewed
Disposition: vcpkg-baseline-resolved dependency; monitor libjpeg-turbo
advisories and treat image-decoder memory-safety advisories as release-blocking
until patched or isolated by the decoder sandbox.
Baseline source: VCPKG_BASELINE
Watch sources: libjpeg-turbo upstream release/security notes, NVD/CVE, OSV,
distro security trackers.

Package: oboe
Status: reviewed
Disposition: Android-only vcpkg-baseline-resolved audio I/O dependency; monitor
upstream Oboe advisories and Android platform security notes before Android
artifact release.
Baseline source: VCPKG_BASELINE
Watch sources: google/oboe release/security notes, NVD/CVE, OSV, Android
security bulletins.

Package: cpu-features
Status: reviewed
Disposition: Android-only vcpkg-baseline-resolved CPU feature detection helper;
monitor upstream android/cpu_features advisories before Android artifact release.
Baseline source: VCPKG_BASELINE
Watch sources: google/cpu_features release/security notes, NVD/CVE, OSV,
Android security bulletins.

## Release Rule

Before a release claim, refresh the watch sources above against the pinned source
set. A newly applicable native-codec advisory is a release blocker unless the
dependency pin is intentionally advanced and rebuilt, the vulnerable path is
proven unreachable in the artifact, or the decoder sandbox isolates the affected
parser strongly enough to record an explicit risk acceptance.
