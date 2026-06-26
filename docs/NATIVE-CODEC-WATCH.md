# Native Codec Advisory Watch

Native-Codec-Watch-Version: 1
Requirements hash: d34aad84c44e8b919e72130eecb78e3f06e3f19a8d667a2219402e8225c90dc1

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

- Package: aom
- Package: cpu-features
- Package: libjpeg-turbo
- Package: libvpx
- Package: libyuv
- Package: oboe
- Package: opus

Forbidden native decoder expansion remains: no `ffmpeg`, no `mfx-dispatch`, no
`ffnvcodec`, and no `amd-amf` in `vcpkg.json`.

VCPKG_BASELINE: 120deac3062162151622ca4860575a33844ba10b

## Overlay-Pinned Libraries

Package: aom
Status: reviewed
Disposition: source-pinned overlay; monitor upstream aom advisories and treat a
decoder-memory-safety advisory as release-blocking until patched or isolated by
the decoder sandbox.
aom version: 3.12.1
AOM_COMMIT: 10aece4157eb79315da205f39e19bf6ab3ee30d0
aom SHA512: 59c3e3f3fbf649857fcba1af63593a06336377fed554f9696c1965580b95778ded76ac409b40589e1f44a94b9fea6df777b7c58760b7c3df6f8274b968b83a05
Watch sources: aomedia upstream release/security notes, NVD/CVE, OSV, distro
security trackers.

Package: libvpx
Status: reviewed
Disposition: source-pinned overlay; monitor upstream libvpx advisories and treat
VP8/VP9 decoder-memory-safety advisories as release-blocking until patched or
isolated by the decoder sandbox.
libvpx version: 1.15.2
libvpx SHA512: 824fe8719e4115ec359ae0642f5e1cea051d458f09eb8c24d60858cf082f66e411215e23228173ab154044bafbdfbb2d93b589bb726f55b233939b91f928aae0
Watch sources: webmproject/libvpx release/security notes, NVD/CVE, OSV, distro
security trackers.

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
