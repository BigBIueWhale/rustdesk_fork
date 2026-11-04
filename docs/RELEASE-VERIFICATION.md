# Release Artifact Verification

RustDesk fork artifacts are authenticated by the exact `dist/SHA256SUMS` manifest produced by
`scripts/build-release.sh`. Downloading that manifest beside the artifacts is not authentication:
the expected manifest SHA-256, full source commit, and fork version must arrive through a channel
independent of the artifact host, or be reproduced from a trusted clean build of that commit.

## Required Verification

1. Obtain these three values over the operator's pre-established authenticated channel:
   - the full 40-hex source commit;
   - the fork version;
   - the SHA-256 of the complete `SHA256SUMS` file.
2. Put these five regular files in one private directory: `SHA256SUMS`,
   `rustdesk-x86_64.deb`, `rustdesk-arm64.apk`, `rustdesk-setup.exe`, and `rustdesk.msi`.
   Reject symlinks, extra files, alternate names, and partial sets. Keep this directory
   private and the verified files unchanged through installation.
3. Compare the manifest itself with the independently received digest:

   ```sh
   sha256sum SHA256SUMS
   ```

4. Require exactly nine newline-terminated manifest lines in the following order.
   Angle-bracketed fields below stand for actual values, not literal placeholder text:

   ```text
   # rustdesk-fork release manifest v1
   # fork-version: <fork version>
   # commit: <full 40-hex source commit>
   # source-date-epoch: <pinned epoch>
   # reproducibility: independent-snapshots-a-equals-b
   <64 lowercase hex digits>  rustdesk-x86_64.deb
   <64 lowercase hex digits>  rustdesk-arm64.apk
   <64 lowercase hex digits>  rustdesk-setup.exe
   <64 lowercase hex digits>  rustdesk.msi
   ```

   The fork version and full commit must exactly match the independently received values.
   The epoch must equal `SOURCE_DATE_EPOCH_PIN` in `scripts/pins.env` from that identified
   source commit. Each checksum line has exactly two spaces between its digest and basename.
   Reject duplicate, missing, reordered or additional entries and any other header format.
   Preserve the original manifest bytes; editing them invalidates its authenticated digest.
5. Verify every artifact from that directory:

   ```sh
   sha256sum --check --strict SHA256SUMS
   ```

   Require successful exit and an `OK` result for each of the four named artifacts.
   GNU checksum verification checks listed file contents; `--strict` also rejects malformed
   checksum lines. It does not enforce this release's names, complete inventory or metadata,
   so the directory and manifest comparisons above are required.

6. Verify the Android APK before installation, using the Android SDK's `apksigner`:

   ```sh
   apksigner verify -Werr --verbose --print-certs rustdesk-arm64.apk
   ```

   Require successful exit and the signature-scheme results enforced by the release builder:
   v1 `false`, v2 `true`, and v3 `true`. Compare the signer certificate SHA-256 digest with
   the independently authenticated `ANDROID_SIGNING_CERT_SHA256` value in `scripts/pins.env`
   from the identified source commit, comparing hex digits without case or colon differences.
   A successful signature check alone does not establish the expected signer identity.
7. Install only after every comparison and verification command succeeds. A mismatch, missing
   independent value, truncated commit, unexpected filename, or unverifiable manifest or APK
   is terminal; there is no verification bypass.

The independent channel may be an in-person exchange, an already-authenticated administrative
channel, or a reproducible clean build from the independently identified commit. A GitHub release
page and a checksum downloaded from that same page are one channel, not two.

The APK signature supplies Android's installation/update identity; the independently
authenticated artifact hash remains the release content trust anchor. These checks establish
artifact identity and integrity. Native functionality, installed-service authorization and the
other release acceptance requirements remain tracked in [HARDENING_STATUS.md](../HARDENING_STATUS.md).

Tool references: [GNU checksum options](https://www.gnu.org/software/coreutils/manual/coreutils.html#cksum-common-options),
[Android apksigner](https://developer.android.com/tools/apksigner).
