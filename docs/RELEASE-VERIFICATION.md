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
2. Put `SHA256SUMS` and exactly the four named artifacts in one private directory. Reject symlinks,
   extra files, alternate names, and partial sets.
3. Compare the manifest itself with the independently received digest:

   ```sh
   sha256sum SHA256SUMS
   ```

4. Read the five manifest header lines. Reject the set unless `fork-version` and the full `commit`
   exactly match the independently received values and `reproducibility` is
   `independent-snapshots-a-equals-b`.
5. Verify every artifact from that directory:

   ```sh
   sha256sum --check --strict SHA256SUMS
   ```

6. Install only after every comparison succeeds. A mismatch, missing independent value, truncated
   commit, unexpected filename, or unverifiable manifest is terminal; there is no unsigned override.

The independent channel may be an in-person exchange, an already-authenticated administrative
channel, or a reproducible clean build from the independently identified commit. A GitHub release
page and a checksum downloaded from that same page are one channel, not two.

For Android, also compare the APK signer certificate SHA-256 reported by
`apksigner verify --verbose --print-certs rustdesk-arm64.apk` with the independently authenticated
`ANDROID_SIGNING_CERT_SHA256` value from the identified source commit. The APK signature is Android's
installation/update identity; the independently authenticated artifact hash remains the release
content trust anchor.
