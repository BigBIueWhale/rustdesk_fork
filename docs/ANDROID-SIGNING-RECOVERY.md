# Android Signing-Key Recovery

The sideloaded Android package is signed directly with the one self-managed app-signing key pinned
by `ANDROID_SIGNING_CERT_SHA256`. There is no Play App Signing recovery service and no build-script
override for a missing or mismatched key. Android documents that a self-managed signing key is
required for future updates and cannot be regenerated; a different certificate normally requires a
different package name and a new installation.

## Custody

- Keep the keystore and password file outside the repository and build images. Store at least two
  independently encrypted offline backups in separate physical locations, with access recorded.
- Keep the password material separate from the keystore except on the isolated signing host during a
  release build. The build accepts only current-UID, non-symlink mode-0600 files beneath current-UID
  mode-0700 directories.
- Before each release, verify that the keystore certificate equals the committed
  `ANDROID_SIGNING_CERT_SHA256`. Test backup readability on an offline host without exporting or
  replacing the private key.

## Loss Without Compromise

1. Stop Android releases.
2. Restore only a previously verified offline copy whose certificate equals the committed pin.
3. If no verified copy exists, retire the existing Android package identity. A newly generated key
   is not a recovery of that identity and must not be accepted through a pin bypass.

## Suspected Or Confirmed Compromise

1. Stop builds and distribution immediately. Preserve incident evidence and identify the last known
   trusted release, manifest, source commit, and certificate fingerprint.
2. Mark the old certificate and every subsequently signed APK untrusted through the authenticated
   operator channel. Do not publish another APK under the old package identity.
3. Create a new package identity and a new signing key on a rebuilt offline signing host. Commit the
   new package name and certificate pin as a reviewed security migration, bump the fork release, and
   run the complete clean double build. No old-key, old-package, or pin-override fallback is allowed.
4. Remove the old package from each device, accepting deletion of its application data, then install
   the independently verified new package. Verify both the artifact manifest and new signer
   fingerprint using `docs/RELEASE-VERIFICATION.md`.

APK Signature Scheme v3 can encode a key lineage, but the current release policy does not create or
test one, older Android versions have different rotation behavior, and an incident is not the time to
invent a lineage using a suspect key. Rotation is therefore unavailable unless a future normative
change designs, builds, and compatibility-tests it before any compromise.

References: [Android app signing](https://developer.android.com/studio/publish/app-signing),
[APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3).
