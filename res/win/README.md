# res/win — committed Windows-build inputs

## flutter_tools-package_config.json

flutter_tools' pre-resolved `.dart_tool/package_config.json` (97 packages), seeded into the §12.2 Windows
golden during provisioning so the build host NEVER calls pub.dev.

**Why this exists.** `dart pub get` on a *fresh* flutter_tools makes a pub.dev advisory/metadata network call
that `--offline` does **not** skip and that is **fatal** when it fails. A fresh-Win11 guest's TLS handshake to
pub.dev fails (`Handshake error in client (OS Error: ...)`), which killed every provision at the flutter_tools
resolve step. Pre-seeding the resolution makes `win-guest-setup.ps1`'s `dart pub get --offline` a **0-network
no-op** (reproduced + verified in the rdwinvm SSH VM: fresh resolve + working net → rc=0; fresh resolve + :443
blocked → rc=69; **seed present + :443 blocked → "Got dependencies!", rc=0**).

`win-guest-setup.ps1` copies this file to `C:\flutter\packages\flutter_tools\.dart_tool\package_config.json`
before the (now no-op) `dart pub get`. `online-fetch.sh` stages it into `./online/`; `provision-windows-vm.sh`
grafts it onto the TOOLCHAINS CD.

Every path inside is `C:\Users\builder\AppData\Local\Pub\Cache\...` (the staged pub cache) or `C:\flutter\...`
(the SDK) — identical in the guest (user `builder`, flutter at `C:\flutter`), so it is portable as-is.

### Regenerating (only when `FLUTTER_VERSION` 3.24.5 or flutter_tools' deps change)

On a Windows host with flutter 3.24.5 and the staged `flutter-pub-cache.tar.gz` extracted to
`%LOCALAPPDATA%\Pub\Cache`:

```
dart pub get --offline --directory C:\flutter\packages\flutter_tools   # needs net ONCE for the advisory
copy C:\flutter\packages\flutter_tools\.dart_tool\package_config.json  res\win\
```

If this file is stale vs the staged cache, the provision **Dies loudly** at the validating `dart pub get` (a
mismatched seed forces a re-resolve → the fatal pub.dev call → non-zero exit), so drift can never silently
produce a wrong build.
