# Build harness (`scripts/`)

The checked-in, offline-by-construction build harness for the hardened fork
(requirements.html §12, R-B8–R-B12). It reproduces upstream 1.4.7's official build
for each target (R-B7) with **exactly two deltas and no others**: no code-signing,
and the build runs off GitHub-hosted runners on one Linux x86_64 box (R-B2).

## Discipline (R-B9 — "one mode, the good one")

Every script is held to the same bar as the rest of the spec:

- **Validate the environment, then abort.** Assert the *exact pinned versions*
  (not mere presence) of Rust / Flutter / NDK / vcpkg baseline / LLVM / JDK, the
  OS+arch, required system libs, and the submodule + lockfile state — *before*
  compiling a byte.
- **Fail loud; no fallbacks.** `set -euo pipefail` (PowerShell
  `$ErrorActionPreference = 'Stop'`). No "install latest if missing", no "retry
  another way", no silent default. A single mode of operation.
- **Pin from one manifest.** Every version comes from [`pins.env`](./pins.env);
  nothing resolves "latest" or a moving channel (R-B5a, R-R1).
- **Self-verifying + idempotent.** Re-running is safe; on success a script
  verifies the artifact (exists, right type, matches its recorded SHA-256, R-B2)
  and never reports success it has not proven.

## Run order (R-B10)

```
host-provision.sh   # once  — additive host runtimes only (R-B11)
online-fetch.sh     # once, or on a pins.env change — the ONLY networked step (R-B10)
build-debian.sh     # per build, offline (--network=none) — the one x86_64 .deb
build-android.sh    # per build, offline — app + androidTest .apk pair (self-signed local key, R-B2)
provision-windows-vm.sh + build-windows.ps1   # KVM Win11 guest (§12.2) — .exe/.msi
cleanup.sh          # reversible-only teardown (R-B11)
```

Build environments are **ephemeral instances of an immutable, pinned template**
(digest-pinned Docker image / golden VM image): spin up a throwaway instance, run
the validated flow, copy out the artifact + its SHA-256, destroy it. No state
carries between builds (§12.1) — that is what makes "one mode, no drift"
structural, not aspirational.

## Files

| File | Role | Status |
|---|---|---|
| `pins.env` | Single version manifest (machine-readable §3.2). | **Done** — versions and consumed artifact digests are pinned with R-B12 provenance; any future sentinel fails closed. |
| `lib.sh` | Shared helpers: source `pins.env`, fail-loud asserts (`die`/`require_cmd`/`assert_version`), SHA-256 verify (rejects the R-B12 sentinel), offline guards, repo-state asserts. | **Done** |
| `online-fetch.sh` | The one networked script → git-ignored `./online`, every artifact SHA-256-checked (R-B10): `cargo vendor --locked`, the toolchains/SDKs/vcpkg/FRB, digest-pinned base images. Idempotent; aborts on the R-B12 sentinel. | **Done** |
| `host-provision.sh` | Additive, idempotent host runtimes (docker pre-existing; qemu-system-x86 plus session-libvirt client/driver pieces, swtpm, and OVMF for the Win VM). It refuses system libvirt default networking, audits for virbr0/dnsmasq/IP-forwarding, installs only what's absent, and records to `.harness-state/provisioned` (outside `./online`, per R-B11's parenthetical). | **Done** |
| `cleanup.sh` | Reversible-only teardown — default removes only harness-created artifacts (prefix `rustdesk-fork-harness`); `--build-host-network` manifest-gates old harness-created system-libvirt default-network teardown; `--reverse-host` removes only recorded packages, fail-closed if the manifest is absent (R-B11/R-B11a). | **Done** |
| `build-debian.sh` | Debian x86_64 `.deb` in a digest-pinned `ubuntu:18.04` image, `--network=none`, wrapping `build.py --flutter --unix-file-copy-paste` (software codec, R-R2b). Env-validates, vendored-offline, SHA-256 + double-build determinism (R-B2). One binary — viewer + `--server` by argv. | **Done** |
| `build-android.sh` | Android aarch64 app `.apk` plus matching isolated-service `androidTest` smoke `.apk` in digest-pinned `ubuntu:24.04`, offline: cargo-ndk (ndk_arm64.sh, features flutter — software codec) + `flutter build apk` + `:app:assembleReleaseAndroidTest`, then apksigner v2 with the stable RSA-4096 local key (password via file, R-B2). | **Done** |
| `provision-windows-vm.sh` | Golden Win11 KVM template (R-B8/§12.2): swtpm vTPM 2.0 + OVMF UEFI, unattended install to the pinned toolchain, evergreen ISO/VS-BuildTools SHA-pinned offline layout (R-B12c). Per-build = CoW overlay. | **Done** |
| `build-windows.ps1` | Windows x86_64 `.exe`/`.msi` inside the KVM guest (PowerShell, $ErrorActionPreference=Stop): asserts pinned versions, vendored-offline, wraps `build.py --flutter` (software codec, R-R2b) + WiX v4 MSI, unsigned + SHA-256 (R-B2). | **Done** |

The build-script *bodies* encode upstream's exact 1.4.7 build commands (taken
verbatim from `build.py` / `flutter-build.yml`, R-B7) and are authored in a
dedicated step — faithful reproduction, no independent version choices.

## Pin Provenance (R-B12)

`pins.env` pins every **version**, git SHA-1 commit, and consumed `./online`
artifact digest. Each SHA-256/SHA512 entry records its provenance inline: either a
publisher manifest/signature cross-check plus an independent byte computation, or
an explicitly documented captured-layout/captured-distfile procedure where the
upstream input is evergreen or byte-unstable.

The `__PENDING_R_B12__` sentinel remains defined only as a fail-closed guard for
future/operator-only entries. `online-fetch.sh` refuses to fetch any artifact whose
digest is still the sentinel, before it touches the network.
