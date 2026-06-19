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
build-debian.sh     # per build, offline (--network=none) — controlled-only + full viewer .deb
build-android.sh    # per build, offline — .apk (self-signed local key, R-B2)
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
| `pins.env` | Single version manifest (machine-readable §3.2). | **Done** — versions verified in-tree; SHA-256 artifact digests pending R-B12 (see below). |
| `lib.sh` | Shared helpers: source `pins.env`, fail-loud asserts (`die`/`require_cmd`/`assert_version`), SHA-256 verify (rejects the R-B12 sentinel), offline guards, repo-state asserts. | **Done** |
| `online-fetch.sh` | The one networked script → git-ignored `./online`, every artifact SHA-256-checked (R-B10). | TODO |
| `host-provision.sh` | Additive, idempotent host runtimes (docker; qemu-kvm/libvirt/swtpm/OVMF for the Win VM). Installs only what's absent; records to `.harness-state/provisioned` (outside `./online`, per R-B11's parenthetical). | **Done** |
| `cleanup.sh` | Reversible-only teardown — default removes only harness-created artifacts (prefix `rustdesk-fork-harness`); `--reverse-host` removes only recorded packages, fail-closed if the manifest is absent (R-B11). | **Done** |
| `build-debian.sh` | Debian x86_64 `.deb` (controlled-only + full viewer), in a digest-pinned `ubuntu:18.04` image. | TODO |
| `build-android.sh` | Android aarch64 `.apk`, `ubuntu:24.04` image; self-signed RSA-4096 keystore (R-B2). | TODO |
| `provision-windows-vm.sh` | Golden Win11 KVM template (§12.2). | TODO |
| `build-windows.ps1` | Windows x86_64 `.exe`/`.msi` in an ephemeral KVM guest. | TODO |

The build-script *bodies* encode upstream's exact 1.4.7 build commands (taken
verbatim from `build.py` / `flutter-build.yml`, R-B7) and are authored in a
dedicated step — faithful reproduction, no independent version choices.

## Honest gap: SHA-256 provenance (R-B12)

`pins.env` pins every **version** and git SHA-1 commit, but its **SHA-256 artifact
digests** are the sentinel `__PENDING_R_B12__`, not real values. R-B12 requires
each first pin be established by an *audited, dual-sourced bootstrap* — the
publisher's own published hash/signature cross-checked against a second path, with
per-pin provenance recorded — so a compromised mirror/CDN at first fetch cannot
poison the anchor. That bootstrap fetches the real artifacts over the network and
cannot be done offline; a fabricated digest would be worse than an honest gap.
`online-fetch.sh` MUST treat the sentinel as a hard fail-closed error.
