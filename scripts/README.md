# Build harness (`scripts/`)

The checked-in, offline-by-construction build harness for the hardened fork
(requirements.html §12, R-B8–R-B12). An ordinary-user Linux x86_64 host launches
authenticated disposable VMs; build tools and container daemons execute only
inside them. Target recipes use the pinned toolchains and require R-B2's
independent cold artifact comparisons without GitHub-hosted runners.

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

Authenticate inert bootstrap bytes with `online-fetch.sh --verifier-vm-inputs`,
then acquire the complete canonical inputs through `online-fetch.sh` in its
outbound-only VM. Build execution requires the separate no-NIC verifier VM.
`build-release.sh`, Debian/Android builders, and Windows golden/build wrappers
are admitted VM workloads; they refuse direct host invocation. The default
`smoke-verifier-vm-authority.sh` exercises authority mechanics and fixtures,
not a production release. Full release transport, canonical inputs and cold
artifact acceptance remain tracked in [HARDENING_STATUS.md](../HARDENING_STATUS.md).

Build environments are **ephemeral instances of an immutable, pinned template**
(digest-pinned Docker image / golden VM image): spin up a throwaway instance, run
the validated flow, copy out the artifact + its SHA-256, destroy it. No state
carries between builds (§12.1) — that is what makes "one mode, no drift"
structural, not aspirational.

Each creating transaction retains and retires its exact process, container,
domain UUID, filesystem and channel identities before success. Names, labels,
PID files, prefixes and package lists confer no cleanup authority. Unowned
leftovers remain unresolved; repository tooling cannot adopt them or alter
host packages, services or networking. Intentionally retained maintenance
candidates remain explicit acquisition state owned by their exact producer.

## Files

| File | Role | Status |
|---|---|---|
| `pins.env` | Single version manifest (machine-readable §3.2). | **Done** — versions and consumed artifact digests are pinned with R-B12 provenance; any future sentinel fails closed. |
| `lib.sh` | Shared helpers: source `pins.env`, fail-loud asserts (`die`/`require_cmd`/`assert_version`), SHA-256 verify (rejects the R-B12 sentinel), offline guards, repo-state asserts, and require each builder-image caller to supply its already-authenticated provenance executor. It contains no Docker endpoint, client, configuration, or ambient fallback. | **Done** |
| `online-fetch.sh` + `online-fetch-vm.sh` | The one networked acquisition entry → git-ignored `./online/inputs`, every artifact SHA-256-checked (R-B10). The sibling `./online/retired` root shares one rootless Landlock/seccomp-confined virtiofs cache-state mount so the required flagged replacements remain atomic; explicitly requested trial artifacts are isolated under `./online/candidates` and are never part of the canonical build-input closure. Systemd-image cache and bounded results use two narrow 9p exports. The bootstrap mode authenticates the pinned VM/base, guest Docker, and uninstalled virtiofsd-package bytes. Every other mode refuses root and dirty/non-master source, enters ordinary-user seccomp-sandboxed QEMU with outbound-only user networking and no host forwarding/listener, reconstructs the exact Git bundle, and gives VM-local Docker no other host filesystem authority. The focused mode executes real `RENAME_NOREPLACE`/`RENAME_EXCHANGE` operations and a non-root guest-bridge HTTPS container; it does not substitute for the complete cache transaction. | **VM source implemented; focused runtime and complete cache execution pending** |
| `build-release.sh` | Non-root release transaction admitted only inside the common no-NIC verifier VM. The parent performs no Docker/image-provenance/container operation; it passes commit-bound content IDs to independently authenticating VM children and uses the retained-descriptor helper directly for its exact current-principal workspace. The executable A/B/publication and hostile-mode cleanup fixtures pass. | **Parent authority done; full VM input/output transport and cold release open** |
| `apple-conform-check.sh` | Fixed macOS-arm64, macOS-x86_64, and iOS-arm64 source-conformance transaction admitted only as the designated nonroot principal inside the authenticated no-NIC verifier VM. Every immutable-image provenance/launch operation uses the guest-private Unix Docker channel with pre/post daemon-generation replay; there is no host-Docker fallback. The authority-only entry test touches no source/vendor/output input and is not the Apple workload. | **VM authority entry green; current full source transaction and native Apple evidence open** |
| `stage-debian-systemd-runtime-libs.sh` + `smoke-verifier-vm-authority.sh --debian-systemd-lifecycle` | The common no-NIC verifier VM verifies the exact devcheck archive, exercises one numeric-nonroot resource-bounded two-mount library-staging profile, joins VM-root Docker, then runs the final A==B `.deb` under real Debian systemd. The fast authority smoke uses the same launch function with a private fixture and truthfully reports `workload=unexecuted`; the exact artifact scenario is mandatory before release publication. | **VM profile exercised; current final artifact run open** |
| `test-android-owner-state.sh` + `smoke-verifier-vm-authority.sh --android-owner-tests` | The focused no-NIC VM loads the certified Android builder into guest-only Docker and compiles seven exact production Kotlin state classes together with standard-source-set executable tests using a VM-local read-only copy of the digest-pinned Kotlin 2.0.21 compiler closure already present in the sealed Gradle seed. The copy is required because this Kotlin compiler memory-maps classpath JARs while the authenticated virtiofs share does not support that operation; every source and copied JAR is verified before execution and the sealed authority is re-inventoried afterward. Fifteen scenarios and 305 assertions cover closed connection types, capture/input ABA, bounded FIFO retirement, status/startup generations and exhaustion, controlled/outgoing voice ownership, cross-domain teardown, and Activity invalidation in seconds. This is real production-state-machine execution, not source-string evidence; it does not exercise Android framework, Activity/service, MediaProjection, AudioRecord, packaging, or device behavior. | **Focused pure-Kotlin behavior wired; packaged native/device evidence open** |
| `smoke-flutter-peer-presentation.sh` | Exact-commit full Linux/X11 peer-presentation transaction: admitted only as the designated nonroot principal inside the authenticated no-NIC verifier VM, with every image query, container launch/inspection/log/cleanup operation routed through its fixed guest-only Docker client, private Unix socket, and root-owned read-only configuration. It constructs a minimal digest-bound AT-SPI runtime from two exact offline Debian packages without installation or maintainer scripts and proves real private D-Bus/AT-SPI activation before the expensive build. The real workload builds the release Rust core/Flutter runner offline, isolates controlled peer/viewer state on one owned `--network=none` loopback namespace, authenticates through the real prompt, correlates capture/encode/TCP/decode/Flutter-texture/X11 pixels, requires bounded focus recovery on the same socket, and joins exact teardown. It publishes no host port and proves only one Linux/X11 peer cycle—not Android/Windows/Apple, installed service, cross-version/soak, or release artifacts. | **VM-only entry wired; current full workload/input transport open** |
| `build-debian.sh` | Debian x86_64 `.deb` in the certified `ubuntu:18.04` image, admitted only inside the authenticated no-NIC verifier VM. The sole compiler operation is no-pull/network-none, numeric non-root, read-only-root, capability-free, no-new-privileges, seccomp/AppArmor confined, private-namespace and resource-bounded; it receives one private exact-commit writable source, hidden Git authority, and read-only exact online input. It validates private outputs, compares independent A/B results, retires its exact workspace, and uses descriptor-bound no-clobber publication. The fast VM test executes this production envelope against private fixtures; the certified toolchain workload and cold artifact transaction remain open. | **VM envelope done; workload/release evidence open** |
| `build-android.sh` | Android aarch64 app `.apk` in digest-pinned `ubuntu:24.04`, offline: cargo-ndk (ndk_arm64.sh, features flutter — software codec) + `flutter build apk`, then apksigner v2/v3 with the stable RSA-4096 local key (password via file, R-B2). It runs only as an admitted no-NIC verifier-VM workload; direct passes use independent coexisting exact-commit trees, each signed APK/checksum pair is privately validated and compared, and exact workspace retirement precedes descriptor-bound no-clobber publication. No `androidTest` APK is currently built or published by this path. | **VM authority source done; certified workload/release and Android instrumentation evidence open** |
| `gen-android-keystore.sh` | One-time creation of the permanent local Android signing identity. It admits only the authenticated no-NIC verifier VM (no host-Docker fallback), refuses root, alias/image overrides, existing output, and non-private/symlinked paths; uses the immutable Android builder for separately bounded non-root/networkless password generation, key generation, and inspection; passes passwords only by read-only file; and synchronizes atomic no-clobber publication from a private same-filesystem stage. Its authority self-test exits before any signing path or identity access. | **Source done; one-time run open** |
| `windows-helper-runtime.sh` | One least-authority runtime shared by Windows build, golden provision, and golden inspection. All three callers first authenticate the no-NIC verifier VM; helper provenance and launches use only its exact guest client, private Unix socket, and root-owned read-only configuration with pre/post generation proof. The runtime fixes the immutable helper image/archive/kernel, confines every operation to numeric-nonroot no-pull/network/read-only-root/capability-free/resource-bounded execution with canonical nonrecursive binds, and gives only exact-golden inspection one `/dev/kvm:rw` grant. | **VM authority and actual small-profile probe done; certified archive/KVM/Windows artifact runs open** |
| `provision-windows-vm.sh` | Verifier-VM-admitted Windows golden preparation with guest-local session libvirt, UEFI and captured pinned installers. Per-build guests use fresh CoW overlays. Provisioning's remaining user-mode NIC and unpinned Brotli acquisition must be reconciled with the offline contract. | **Offline provisioning and native acceptance open** |
| `build-windows.ps1` | Windows x86_64 `.exe`/`.msi` inside the KVM guest (PowerShell, $ErrorActionPreference=Stop): asserts pinned versions, vendored-offline, wraps `build.py --flutter` (software codec, R-R2b) + WiX v4 MSI, unsigned + SHA-256 (R-B2). | **Done** |

## Pin Provenance (R-B12)

`pins.env` pins every **version**, git SHA-1 commit, and consumed `./online/inputs`
artifact digest. Each SHA-256/SHA512 entry records its provenance inline: either a
publisher manifest/signature cross-check plus an independent byte computation, or
an explicitly documented captured-layout/captured-distfile procedure where the
upstream input is evergreen or byte-unstable.

The `__PENDING_R_B12__` sentinel remains defined only as a fail-closed guard for
future/operator-only entries. `online-fetch.sh` refuses to fetch any artifact whose
digest is still the sentinel, before it touches the network.
