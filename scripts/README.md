# Build harness (`scripts/`)

This guide describes the build and verification entrypoints for the hardened fork.
[requirements.html](../requirements.html) defines their security and build contract;
[HARDENING_STATUS.md](../HARDENING_STATUS.md) records current evidence and OPEN /
STOP-SHIP obligations.

## Execution boundary

An ordinary-user Linux x86_64 host orchestrates authenticated disposable VMs.
Build tools, Docker daemons, RustDesk programs and test executables run inside
the guests. Acquisition uses an outbound-only guest network with no host port
forwarding; verification uses a separate no-NIC guest. Builders authenticate
their guest authority before execution and have no host-Docker fallback.

The Linux VM launchers use the shared
[transient-storage helpers](./vm-transient-storage.sh). Writable overlays,
provisioning images, source archives, input/seed media and tool temporary files
belong in the bounded, identity-checked RAM workspace. Admission accounts for
guest RAM, scratch and host headroom before bulk files are created. Insufficient
resources refuse without disk scratch. The shared lock, hard file ceilings and
live monitor remain active through exact process joins and workspace retirement.

Follow [AGENTS.md](../AGENTS.md) before launching a VM. Separate media and Windows
VM paths require equivalent storage admission, limits, isolation and joined
cleanup before execution. Existing names, PID files or directory prefixes do
not authorize adopting or deleting leftovers.

## Inputs and run order

1. Authenticate inert bootstrap inputs with
   `online-fetch.sh --verifier-vm-inputs`.
2. Acquire the canonical `online/inputs` closure through `online-fetch.sh` in
   its acquisition VM. Explicit maintenance candidates remain outside that
   closure.
3. Select the required workload through `smoke-verifier-vm-authority.sh`.
   Its default mode exercises authority fixtures; product scenarios use their
   explicit workload modes.

Build recipes use the versions and artifact digests in [pins.env](./pins.env),
require the complete canonical input closure, and resolve dependencies offline.
Digest provenance is recorded alongside the pins; missing, pending or mismatched
inputs fail closed. Independent cold builds must satisfy R-B2's artifact equality
and source-manifest binding before release acceptance.

Recover the existing Android signing identity using
[ANDROID-SIGNING-RECOVERY.md](../docs/ANDROID-SIGNING-RECOVERY.md).
`gen-android-keystore.sh` creates a new identity; it cannot recover or replace
the key required by the committed certificate pin. Verify artifacts using
[RELEASE-VERIFICATION.md](../docs/RELEASE-VERIFICATION.md).

## Entrypoints

| File | Purpose |
| --- | --- |
| [pins.env](./pins.env) | Pinned versions, source identities, artifact digests and provenance. |
| [lib.sh](./lib.sh) | Shared pin loading, input validation, offline guards and repository checks. |
| [online-fetch.sh](./online-fetch.sh), [online-fetch-vm.sh](./online-fetch-vm.sh) | Bootstrap authentication and guest-only acquisition into the canonical offline inputs. |
| [smoke-verifier-vm-authority.sh](./smoke-verifier-vm-authority.sh) | Host orchestration for the authenticated no-NIC verifier VM and its focused workload modes. |
| [smoke-verifier-vm-authority-guest.sh](./smoke-verifier-vm-authority-guest.sh) | Guest authority setup, workload execution, evidence and owned cleanup. |
| [vm-transient-storage.py](./vm-transient-storage.py), [vm-transient-storage.sh](./vm-transient-storage.sh) | Shared RAM admission, storage limits, monitoring and retirement for Linux VM orchestration. |
| [vm-host-network.py](./vm-host-network.py) | Inherited host socket restrictions and listener-observation retention for offline verification. |
| [build-release.sh](./build-release.sh) | Release transaction coordinating independent builds, artifact comparison and publication. |
| [build-debian.sh](./build-debian.sh), [build-android.sh](./build-android.sh) | Debian x86_64 and Android aarch64 artifact recipes admitted inside the verifier VM. |
| [stage-debian-systemd-runtime-libs.sh](./stage-debian-systemd-runtime-libs.sh) | Runtime-library staging for the verifier's `--debian-systemd-lifecycle` workload. |
| [test-android-owner-state.sh](./test-android-owner-state.sh) | Focused production Kotlin state tests used by `--android-owner-tests`; framework and device acceptance remain separate. |
| [smoke-flutter-peer-presentation.sh](./smoke-flutter-peer-presentation.sh) | Source-bound Linux/X11 production-peer and viewer presentation scenarios inside the verifier VM. |
| [apple-conform-check.sh](./apple-conform-check.sh) | macOS/iOS source conformance and target compilation; signed artifacts and native Apple execution require their own acceptance. |
| [gen-android-keystore.sh](./gen-android-keystore.sh) | Guest-only creation of a new signing identity, subject to the signing-recovery restriction above. |
| [windows-helper-runtime.sh](./windows-helper-runtime.sh), [provision-windows-vm.sh](./provision-windows-vm.sh) | Windows helper authority and golden-VM preparation, subject to the storage restriction above. |
| [build-windows.ps1](./build-windows.ps1) | Windows x86_64 executable/MSI recipe executed inside the disposable Windows guest. |
