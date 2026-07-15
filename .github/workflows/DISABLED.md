# GitHub Actions — DISABLED (this fork builds locally)

This hardened, direct-IP-only fork does **not** use GitHub Actions for CI/CD. GitHub Actions provides
no build, verification, or release evidence. The authoritative local release transaction is
`scripts/build-release.sh`; it runs on the operator's own host and invokes the target-specific builders
from authenticated private snapshots, never in the cloud (§12 of `requirements.html`):

| Target | How (local) |
| --- | --- |
| Debian `.deb` | `scripts/build-debian.sh` (containerized, §12.1) |
| Windows       | the ephemeral KVM Windows 11 VM — `scripts/provision-windows-vm.sh` + `scripts/build-windows.ps1` (§12.2) |
| Android       | the §12 Docker flow |

The target-specific scripts are not independent release entry points. The upstream RustDesk workflows are
retained for reference but **disabled** via the
`.disabled` suffix — GitHub Actions only parses `*.yml` / `*.yaml`, so with every workflow
renamed it triggers **nothing** (no push / PR / tag / schedule, and no manual dispatch).
`dependabot.yml` is likewise disabled: this fork's dependency world is **exactly pinned**
(`Cargo.lock` + `scripts/pins.env`, R-R1/R-B12), not auto-bumped.

Disabled workflows: `bridge`, `ci`, `flutter-build`, `flutter-ci`, `flutter-tag`,
`third-party-RustDeskTempTopMostWindow`, `wf-cliprdr-ci`.

**To re-enable** a workflow, rename it back to `*.yml` — and also rename back any
`workflow_call` workflow it `uses:` (e.g. `flutter-ci` → `flutter-build` → `bridge`).
