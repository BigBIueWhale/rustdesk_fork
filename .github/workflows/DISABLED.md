# GitHub-hosted automation — DISABLED (this fork builds locally)

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
retained for reference but **disabled twice**. The `.disabled` suffix keeps GitHub Actions from loading them,
and every retained file schema-demotes its top-level `on` and `jobs` keys to `historical_on` and
`historical_jobs`. Renaming a reference alone cannot enable it: it still has neither a workflow trigger nor an
executable job graph. This means the references trigger **nothing** (no push / PR / tag / schedule, no reusable
call, and no manual dispatch).
No Dependabot configuration or disabled copy is retained. The obsolete upstream updater targeted the sole
`hbb_common` git submodule, which this fork absorbed in-tree; `.gitmodules` and every gitlink are absent. This
fork's dependency world is **exactly pinned** (`Cargo.lock` + `pubspec.lock` + `vcpkg.json` + `scripts/pins.env`,
R-R1/R-R1a/R-B12), so dependency changes require an explicit reviewed pin/provenance transaction rather than an
automated pull-request configuration. GitHub's separate repository-level alert/security-update settings are not
controlled by this source file and are not represented as a source guarantee.

Disabled workflows: `bridge`, `ci`, `flutter-build`, `flutter-ci`, `flutter-tag`,
`third-party-RustDeskTempTopMostWindow`, `wf-cliprdr-ci`.

There is no rename-only re-enable path. Restoring `on` and `jobs` is an explicit release-authority change that
must update R-R2/R-R2d and the closed workflow inventory before a file can be renamed to `*.yml`; reusable
dependencies must be reviewed and restored separately. Historical `uses:` paths are intentionally left as
references, not as an executable workflow chain.
