# GitHub-hosted automation — DISABLED (verifier VM only)

This hardened, direct-IP-only fork does **not** use GitHub Actions for CI/CD. GitHub Actions provides
no build, verification, or release evidence. Product builds and verification require the authenticated,
ordinary-user QEMU verifier VM of R-S11dh in [`requirements.html`](../../requirements.html), with no NIC,
Unix-only control channels, immutable inputs, bounded RAM scratch, resource admission and joined cleanup.
Container operations use only the designated guest daemon and network-isolated containers. The
orchestration host is not a product, test, installer or builder execution environment.

`scripts/build-release.sh` is the VM-internal release coordinator. Target-specific builders are not
independent host entry points. A release requires the complete admitted source/input/signing/Windows
golden transport, exact bounded artifact return, cold reproducibility and target-native acceptance;
missing authority or inputs refuse without a host-Docker or direct-launch fallback. Release preparation
is described in [`VERSIONING.md`](../../docs/VERSIONING.md); current transport, artifact and native
acceptance is tracked in [`HARDENING_STATUS.md`](../../HARDENING_STATUS.md).

This directory contains only this policy document. GitHub Actions workflow definitions and disabled
copies are absent. Git history preserves the obsolete upstream workflows; they are not build inputs,
release recipes, or a supported activation path. Adding hosted automation requires an explicit change
to the release-authority requirements and their absence guard.

No Dependabot configuration or disabled copy is retained. The obsolete upstream updater targeted the sole
`hbb_common` git submodule, which this fork absorbed in-tree; `.gitmodules` and every gitlink are absent. This
fork's dependency world is **exactly pinned** (`Cargo.lock` + `pubspec.lock` + `vcpkg.json` + `scripts/pins.env`,
R-R1/R-R1a/R-B12), so dependency changes require an explicit reviewed pin/provenance transaction rather than an
automated pull-request configuration. GitHub's separate repository-level alert/security-update settings are not
controlled by this source file and are not represented as a source guarantee.
