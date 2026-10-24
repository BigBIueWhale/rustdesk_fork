# Windows MSI packaging

This WiX project is an input to the fork's
[Windows build recipe](../../scripts/build-windows.ps1). The recipe runs the
preprocessor, restores the pinned WiX packages offline in locked mode, builds the
x64 MSI, and canonicalizes and validates the resulting installer.

Follow the [build execution boundary](../../scripts/README.md#execution-boundary)
and [release preparation procedure](../../docs/VERSIONING.md#preparing-a-release)
for authenticated inputs, disposable guest execution and complete release sets.
Current Windows build and installed-artifact acceptance is tracked in the
[hardening ledger](../../HARDENING_STATUS.md#current-verdict).
Before installation, follow the
[release artifact verification procedure](../../docs/RELEASE-VERIFICATION.md).

This project is mainly derived from <https://github.com/MediaPortal/MediaPortal-2.git> .
