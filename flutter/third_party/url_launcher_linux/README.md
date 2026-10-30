# Vendored `url_launcher_linux`

This fork carries a local copy of `url_launcher_linux` 3.2.1, the Linux
implementation of `url_launcher`. The application's
[pubspec.yaml](../../pubspec.yaml) selects this directory through a
`dependency_overrides` path entry, and [pubspec.lock](../../pubspec.lock)
records it as a path dependency. Application code continues to use `url_launcher`.

The local copy includes a Linux engine-shutdown correction. See
[UPSTREAM.md](UPSTREAM.md) for the imported package identity and the native change.
The [changelog](CHANGELOG.md) records upstream package history;
[LICENSE](LICENSE) and [AUTHORS](AUTHORS) retain upstream attribution.

For changes and verification, follow the fork's
[contribution guide](../../../docs/CONTRIBUTING.md) and
[build execution boundary](../../../scripts/README.md#execution-boundary).
