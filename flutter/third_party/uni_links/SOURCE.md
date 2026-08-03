# Vendored source

- Upstream: `https://github.com/rustdesk-org/uni_links`
- Commit: `f416118d843a7e9ed117c7bb7bdc2deda5a9e86f`
- Upstream path: `uni_links/`
- Package version: `0.5.1`

Only the package's production sources and license are vendored. Local Android
maintenance is intentionally limited to declaring the AGP 8 namespace, aligning
the plugin build declaration with the application's pinned AGP version, removing
the now-ignored manifest `package` attribute, and deleting the obsolete Flutter
V1 `PluginRegistry.Registrar` registration entry point. The current RustDesk
Android application uses Flutter's V2 embedding.
