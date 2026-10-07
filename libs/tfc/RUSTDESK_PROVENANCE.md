# TFC provenance and local maintenance

The retained runtime source and both licenses come from RustDesk's TFC 0.7.0
fork at commit `78bb80a8e596e4c14ae57c8448f5fca75f91f2b0`, root Git tree
`369a0ac9e63bfff8d377c5605eb2c82aa5f566c1`:
[exact upstream source](https://github.com/rustdesk-org/The-Fat-Controller/tree/78bb80a8e596e4c14ae57c8448f5fca75f91f2b0).
`UPSTREAM_BLOBS.tsv` records the original Git blob for every retained file.
All 67 imported files matched that complete primary Git tree before local edits.
GitHub reports a valid commit signature; it was not independently authenticated.
Byte binding is not a complete supplier review.

The crate is repository-owned so the native input implementation can be corrected
without modifying immutable build-cache inputs or selecting a mutable Git branch.
The package version and Windows/macOS dependencies are preserved. Windows/macOS
implementations are imported unchanged and are not newly validated by Linux tests.
Linux is unconditionally X11, as in the pinned fork. Unreachable Wayland code,
the unused build-time login-session probe/features, unused dependencies, and
upstream examples/tests/docs are not imported. The source no longer needs the
Git X11 package previously used only for an extra keyboard query; registry X11
used elsewhere in RustDesk is unaffected.

Local Linux changes:

- Match `XkbStateRec` to the client C header, not the server's internal record:
  byte group/locked group, then two unsigned-short base/latched groups. The
  native `XkbGetState` return is Status, and a failed query returns its error
  before key mapping or event emission.
- Build mappings from the description returned on the context's one display.
  Use each key's group count rather than allocating another display/description
  and treating the names-array capacity as an active group count. The complete
  keyboard description has one scoped `XkbFreeKeyboard(..., True)` owner.
- Retain the symbol allocation through a scoped owner, including invalid-count
  exits. Validate keycode range before narrowing or calculating its span.
- Remove the disabled backend comments, stale state-query branch, and docs
  advertising a nonexistent fallback feature.

Native execution, artifact identities, evidence limits and outstanding product
work belong in `HARDENING_STATUS.md`, not this provenance record. In particular,
this import does not claim that every inherited API is corrected: the Linux
`unicode_string` no-op, modifier/error cleanup, enclosing Enigo error routing,
complete supplier review, other platforms, canonical offline-closure regeneration,
and full application/installed/artifact acceptance still require their own work.
