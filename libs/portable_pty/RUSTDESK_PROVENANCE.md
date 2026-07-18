# portable-pty provenance

This directory is the `pty/` crate from RustDesk's pinned WezTerm fork commit
`80174f8009f41565f0fa8c66dab90d4f9211ae16` (`portable-pty` 0.8.1), previously
resolved directly by the root `Cargo.toml` Git dependency.

It is kept in-tree so RustDesk can own and audit the Unix child-process boundary.
The fork-specific change replaces the dependency's post-fork allocating,
best-effort `close_random_fds` routine with parent-prepared, bounded descriptor
enumeration and an async-signal-safe, fail-closed `fcntl(F_GETFD/F_SETFD)`
close-on-exec policy. The policy preserves only stdio in the final PTY child and
keeps Rust's exec-error pipe usable until a successful `exec`.

The remaining source is byte-for-byte from that pinned `pty/` directory except
for the local dependency declaration needed outside the original WezTerm
workspace and the security policy/tests above.
