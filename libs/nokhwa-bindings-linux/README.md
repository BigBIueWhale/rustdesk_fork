# Linux camera backend

Derived from `rustdesk-org/nokhwa` commit
`c2f74662b6ce117f7f94301693fdfadc0b1ec91a`, package
`nokhwa-bindings-linux` 0.1.1, under Apache-2.0. The original `src/lib.rs`
SHA-256 is `9fb446f29bcc50a20e786704f9c91bcf404a744208a361264a7e4e0fc1573da4`.
Copyright notices remain in the source.

Each capture object opens and owns its device. Numeric node indices do not
identify existing open handles: a fresh open must resolve the current node.
Stream sharing belongs to RustDesk's capture service, not a global weak cache
inside the backend. V4L2 enforces exclusive streaming ownership for independent
opens; a competing stream must fail without changing the incumbent stream.

Capture mappings and their nonblocking device handle have one owner. A frame
deadline returns WouldBlock without stopping capture or requeuing a buffer the
driver already owns. Only a successful dequeue creates a buffer to requeue;
only its reported payload is exposed. Caller waits are capped at one second.
Explicit close reports errors and retains the stream for cleanup retry. Drop
attempts cleanup without panicking and reports failures. The memmap2 owner uses
the application's existing pinned dependency to retire each mapping.

The root Cargo patch and native camera probe select this same source. Other
nokhwa packages and dependency versions retain their existing pins.
