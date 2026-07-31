# texture_rgba_renderer provenance

This package is derived from
`https://github.com/rustdesk-org/flutter_texture_rgba_renderer` commit
`42797e0f03141dc2b585f76c64a13974508058b4` (upstream package version
`0.0.16`).

RustDesk maintains this in-tree derivative because the upstream native
implementations did not give texture teardown one exact owner:

- Windows used Flutter's deprecated asynchronous unregister overload, destroyed
  callback state before raster-thread unregister completion, and unregistered a
  second time from the texture destructor.
- macOS unregistered the Flutter texture but retained the renderer in its key
  map.
- Linux kept renderers in process-global raw-pointer state, did not release the
  plugin's owning `GObject` reference, and had no finalizer for its buffers and
  mutex.
- Windows and Linux preserved the oldest pending pixel buffer by rejecting
  every newer frame until raster consumption, while macOS replaced the buffer
  but emitted a duplicate availability notification for every replacement.

The in-tree package preserves the upstream Apache-2.0 license. Modified source
files carry a derivation notice.
