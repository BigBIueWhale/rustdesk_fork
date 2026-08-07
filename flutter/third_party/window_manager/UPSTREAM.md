# Upstream provenance and local lifecycle correction

This package is an in-tree copy of `window_manager` 0.3.6 from
`https://github.com/rustdesk-org/window_manager`, commit
`85789bfe6e4cfaf4ecc00c52857467fdb7f26879` (Git tree
`9627e63c85411da995da37cb7cd6d392766a509d`). Before the local correction,
`linux/window_manager_plugin.cc` had SHA-256
`5b2a562f2e853cde3661468aea2a38fc9d1abef5e2fbd3befbc86831a7f7cd87`.
The Dart, asset, macOS, and Windows implementation bytes are unchanged from
that commit. The four shipped PNG assets have these SHA-256 identities:

- `images/ic_chrome_close.png`:
  `70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5`
- `images/ic_chrome_maximize.png`:
  `93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4`
- `images/ic_chrome_minimize.png`:
  `0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a`
- `images/ic_chrome_unmaximize.png`:
  `3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b`

The selected Linux implementation derived its `GtkWindow` from a registrar on
every method call, even though the registrar and a queued platform message can
outlive the GTK view. It also left its GTK signal callbacks, process-wide
button-press emission hook, channel, and registrar unretired. A real two-peer
release run reproduced the consequence after normal remote-window closure:
the multi-window owner completed destruction, then a queued `isMaximized`
message entered `gtk_window_is_maximized()` through this plugin with a stale
window and terminated the viewer with `SIGSEGV`.

The local Linux correction binds the plugin to the concrete window selected at
registration, observes that window's `destroy` signal as a terminal lifetime
boundary, rejects later queued calls with `window_unavailable`, and retires
every signal/hook/channel/registrar resource it owns. The native regression
drives the real standard-method channel with an unavailable window and proves
both the error response and terminal handler/plugin release.
