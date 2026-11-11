# Vendored `file_selector_linux`

This directory vendors the complete `file_selector_linux` 0.9.4+1 package with
one Linux lifetime correction in `linux/file_selector_plugin.cc`.
The original hosted archive has SHA-256
`da76400e7872ce7637ffdce12749ec24169c25f6195c28372208e65a24bcd2ab`.
Publisher metadata/content and independent CFUG content matched during the
authenticated acquisition recorded in
`.harness-state/verifier-vm/flutter-plugin-archives-ba16484a.json`.
The import uses that package from the authenticated migration cache
`fc3d40987ffbc03c0aa675d990852264c126e67a358a4a78797c2ee6d6d5d931`.
The original plugin source has SHA-256
`6c85e3968576e093e950fa6f0e11d788fe6972c9d93dbd93cd5514f807d31fd9`.
Upstream: <https://github.com/flutter/packages/tree/main/packages/file_selector/file_selector_linux>.

The messenger owns a channel, the channel's handler owns the Pigeon API object,
and that object owns the plugin. Removing the handler releases the plugin's last
reference. Its disposal therefore releases the registrar without recursively
clearing that handler: the generated clear function constructs another channel,
which attempts registration after the engine has retired.
The ownership model matches the pinned Flutter engine's
[handler destruction](https://github.com/flutter/flutter/blob/6a19cca56475dbfba1478ee68d7bd0c2ef891da1/engine/src/flutter/shell/platform/linux/fl_basic_message_channel.cc#L99).
Dart methods, generated messages and native file chooser behavior are unchanged.
The native application replay `--screenshot-save` exercises cancel, an exact
Unicode PNG save, fresh subsequent frames and clean engine shutdown.
