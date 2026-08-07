# Vendored `url_launcher_linux`

This directory is the exact `url_launcher_linux` 3.2.1 package whose hosted
archive is locked in the pre-vendoring `flutter/pubspec.lock` with SHA-256
`4e9ba368772369e3e08f231d2301b4ef72b9ff87c31192ef471b380ef29a4935`.
The imported upstream `linux/url_launcher_plugin.cc` has SHA-256
`52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d`.
Its upstream repository is
<https://github.com/flutter/packages/tree/main/packages/url_launcher/url_launcher_linux>.

RustDesk carries one Linux native lifetime correction in
`linux/url_launcher_plugin.cc`. The two Pigeon message handlers jointly retain
one API object, and that object owns the plugin. The plugin can therefore reach
its last reference only while the Flutter messenger is already removing those
handlers. Upstream 3.2.1 nevertheless calls
`ful_url_launcher_api_clear_method_handlers()` from the plugin's `dispose()`,
recursively constructing replacement channels during engine shutdown. The
vendored copy omits that redundant recursive clear and still releases its
registrar. Dart behavior, message names and payloads, URL-launch behavior, and
all non-Linux platform packages remain unchanged.
