# Vendored desktop_multi_window

This directory is an exact source import of
`https://github.com/rustdesk-org/rustdesk_desktop_multi_window` commit
`b47e8385e5a75d38319ad706a64b0ead3108b093`, previously pinned directly by
`flutter/pubspec.yaml` and `flutter/pubspec.lock`.

The only source change in the imported plugin is the Linux subwindow-destruction
lifetime correction in `linux/flutter_window.cc` and `linux/flutter_window.h`.
The upstream callback erased the manager-owned `FlutterWindow` from inside that
same object's GTK `delete-event` callback and then read the freed object while
returning. The vendored correction makes close scheduling idempotent, inhibits
GTK's synchronous default destruction, and defers the owning-map erase to the
GTK idle queue so the signal callback has returned before destruction begins.

The original Apache-2.0 license is retained in `LICENSE`. Do not refresh this
directory from upstream without reviewing and recording the exact new commit,
reapplying or retiring the local lifetime correction, regenerating the Flutter
lockfile, and rerunning the exact Linux full-peer close transaction plus the
Windows and macOS build/verifier gates.
