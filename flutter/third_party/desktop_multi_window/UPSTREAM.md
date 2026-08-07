# Vendored desktop_multi_window

This directory is an exact source import of
`https://github.com/rustdesk-org/rustdesk_desktop_multi_window` commit
`b47e8385e5a75d38319ad706a64b0ead3108b093`, previously pinned directly by
`flutter/pubspec.yaml` and `flutter/pubspec.lock`.

The functional source change in the imported plugin is the Linux
subwindow-destruction lifetime correction in `linux/flutter_window.cc`,
`linux/flutter_window.h`, `linux/window_channel.cc`, and
`linux/window_channel.h`. The upstream callback erased the manager-owned
`FlutterWindow` from inside that same object's GTK `delete-event` callback and
then read the freed object while returning. The vendored correction makes close
scheduling idempotent, inhibits GTK's synchronous default destruction, and
defers the owning-map erase to the GTK idle queue. RustDesk's Dart `onDestroy`
handler is asynchronous because it retires textures and sessions before the
subwindow engine may disappear. Native code therefore also waits for the method
response before scheduling the idle erase. Both the Dart cleanup and the
method-response callback have returned before destruction begins.

The imported Linux source also installed process-global GTK button-press and
button-release emission hooks with the subwindow object as callback data, but
retained and removed only the press-hook ID. The vendored correction owns both
IDs and removes both hooks before destroying the GTK window, so no global hook
can retain a dangling `FlutterWindow` pointer after owner retirement.

The vendored Dart also carries behavior-preserving analyzer hygiene required by
the release gate: it removes an impossible null-aware call and unused imports,
calls `super.initState()`, uses a real `@override`, matches overridden parameter
names, and replaces deprecated `describeEnum(edge)` with the equivalent
`edge.name` wire value. These are deliberate recorded deviations from the exact
upstream commit, not an unrecorded refresh.

The original Apache-2.0 license is retained in `LICENSE`. Do not refresh this
directory from upstream without reviewing and recording the exact new commit,
reapplying or retiring the local lifetime correction, regenerating the Flutter
lockfile, preserving or deliberately retiring the analyzer corrections, and
rerunning the exact Linux full-peer close transaction plus the Windows and macOS
build/verifier gates.
