import 'package:desktop_multi_window/src/channels.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_hbb/utils/multi_window_manager.dart';
import 'package:flutter_test/flutter_test.dart';

class _WindowStorage implements RustdeskImpl {
  final local = <String, String>{};
  final peers = <String, String>{};
  final writes = <String>[];

  @override
  bool isIncomingOnly() => false;
  @override
  bool isOutgoingOnly() => false;
  @override
  String getLocalFlutterOption({required String k}) => local[k] ?? '';
  @override
  Future<void> setLocalFlutterOption({required String k, required String v}) async {
    local[k] = v;
  }
  @override
  String mainGetPeerFlutterOptionSync({required String id, required String k}) =>
      peers[id] ?? '';
  @override
  void mainSetPeerFlutterOptionSync(
      {required String id, required String k, required String v}) {
    expect(k, startsWith(kWindowPrefix));
    peers[id] = v;
    writes.add(id);
  }
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected window storage call: ${invocation.memberName}');
}

void main() {
  final binding = TestWidgetsFlutterBinding.ensureInitialized();
  for (final mode in ['normal', 'maximized', 'fullscreen']) {
    test('peer window $mode save preserves dimensions separately from position',
        () async {
      final storage = _WindowStorage();
      installWindowPositionProbeBinding(storage);
      resetWindowPositionProbe();
      stateGlobal.fullscreen.value = mode == 'fullscreen';
      addTearDown(() {
        resetWindowPositionProbe();
        stateGlobal.fullscreen.value = false;
        binding.defaultBinaryMessenger.setMockMethodCallHandler(miltiWindowChannel, null);
        binding.defaultBinaryMessenger.setMockMethodCallHandler(windowEventChannel, null);
      });

      var frame = const Rect.fromLTWH(0, 0, 960, 540);
      binding.defaultBinaryMessenger.setMockMethodCallHandler(miltiWindowChannel,
          (call) async {
        if (call.method == 'isMaximized') {
          expect(call.arguments, 7);
          return mode == 'maximized';
        }
        expect(call.method, 'getFrame');
        expect(mode, 'normal');
        expect(call.arguments, {'windowId': 7});
        return {'x': frame.left, 'y': frame.top,
          'width': frame.width, 'height': frame.height};
      });
      binding.defaultBinaryMessenger.setMockMethodCallHandler(windowEventChannel,
          (call) async {
        expect(call.method, kWindowEventGetRemoteList);
        expect(call.arguments, {'targetWindowId': 7, 'arguments': null});
        return 'absent,complete,partial';
      });

      for (final type in [WindowType.RemoteDesktop, WindowType.ViewCamera]) {
        for (final offset in [Offset.zero, const Offset(-800, 75), const Offset(40, 60)]) {
          resetWindowPositionProbe();
          frame = offset & const Size(960, 540);
          final previous = LastWindowPosition(960, 540, offset.dx, offset.dy, false, false);
          final complete = LastWindowPosition(1234, 678, -320, 25, false, false);
          final partial = LastWindowPosition(null, 444, null, -35, false, false);
          storage.local[windowFramePrefix + type.name] = previous.toString();
          storage.peers
            ..clear()
            ..addAll({'complete': complete.toString(), 'partial': partial.toString()});
          storage.writes.clear();
          await saveWindowPosition(type, windowId: 7, flush: true);
          expect(storage.writes, ['absent', 'complete', 'partial']);
          final actual = {for (final id in storage.writes)
            id: LastWindowPosition.loadFromString(storage.peers[id]!)!.toJson()};
          debugPrint('PEER_WINDOW_SAVE mode=$mode type=${type.name} offset=$offset values=$actual');
          for (final id in storage.writes) {
            final saved = id == 'complete' ? complete : id == 'partial' ? partial : null;
            final preserve = mode != 'normal';
            final expected = LastWindowPosition(
              preserve ? saved?.width ?? 960 : 960,
              preserve ? saved?.height ?? 540 : 540,
              preserve ? saved?.offsetWidth ?? offset.dx : offset.dx,
              preserve ? saved?.offsetHeight ?? offset.dy : offset.dy,
              mode == 'maximized', mode == 'fullscreen');
            expect(actual[id], expected.toJson(), reason: '$mode ${type.name} $id $offset');
          }
          expect(LastWindowPosition.loadFromString(
              storage.local[windowFramePrefix + type.name]!)!.width, 960);
        }
      }
    });
  }
}
