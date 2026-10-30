import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';

class _QualityMonitorOwner implements FFI {
  @override
  final FfiModel ffiModel = _QualityMonitorFfiModel();

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected monitor owner access: ${invocation.memberName}');
}

class _QualityMonitorFfiModel implements FfiModel {
  @override
  final PeerInfo pi = PeerInfo();

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected peer model access: ${invocation.memberName}');
}

class _VisibleQualityMonitor extends QualityMonitorModel {
  _VisibleQualityMonitor(this.owner) : super(WeakReference(owner));
  final _QualityMonitorOwner owner;
  bool visible = true;

  @override
  bool get show => visible;
}

Future<_VisibleQualityMonitor> _qualityMonitor(WidgetTester tester) async {
  final owner = _QualityMonitorOwner();
  final model = _VisibleQualityMonitor(owner);
  addTearDown(() async {
    await tester.pumpWidget(const SizedBox.shrink());
    model.dispose();
    model.owner.ffiModel.pi.dispose();
  });
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: QualityMonitor(model))));
  return model;
}

Map<String, String> _qualityStatus({
  String speed = '',
  String fps = '{}',
  String delay = '',
  String targetBitrate = '',
  String codec = '',
  String chroma = '',
}) => {
  'speed': speed,
  'fps': fps,
  'delay': delay,
  'target_bitrate': targetBitrate,
  'codec_format': codec,
  'chroma': chroma,
};

void main() {
  testWidgets('quality monitor decodes the selected display snapshot',
      (tester) async {
    final model = await _qualityMonitor(tester);
    model.owner.ffiModel.pi.currentDisplay = 1;
    model.updateQualityStatus(_qualityStatus(
      speed: '12.5kB/s', fps: '{"0":10,"1":60}', delay: '55',
      targetBitrate: '1100', codec: 'VP9', chroma: '4:4:4',
    ));
    await tester.pump();
    for (final text in ['12.5kB/s', '60', '55ms', '1100kb', 'VP9', '4:4:4']) {
      expect(find.text(text), findsOneWidget, reason: text);
    }
    expect(find.text('10'), findsNothing);
  });

  testWidgets('quality monitor merges delay and frame snapshots independently',
      (tester) async {
    final model = await _qualityMonitor(tester);
    model.updateQualityStatus(_qualityStatus(
      speed: '12.5kB/s', fps: '{"0":30}', delay: '55',
      targetBitrate: '1100', codec: 'VP9', chroma: '4:4:4',
    ));
    await tester.pump();
    model.updateQualityStatus(_qualityStatus(delay: '80', targetBitrate: '1500'));
    await tester.pump();
    for (final text in ['12.5kB/s', '30', '80ms', '1500kb', 'VP9', '4:4:4']) {
      expect(find.text(text), findsOneWidget, reason: text);
    }
    model.updateQualityStatus(_qualityStatus(
      speed: '7.5kB/s', fps: '{"0":0}', codec: 'VP9', chroma: '4:2:0',
    ));
    await tester.pump();
    for (final text in ['7.5kB/s', '0', '80ms', '1500kb', 'VP9', '4:2:0']) {
      expect(find.text(text), findsOneWidget, reason: text);
    }
  });

  testWidgets('quality monitor preserves values across omitted and empty fields',
      (tester) async {
    final model = await _qualityMonitor(tester);
    model.updateQualityStatus(_qualityStatus(
      speed: '12.5kB/s', fps: '{"0":30}', delay: '55',
      targetBitrate: '1100', codec: 'VP9', chroma: '4:4:4',
    ));
    await tester.pump();
    model.updateQualityStatus({'speed': '1kB/s'});
    await tester.pump();
    for (final update in <Map<String, String>>[{}, _qualityStatus(fps: '')]) {
      model.updateQualityStatus(update);
      await tester.pump();
      for (final text in ['1kB/s', '30', '55ms', '1100kb', 'VP9', '4:4:4']) {
        expect(find.text(text), findsOneWidget, reason: text);
      }
    }
  });

  testWidgets('quality monitor orders all displays and follows selection',
      (tester) async {
    final model = await _qualityMonitor(tester);
    final pi = model.owner.ffiModel.pi;
    pi.displays.addAll([Display(), Display(), Display()]);
    pi.currentDisplay = kAllDisplayValue;
    model.updateQualityStatus(_qualityStatus(fps: '{"2":11,"0":25,"1":0}'));
    await tester.pump();
    expect(find.text('25 0 11'), findsOneWidget);
    model.updateQualityStatus(_qualityStatus(delay: '80'));
    await tester.pump();
    expect(find.text('25 0 11'), findsOneWidget);
    pi.currentDisplay = 2;
    model.updateQualityStatus(_qualityStatus(fps: '{"2":17,"0":28,"1":0}'));
    await tester.pump();
    expect(find.text('17'), findsOneWidget);
    expect(find.text('25 0 11'), findsNothing);
    expect(find.text('80ms'), findsOneWidget);
  });

  testWidgets('quality monitor preserves delay at zero FPS', (tester) async {
    final model = await _qualityMonitor(tester);
    for (final fps in ['0', '0 0', '0 0 0']) {
      model.data.fps = fps;
      model.updateQualityStatus({'delay': '750'});
      await tester.pump();
      expect(find.text('750ms'), findsOneWidget, reason: 'FPS=$fps');
      expect(find.text(fps), findsOneWidget);
      expect(model.data.delay, '750');
      expect(find.text('0ms'), findsNothing);
    }
  });

  testWidgets('quality monitor preserves delay before FPS arrives',
      (tester) async {
    final model = await _qualityMonitor(tester);
    for (final fps in <String?>[null, '']) {
      model.data.fps = fps;
      model.updateQualityStatus({'delay': '300'});
      await tester.pump();
      expect(find.text('300ms'), findsOneWidget, reason: 'FPS=$fps');
      expect(find.text('0ms'), findsNothing);
    }
  });

  testWidgets('quality monitor keeps delay through frame rate changes',
      (tester) async {
    final model = await _qualityMonitor(tester);
    model.data.fps = '30';
    model.updateQualityStatus({'delay': '125'});
    await tester.pump();
    expect(find.text('125ms'), findsOneWidget);
    model.data.fps = '0';
    model.updateQualityStatus({});
    await tester.pump();
    expect(find.text('125ms'), findsOneWidget);
    model.updateQualityStatus({'delay': '900'});
    await tester.pump();
    expect(find.text('900ms'), findsOneWidget);
    model.data.fps = '24';
    model.updateQualityStatus({});
    await tester.pump();
    expect(find.text('900ms'), findsOneWidget);
    expect(find.text('24'), findsOneWidget);
  });

  testWidgets('quality monitor distinguishes absent and measured zero delay',
      (tester) async {
    final model = await _qualityMonitor(tester);
    for (final fps in <String?>['30', '0', null]) {
      model.data.fps = fps;
      model.data.delay = null;
      model.updateQualityStatus({});
      await tester.pump();
      expect(find.text('-ms'), findsOneWidget);
      expect(find.text('0ms'), findsNothing);
      model.updateQualityStatus({'delay': '0'});
      await tester.pump();
      expect(find.text('0ms'), findsOneWidget);
      expect(find.text('-ms'), findsNothing);
    }
  });

  testWidgets('quality monitor visibility preserves reported values',
      (tester) async {
    final model = await _qualityMonitor(tester);
    model.data.fps = '30';
    model.updateQualityStatus({'delay': '250'});
    await tester.pump();
    expect(find.text('250ms'), findsOneWidget);
    model.visible = false;
    model.updateQualityStatus({});
    await tester.pump();
    expect(find.text('Delay'), findsNothing);
    expect(find.text('250ms'), findsNothing);
    model.visible = true;
    model.updateQualityStatus({});
    await tester.pump();
    expect(find.text('250ms'), findsOneWidget);
  });

}
