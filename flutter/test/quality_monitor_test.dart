import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';

class _QualityMonitorOwner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected monitor owner access: ${invocation.memberName}');
}

class _VisibleQualityMonitor extends QualityMonitorModel {
  _VisibleQualityMonitor(FFI owner) : super(WeakReference(owner));
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
  });
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: QualityMonitor(model))));
  return model;
}

void main() {
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
