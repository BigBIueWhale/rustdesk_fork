import 'package:flutter_hbb/desktop/pages/remote_page.dart';
import 'package:flutter_hbb/desktop/widgets/remote_toolbar.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:uuid/uuid.dart';

class _FakeToolbarState implements ToolbarState {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    Get.testMode = true;
  });

  tearDown(() {
    Get.reset();
  });

  test('remote page owns a session ID before state creation', () {
    final page = RemotePage(
      id: 'generated-session-peer',
      toolbarState: _FakeToolbarState(),
    );

    expect(page.sessionId.toString(), isNotEmpty);
  });

  test('remote page preserves a provided session ID', () {
    final sessionId = Uuid().v4obj();
    final page = RemotePage(
      id: 'provided-session-peer',
      sessionId: sessionId,
      toolbarState: _FakeToolbarState(),
    );

    expect(page.sessionId, sessionId);
  });
}
