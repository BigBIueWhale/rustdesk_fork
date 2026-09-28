import 'dart:async';

import 'package:flutter_hbb/models/android_permission_request_coordinator.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('immediate grant completes the already-owned request', () async {
    final coordinator = AndroidPermissionRequestCoordinator();
    final request = coordinator.begin(type: 'notification', id: 'request-1');

    expect(request, isNotNull);
    expect(
      coordinator.complete(
        type: 'notification',
        id: 'request-1',
        granted: true,
      ),
      isTrue,
    );
    expect(await request!.result, isTrue);
  });

  test('denial completes instead of leaving the request pending', () async {
    final coordinator = AndroidPermissionRequestCoordinator();
    final request = coordinator.begin(type: 'audio', id: 'request-1');

    expect(
      coordinator.complete(
        type: 'audio',
        id: 'request-1',
        granted: false,
      ),
      isTrue,
    );
    expect(await request!.result, isFalse);
  });

  test('stale type or identity cannot retire the current request', () async {
    final coordinator = AndroidPermissionRequestCoordinator();
    final request = coordinator.begin(type: 'storage', id: 'request-2')!;
    var completed = false;
    unawaited(request.result.then<void>((_) {
      completed = true;
    }));

    expect(
      coordinator.complete(
        type: 'audio',
        id: 'request-2',
        granted: true,
      ),
      isFalse,
    );
    expect(
      coordinator.complete(
        type: 'storage',
        id: 'request-1',
        granted: true,
      ),
      isFalse,
    );
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);
    expect(coordinator.pendingId('storage'), 'request-2');

    expect(
      coordinator.complete(
        type: 'storage',
        id: 'request-2',
        granted: true,
      ),
      isTrue,
    );
    expect(await request.result, isTrue);
  });

  test('overlap cannot displace the in-flight request', () async {
    final coordinator = AndroidPermissionRequestCoordinator();
    final first = coordinator.begin(type: 'audio', id: 'request-1')!;

    expect(
      coordinator.begin(type: 'storage', id: 'request-2'),
      isNull,
    );
    expect(coordinator.pendingId('audio'), 'request-1');
    expect(coordinator.pendingId('storage'), isNull);

    expect(
      coordinator.complete(
        type: 'audio',
        id: 'request-1',
        granted: true,
      ),
      isTrue,
    );
    expect(await first.result, isTrue);
  });

  test('a predecessor callback cannot complete its successor', () async {
    final coordinator = AndroidPermissionRequestCoordinator();
    final first = coordinator.begin(type: 'audio', id: 'request-1')!;
    expect(
      coordinator.complete(
        type: 'audio',
        id: 'request-1',
        granted: false,
      ),
      isTrue,
    );
    expect(await first.result, isFalse);

    final successor = coordinator.begin(type: 'audio', id: 'request-2')!;
    expect(
      coordinator.complete(
        type: 'audio',
        id: 'request-1',
        granted: true,
      ),
      isFalse,
    );
    expect(coordinator.pendingId('audio'), 'request-2');

    expect(
      coordinator.complete(
        type: 'audio',
        id: 'request-2',
        granted: true,
      ),
      isTrue,
    );
    expect(await successor.result, isTrue);
  });
}
