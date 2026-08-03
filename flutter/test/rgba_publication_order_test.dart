import 'dart:async';

import 'package:flutter_hbb/models/rgba_publication_order.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a newer publication invalidates an older asynchronous completion', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final latest = order.admit('session', 0, 2)!;

    expect(order.isCurrent(first), isFalse);
    expect(order.isCurrent(latest), isTrue);
    expect(order.admit('session', 0, 1), isNull);
    expect(order.admit('session', 0, 2), isNull);
  });

  test('out-of-order asynchronous completions commit only the latest',
      () async {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final firstGate = Completer<void>();
    final latestGate = Completer<void>();
    final commits = <int>[];

    Future<void> finish(RgbaPublicationAdmission<String> admission, int value,
        Completer<void> gate) async {
      await gate.future;
      if (order.isCurrent(admission)) {
        commits.add(value);
      }
    }

    final firstCompletion = finish(first, 1, firstGate);
    final latest = order.admit('session', 0, 2)!;
    final latestCompletion = finish(latest, 2, latestGate);
    latestGate.complete();
    await latestCompletion;
    firstGate.complete();
    await firstCompletion;

    expect(commits, [2]);
  });

  test('a newer cross-display publication supersedes the old display', () {
    final order = ExactRgbaPublicationOrder<String>();
    final firstDisplay = order.admit('session', 0, 7)!;
    final secondDisplay = order.admit('session', 1, 8)!;

    expect(order.isCurrent(firstDisplay), isFalse);
    expect(order.isCurrent(secondDisplay), isTrue);
    expect(order.admit('session', 0, 7), isNull);
  });

  test('an exact new session may begin with a lower native publication', () {
    final order = ExactRgbaPublicationOrder<String>();
    final predecessor = order.admit('predecessor', 0, 40)!;
    final replacement = order.admit('replacement', 0, 1)!;

    expect(order.isCurrent(predecessor), isFalse);
    expect(order.isCurrent(replacement), isTrue);
  });

  test('retirement invalidates an admitted asynchronous completion', () {
    final order = ExactRgbaPublicationOrder<String>();
    final admitted = order.admit('session', 0, 1)!;

    order.retire();

    expect(order.isCurrent(admitted), isFalse);
  });

  test('nonpositive native publications are rejected', () {
    final order = ExactRgbaPublicationOrder<String>();

    expect(order.admit('session', 0, 0), isNull);
    expect(order.admit('session', 0, -1), isNull);
  });
}
