import 'package:flutter_hbb/models/rgba_publication_order.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a newer admission does not suppress an earlier useful completion', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final latest = order.admit('session', 0, 2)!;

    expect(order.canComplete(first), isTrue);
    expect(order.canComplete(latest), isTrue);

    expect(order.commit(first), isTrue);
    expect(order.canComplete(first), isFalse);
    expect(order.canComplete(latest), isTrue);

    expect(order.commit(latest), isTrue);
    expect(order.commit(first), isFalse);
    expect(order.canComplete(latest), isFalse);
  });

  test('a higher completion permanently rejects a lower late result', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final latest = order.admit('session', 0, 2)!;

    expect(order.commit(latest), isTrue);

    expect(order.canComplete(first), isFalse);
    expect(order.commit(first), isFalse);
  });

  test('a higher conversion failure does not starve a lower completion', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final failedLatest = order.admit('session', 0, 2)!;

    // No commit models an image conversion that returned no image.
    expect(order.canComplete(failedLatest), isTrue);
    expect(order.commit(first), isTrue);
  });

  test('completion order remains global across displays', () {
    final firstDisplay = ExactRgbaPublicationOrder<String>();
    final first = firstDisplay.admit('session', 0, 7)!;
    final second = firstDisplay.admit('session', 1, 8)!;

    expect(firstDisplay.commit(first), isTrue);
    expect(firstDisplay.commit(second), isTrue);
    expect(firstDisplay.canComplete(first), isFalse);

    final secondDisplay = ExactRgbaPublicationOrder<String>();
    final delayedFirst = secondDisplay.admit('session', 0, 7)!;
    final earlySecond = secondDisplay.admit('session', 1, 8)!;
    expect(secondDisplay.commit(earlySecond), isTrue);

    expect(secondDisplay.commit(delayedFirst), isFalse);
  });

  test('an exact new session invalidates predecessor work and may restart', () {
    final order = ExactRgbaPublicationOrder<String>();
    final predecessor = order.admit('predecessor', 0, 40)!;
    expect(order.commit(predecessor), isTrue);
    final replacement = order.admit('replacement', 0, 1)!;

    expect(order.canComplete(predecessor), isFalse);
    expect(order.commit(predecessor), isFalse);
    expect(order.canComplete(replacement), isTrue);
    expect(order.commit(replacement), isTrue);
  });

  test('retirement invalidates admitted work and resets publication order', () {
    final order = ExactRgbaPublicationOrder<String>();
    final admitted = order.admit('session', 0, 1)!;
    expect(order.commit(admitted), isTrue);

    order.retire();

    expect(order.canComplete(admitted), isFalse);
    expect(order.commit(admitted), isFalse);
    final replacement = order.admit('session', 0, 1)!;
    expect(order.commit(replacement), isTrue);
  });

  test('nonpositive and duplicate native publications are rejected', () {
    final order = ExactRgbaPublicationOrder<String>();

    expect(order.admit('session', 0, 0), isNull);
    expect(order.admit('session', 0, -1), isNull);
    expect(order.admit('session', 0, 1), isNotNull);
    expect(order.admit('session', 0, 1), isNull);
    expect(order.admit('session', 1, 1), isNull);
  });
}
