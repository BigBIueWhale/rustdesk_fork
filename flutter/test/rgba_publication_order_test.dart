import 'package:flutter_hbb/models/rgba_publication_order.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a newer admission does not suppress an earlier useful completion', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final latest = order.admit('session', 0, 2)!;

    expect(order.canComplete(first), isTrue);
    expect(order.canComplete(latest), isTrue);

    final firstCommit = order.commit(first)!;
    expect(order.isCurrent(firstCommit), isTrue);

    final latestCommit = order.commit(latest)!;
    expect(order.isCurrent(firstCommit), isFalse);
    expect(order.isCurrent(latestCommit), isTrue);
  });

  test('a higher completion permanently rejects a lower late result', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final latest = order.admit('session', 0, 2)!;

    final latestCommit = order.commit(latest)!;

    expect(order.commit(first), isNull);
    expect(order.isCurrent(latestCommit), isTrue);
  });

  test('a higher conversion failure does not starve a lower completion', () {
    final order = ExactRgbaPublicationOrder<String>();
    final first = order.admit('session', 0, 1)!;
    final failedLatest = order.admit('session', 0, 2)!;

    // No commit models an image conversion that returned no image.
    expect(order.canComplete(failedLatest), isTrue);
    final firstCommit = order.commit(first)!;

    expect(order.isCurrent(firstCommit), isTrue);
  });

  test('completion order remains global across displays', () {
    final firstDisplay = ExactRgbaPublicationOrder<String>();
    final first = firstDisplay.admit('session', 0, 7)!;
    final second = firstDisplay.admit('session', 1, 8)!;

    final firstCommit = firstDisplay.commit(first)!;
    final secondCommit = firstDisplay.commit(second)!;

    expect(firstDisplay.isCurrent(firstCommit), isFalse);
    expect(firstDisplay.isCurrent(secondCommit), isTrue);

    final secondDisplay = ExactRgbaPublicationOrder<String>();
    final delayedFirst = secondDisplay.admit('session', 0, 7)!;
    final earlySecond = secondDisplay.admit('session', 1, 8)!;
    final earlySecondCommit = secondDisplay.commit(earlySecond)!;

    expect(secondDisplay.commit(delayedFirst), isNull);
    expect(secondDisplay.isCurrent(earlySecondCommit), isTrue);
  });

  test('an exact new session invalidates predecessor work and may restart', () {
    final order = ExactRgbaPublicationOrder<String>();
    final predecessor = order.admit('predecessor', 0, 40)!;
    final predecessorCommit = order.commit(predecessor)!;
    final replacement = order.admit('replacement', 0, 1)!;

    expect(order.canComplete(predecessor), isFalse);
    expect(order.isCurrent(predecessorCommit), isFalse);
    expect(order.canComplete(replacement), isTrue);
    expect(order.isCurrent(order.commit(replacement)!), isTrue);
  });

  test('retirement invalidates admitted and committed work', () {
    final order = ExactRgbaPublicationOrder<String>();
    final admitted = order.admit('session', 0, 1)!;
    final committed = order.commit(admitted)!;

    order.retire();

    expect(order.canComplete(admitted), isFalse);
    expect(order.isCurrent(committed), isFalse);
    expect(order.commit(admitted), isNull);
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
