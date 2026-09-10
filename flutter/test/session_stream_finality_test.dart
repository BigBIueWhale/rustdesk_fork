import 'package:flutter_hbb/models/session_stream_finality.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('an exact normal-close event suppresses later stream termination', () {
    final finality = SessionStreamFinality();

    finality.acceptExpectedClose();

    expect(finality.acceptUnexpectedTermination(), isFalse);
    expect(finality.acceptUnexpectedTermination(), isFalse);
  });

  test('unexpected stream termination is admitted exactly once', () {
    final finality = SessionStreamFinality();

    expect(finality.acceptUnexpectedTermination(), isTrue);
    expect(finality.acceptUnexpectedTermination(), isFalse);
  });

  test('replacement invalidates the predecessor with the same owner', () {
    final generations = SessionStreamGeneration<String>();
    final predecessor = generations.reserve('session-a');
    final replacement = generations.reserve('session-a');

    expect(predecessor.generation, 1);
    expect(replacement.generation, 2);
    expect(generations.isCurrent(predecessor), isFalse);
    expect(generations.isCurrent(replacement), isTrue);
  });

  test('owner retirement cannot retire a different current owner', () {
    final generations = SessionStreamGeneration<String>();
    final current = generations.reserve('session-b');

    expect(generations.retireOwner('session-a'), isFalse);
    expect(generations.isCurrent(current), isTrue);
    expect(generations.retireOwner('session-b'), isTrue);
    expect(generations.isCurrent(current), isFalse);
  });
}
