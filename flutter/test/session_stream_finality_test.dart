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
}
