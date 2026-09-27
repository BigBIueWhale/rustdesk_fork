import 'package:flutter_hbb/models/reconnect_schedule_authority.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a replaced reconnect callback can never claim the session', () {
    final authority = ReconnectScheduleAuthority();
    final predecessor = authority.replaceAutomaticRetry(requested: true)!;
    final replacement = authority.replaceAutomaticRetry(requested: true)!;

    expect(authority.claim(predecessor), isFalse);
    expect(authority.claim(replacement), isTrue);
    expect(authority.claim(replacement), isFalse);
  });

  test('credential recovery retires and suppresses generic retries', () {
    final authority = ReconnectScheduleAuthority();
    final stale = authority.replaceAutomaticRetry(requested: true)!;

    authority.requireCredentialReplacement();

    expect(authority.claim(stale), isFalse);
    expect(authority.replaceAutomaticRetry(requested: true), isNull);
  });

  test('only native connection admission ends credential recovery', () {
    final authority = ReconnectScheduleAuthority();
    authority.requireCredentialReplacement();

    expect(authority.replaceAutomaticRetry(requested: true), isNull);

    authority.acceptConnected();
    final admitted = authority.replaceAutomaticRetry(requested: true)!;
    expect(authority.claim(admitted), isTrue);
  });

  test('owner reset invalidates every callback from the old owner', () {
    final authority = ReconnectScheduleAuthority();
    final stale = authority.replaceAutomaticRetry(requested: true)!;

    authority.reset();

    expect(authority.claim(stale), isFalse);
    final current = authority.replaceAutomaticRetry(requested: true)!;
    expect(authority.claim(current), isTrue);
  });
}
