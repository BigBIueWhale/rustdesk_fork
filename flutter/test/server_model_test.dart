import 'dart:async';

import 'package:flutter_hbb/models/android_service_ui_state.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('controlled clients ignore retired role-swap state', () {
    final client = Client.fromJson(<String, dynamic>{
      'id': 7,
      'registry_generation': 19,
      'authorized': true,
      'is_file_transfer': false,
      'is_view_camera': false,
      'is_terminal': false,
      'port_forward': '',
      'name': 'owner',
      'peer_id': 'peer',
      'keyboard': true,
      'clipboard': true,
      'audio': true,
      'file': true,
      'privacy_mode': true,
      'disconnected': false,
      'from_switch': true,
      'in_voice_call': false,
      'incoming_voice_call': false,
    });

    final serialized = client.toJson();
    expect(serialized['id'], 7);
    expect(serialized['registry_generation'], 19);
    expect(serialized, isNot(contains('from_switch')));
  });

  test('Android service commands cannot manufacture observed running state',
      () async {
    final state = AndroidServiceUiState();
    final entered = Completer<void>();
    final release = Completer<void>();
    var duplicateRan = false;

    final first = state.runCommand(() async {
      entered.complete();
      await release.future;
    });
    await entered.future;

    expect(state.commandInFlight, isTrue);
    expect(state.observedRunning, isFalse);
    expect(
      await state.runCommand(() async {
        duplicateRan = true;
      }),
      isFalse,
    );
    expect(duplicateRan, isFalse);

    expect(state.observeRunning(true), isTrue);
    expect(state.observedRunning, isTrue);
    release.complete();
    expect(await first, isTrue);
    expect(state.commandInFlight, isFalse);
    expect(state.observedRunning, isTrue);
  });

  test('Android service command failure releases only the command latch',
      () async {
    final state = AndroidServiceUiState();
    state.observeRunning(true);

    await expectLater(
      state.runCommand(() async {
        throw StateError('expected command failure');
      }),
      throwsStateError,
    );

    expect(state.commandInFlight, isFalse);
    expect(state.observedRunning, isTrue);
    expect(await state.runCommand(() async {}), isTrue);
    expect(state.observeRunning(false), isTrue);
    expect(state.observeRunning(false), isFalse);
    expect(state.observedRunning, isFalse);
  });
}
