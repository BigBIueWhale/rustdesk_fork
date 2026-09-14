import 'dart:async';
import 'dart:convert';

import 'package:flutter_hbb/models/android_service_ui_state.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';

Map<String, dynamic> _clientState({
  required int id,
  required int registryGeneration,
  String peerId = 'peer',
  bool disconnected = false,
  bool inVoiceCall = false,
  bool incomingVoiceCall = false,
}) =>
    <String, dynamic>{
      'id': id,
      'registry_generation': registryGeneration,
      'authorized': true,
      'is_file_transfer': false,
      'is_view_camera': false,
      'is_terminal': false,
      'port_forward': '',
      'name': 'owner-$id',
      'peer_id': peerId,
      'keyboard': true,
      'clipboard': true,
      'audio': true,
      'file': true,
      'privacy_mode': false,
      'disconnected': disconnected,
      'in_voice_call': inVoiceCall,
      'incoming_voice_call': incomingVoiceCall,
    };

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

  test('full CM snapshot repairs same-count owner and state changes', () {
    final predecessor = Client.fromJson(
        _clientState(id: 7, registryGeneration: 19, peerId: 'old'));
    predecessor.unreadChatMessageCount.value = 4;

    final replacement = reconcileCmClientState(
      <Client>[predecessor],
      jsonEncode(<Map<String, dynamic>>[
        _clientState(id: 7, registryGeneration: 20, peerId: 'new'),
      ]),
    );

    expect(replacement.changed, isTrue);
    expect(replacement.rebuildTabs, isTrue);
    expect(replacement.clients, hasLength(1));
    expect(replacement.clients.single.registryGeneration, 20);
    expect(replacement.clients.single.peerId, 'new');
    expect(identical(replacement.clients.single, predecessor), isFalse);

    final current = replacement.clients.single;
    current.unreadChatMessageCount.value = 6;
    final stateChange = reconcileCmClientState(
      replacement.clients,
      jsonEncode(<Map<String, dynamic>>[
        _clientState(
          id: 7,
          registryGeneration: 20,
          peerId: 'new',
          disconnected: true,
          incomingVoiceCall: true,
        ),
      ]),
    );

    expect(stateChange.changed, isTrue);
    expect(stateChange.rebuildTabs, isFalse);
    expect(identical(stateChange.clients.single, current), isTrue);
    expect(stateChange.clients.single.disconnected, isTrue);
    expect(stateChange.clients.single.incomingVoiceCall, isTrue);
    expect(stateChange.clients.single.unreadChatMessageCount.value, 6);

    final unchanged = reconcileCmClientState(
      stateChange.clients,
      jsonEncode(<Map<String, dynamic>>[
        _clientState(
          id: 7,
          registryGeneration: 20,
          peerId: 'new',
          disconnected: true,
          incomingVoiceCall: true,
        ),
      ]),
    );
    expect(unchanged.changed, isFalse);
    expect(unchanged.rebuildTabs, isFalse);
  });

  test('CM snapshot validates owners before mutating live client state', () {
    final current = Client.fromJson(
        _clientState(id: 7, registryGeneration: 19, peerId: 'current'));

    expect(
      () => reconcileCmClientState(
        <Client>[current],
        jsonEncode(<Map<String, dynamic>>[
          _clientState(id: 7, registryGeneration: 20),
          _clientState(id: 7, registryGeneration: 21),
        ]),
      ),
      throwsFormatException,
    );
    expect(
      () => reconcileCmClientState(
        <Client>[current],
        jsonEncode(<Map<String, dynamic>>[
          _clientState(id: 8, registryGeneration: 19),
          _clientState(id: 9, registryGeneration: 19),
        ]),
      ),
      throwsFormatException,
    );
    expect(current.registryGeneration, 19);
    expect(current.peerId, 'current');
    expect(current.disconnected, isFalse);

    final ordered = reconcileCmClientState(
      const <Client>[],
      jsonEncode(<Map<String, dynamic>>[
        _clientState(id: 9, registryGeneration: 21),
        _clientState(id: 8, registryGeneration: 20),
      ]),
    );
    expect(
      ordered.clients.map((client) => client.registryGeneration),
      orderedEquals(<int>[20, 21]),
    );
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
