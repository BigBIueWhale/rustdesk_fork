import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('controlled clients ignore retired role-swap state', () {
    final client = Client.fromJson(<String, dynamic>{
      'id': 7,
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
    expect(serialized, isNot(contains('from_switch')));
  });
}
