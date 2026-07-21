import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('saved peers ignore retired cloud provenance', () {
    final peer = Peer.fromJson(<String, dynamic>{
      'id': '192.0.2.7:21118',
      'same_server': true,
    });

    final serialized = peer.toJson();
    expect(serialized['id'], '192.0.2.7:21118');
    expect(serialized, isNot(contains('same_server')));
  });
}
