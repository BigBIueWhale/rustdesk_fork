import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const metadata = <String, dynamic>{
    'id': '192.0.2.7:21118',
    'username': 'local-user',
    'hostname': 'local-host',
    'platform': 'Linux',
    'alias': 'Local peer',
    'tags': <String>['local'],
    'rdpPort': '3389',
    'rdpUsername': 'rdp-user',
    'loginName': 'login-user',
    'note': 'Local peer note',
  };

  test('direct peers retain their address and local display metadata', () {
    final peer = Peer.fromJson(metadata);
    expect(peer.id, '192.0.2.7:21118');
    expect(peer.getId(), 'Local peer');
    expect(peer.username, 'local-user');
    expect(peer.hostname, 'local-host');
    expect(peer.platform, 'Linux');
    expect(peer.tags, ['local']);
    expect(peer.rdpPort, '3389');
    expect(peer.rdpUsername, 'rdp-user');
    expect(peer.loginName, 'login-user');
    expect(peer.note, 'Local peer note');
    peer.alias = '';
    expect(peer.getId(), peer.id);
    expect(Peer.loading().id, '...');
  });

  test('retired account metadata cannot prevent a direct peer from loading', () {
    final peer = Peer.fromJson(<String, dynamic>{
      ...metadata,
      'hash': <String, String>{'secret': 'SyntheticHash'},
      'password': <String>['SyntheticPassword'],
      'device_group_name': 17,
      'same_server': <String>['retired'],
      'access_token': <String>['SyntheticToken'],
    });
    expect(peer.id, metadata['id']);
    expect(peer.getId(), metadata['alias']);
    expect(peer.note, metadata['note']);
  });

  test('direct peers expose no retired credential or group fields', () {
    final dynamic peer = Peer.fromJson(<String, dynamic>{
      ...metadata,
      'hash': 'SyntheticHash',
      'password': 'SyntheticPassword',
      'device_group_name': 'retired-group',
    });
    for (final read in <dynamic Function()>[
      () => peer.hash,
      () => peer.password,
      () => peer.device_group_name,
    ]) {
      expect(read, throwsA(isA<NoSuchMethodError>()));
    }
  });
}
