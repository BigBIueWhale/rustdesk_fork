import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'global_event_dispatcher.dart';
import 'platform_model.dart';

class Peer {
  final String id;
  String username; // pc username
  String hostname;
  String platform;
  String alias;
  List<dynamic> tags;
  String note;

  String getId() {
    if (alias != '') {
      return alias;
    }
    return id;
  }

  Peer.fromJson(Map<String, dynamic> json)
      : id = json['id'] ?? '',
        username = json['username'] ?? '',
        hostname = json['hostname'] ?? '',
        platform = json['platform'] ?? '',
        alias = json['alias'] ?? '',
        tags = json['tags'] ?? [],
        note = json['note'] is String ? json['note'] : '';
}

class Peers extends ChangeNotifier {
  final String name;
  final String loadEvent;
  List<Peer> peers = List.empty(growable: true);
  // Part of the peers that are not in the rest peers list.
  // When there're too many peers, we may want to load the front 100 peers first,
  // so we can see peers in UI quickly. `restPeerIds` is the rest peers' ids.
  // And then load all peers later.
  List<String> restPeerIds = List.empty(growable: true);
  late final GlobalEventRegistration? _registration;
  Peers({required this.name, required this.loadEvent}) {
    _registration =
        platformFFI.registerEventHandler(loadEvent, name, (evt) async {
      updatePeers(evt);
    });
  }

  @override
  void dispose() {
    _registration?.cancel();
    super.dispose();
  }

  @visibleForTesting
  void updatePeers(Map<String, dynamic> evt) {
    final nextPeers = _decodePeers(evt['peers']);
    if (nextPeers == null) return;
    final ids = evt['ids'];
    if (ids != null && ids is! String) {
      debugPrint('peers(): invalid peer data');
      return;
    }
    final nextIds = ids is String && ids.isNotEmpty
        ? ids.split(',').map((id) => id.trim()).toList()
        : <String>[];
    if (nextIds.any((id) => id.isEmpty)) {
      debugPrint('peers(): invalid peer data');
      return;
    }

    peers = nextPeers;
    restPeerIds = nextIds;
    notifyListeners();
  }

  List<Peer>? _decodePeers(Object? peersStr) {
    try {
      if (peersStr == "") return [];
      List<dynamic> peers = json.decode(peersStr as String);
      return peers.map((peer) {
        return Peer.fromJson(peer as Map<String, dynamic>);
      }).toList();
    } catch (_) {
      debugPrint('peers(): invalid peer data');
    }
    return null;
  }
}
