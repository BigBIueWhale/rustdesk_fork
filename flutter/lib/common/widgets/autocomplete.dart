import 'package:flutter/material.dart';
import '../../../models/platform_model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/peer_card.dart';

class AllPeersLoader {
  final Peers _recentPeers;
  final Future<void> Function() _requestLoad;
  List<Peer> peers = [];

  bool _isPeersLoading = false;
  bool _isPeersLoaded = false;
  bool _cleared = false;

  void Function(VoidCallback)? _setState;

  bool get needLoad =>
      !_cleared && _setState != null && !_isPeersLoaded && !_isPeersLoading;
  bool get isPeersLoaded => _isPeersLoaded;
  bool get isPeersLoading => _isPeersLoading;

  AllPeersLoader({Peers? recentPeers, Future<void> Function()? requestLoad})
      : _recentPeers = recentPeers ?? gFFI.recentPeersModel,
        _requestLoad = requestLoad ?? (() => bind.mainLoadRecentPeers());

  void init(void Function(VoidCallback) setState) {
    if (_cleared || _setState != null) {
      throw StateError('peer loader is already initialized or retired');
    }
    _setState = setState;
    _recentPeers.addListener(_mergeAllPeers);
  }

  void clear() {
    if (_cleared) return;
    _cleared = true;
    _recentPeers.removeListener(_mergeAllPeers);
    _setState = null;
    peers = [];
    _isPeersLoading = false;
    _isPeersLoaded = false;
  }

  Future<void> getAllPeers() async {
    if (!needLoad) {
      return;
    }
    if (_recentPeers.peers.isNotEmpty) {
      _mergeAllPeers();
      return;
    }
    _setState?.call(() => _isPeersLoading = true);
    try {
      await _requestLoad();
    } catch (_) {
      if (!_cleared && !_isPeersLoaded) {
        _setState?.call(() => _isPeersLoading = false);
      }
      rethrow;
    }
  }

  void _mergeAllPeers() {
    if (_cleared) return;
    // R-G2/R-SV6 + R-X5: a direct-IP fork has no account address book/groups and no LAN
    // discovery — the autocomplete suggests only the local Recent peers.
    List<Peer> parsedPeers = [];
    Set<String> peerIds = {};
    for (final peer in _recentPeers.peers) {
      if (!peerIds.contains(peer.id)) {
        parsedPeers.add(peer);
        peerIds.add(peer.id);
      }
    }
    for (final id in _recentPeers.restPeerIds) {
      if (!peerIds.contains(id)) {
        parsedPeers.add(Peer.fromJson({'id': id}));
        peerIds.add(id);
      }
    }

    _setState?.call(() {
      peers = parsedPeers;
      _isPeersLoading = false;
      _isPeersLoaded = true;
    });
  }
}

class AutocompletePeerTile extends StatefulWidget {
  final VoidCallback onSelect;
  final Peer peer;

  const AutocompletePeerTile({
    Key? key,
    required this.onSelect,
    required this.peer,
  }) : super(key: key);

  @override
  AutocompletePeerTileState createState() => AutocompletePeerTileState();
}

class AutocompletePeerTileState extends State<AutocompletePeerTile> {
  List _frontN<T>(List list, int n) {
    if (list.length <= n) {
      return list;
    } else {
      return list.sublist(0, n);
    }
  }

  @override
  Widget build(BuildContext context) {
    final double tileRadius = 5;
    final name =
        '${widget.peer.username}${widget.peer.username.isNotEmpty && widget.peer.hostname.isNotEmpty ? '@' : ''}${widget.peer.hostname}';
    final greyStyle = TextStyle(
        fontSize: 11,
        color: Theme.of(context).textTheme.titleLarge?.color?.withOpacity(0.6));
    final child = GestureDetector(
        onTap: () => widget.onSelect(),
        child: Padding(
            padding: EdgeInsets.only(left: 5, right: 5),
            child: Container(
                height: 42,
                margin: EdgeInsets.only(bottom: 5),
                child: Row(
                  mainAxisSize: MainAxisSize.max,
                  children: [
                    Container(
                        decoration: BoxDecoration(
                          color: str2color(
                              '${widget.peer.id}${widget.peer.platform}', 0x7f),
                          borderRadius: BorderRadius.only(
                            topLeft: Radius.circular(tileRadius),
                            bottomLeft: Radius.circular(tileRadius),
                          ),
                        ),
                        alignment: Alignment.center,
                        width: 42,
                        height: null,
                        child: Padding(
                            padding: EdgeInsets.all(6),
                            child: getPlatformImage(widget.peer.platform,
                                size: 30))),
                    Expanded(
                      child: Container(
                          padding: EdgeInsets.only(left: 10),
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.background,
                            borderRadius: BorderRadius.only(
                              topRight: Radius.circular(tileRadius),
                              bottomRight: Radius.circular(tileRadius),
                            ),
                          ),
                          child: Row(
                            children: [
                              Expanded(
                                  child: Container(
                                      margin: EdgeInsets.only(top: 2),
                                      child: Container(
                                          margin: EdgeInsets.only(top: 2),
                                          child: Column(
                                            children: [
                                              Container(
                                                  margin:
                                                      EdgeInsets.only(top: 2),
                                                  child: Row(children: [
                                                    Expanded(
                                                        child: Text(
                                                      widget.peer.alias.isEmpty
                                                          ? widget.peer.id
                                                          : widget.peer.alias,
                                                      overflow:
                                                          TextOverflow.ellipsis,
                                                      style: Theme.of(context)
                                                          .textTheme
                                                          .titleSmall,
                                                    )),
                                                    widget.peer.alias.isNotEmpty
                                                        ? Flexible(
                                                            flex: 2,
                                                            child: Padding(
                                                                padding:
                                                                    const EdgeInsets
                                                                        .only(
                                                                        left: 5,
                                                                        right: 5),
                                                                child: Text(
                                                                  "(${widget.peer.id})",
                                                                  style:
                                                                      greyStyle,
                                                                  overflow:
                                                                      TextOverflow
                                                                          .ellipsis,
                                                                )))
                                                        : Container(),
                                                  ])),
                                              Align(
                                                alignment: Alignment.centerLeft,
                                                child: Text(
                                                  name,
                                                  style: greyStyle,
                                                  textAlign: TextAlign.start,
                                                  overflow:
                                                      TextOverflow.ellipsis,
                                                ),
                                              ),
                                            ],
                                          )))),
                            ],
                          )),
                    )
                  ],
                ))));
    return Tooltip(
      message: !(isDesktop || isWebDesktop)
          ? ''
          : widget.peer.tags.isNotEmpty
              ? '${translate('Tags')}: ${widget.peer.tags.join(', ')}'
              : '',
      child: child,
    );
  }
}
