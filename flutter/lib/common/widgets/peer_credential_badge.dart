import 'package:flutter/material.dart';
import 'package:flutter_hbb/generated_bridge.dart'
    if (dart.library.html) 'package:flutter_hbb/web/bridge.dart';
import 'package:flutter_hbb/models/platform_model.dart';

class PeerCredentialBadge extends StatefulWidget {
  const PeerCredentialBadge({
    required this.peerId,
    required this.retryLabel,
    this.size = 12,
    this.readStatus,
    super.key,
  });

  final String peerId;
  final String retryLabel;
  final double size;
  final Future<PeerCredentialStatus> Function(String)? readStatus;

  @override
  State<PeerCredentialBadge> createState() => _PeerCredentialBadgeState();
}

class _PeerCredentialBadgeState extends State<PeerCredentialBadge> {
  late Future<PeerCredentialStatus> _status;
  late Object _generation;
  bool _pending = false;

  void _read() {
    final generation = Object();
    _generation = generation;
    _pending = true;
    _status = Future<PeerCredentialStatus>.sync(() {
      final read = widget.readStatus;
      return read != null
          ? read(widget.peerId)
          : bind.mainGetPeerCredentialStatus(id: widget.peerId);
    }).whenComplete(() {
      if (identical(_generation, generation)) _pending = false;
    });
  }

  @override
  void initState() {
    super.initState();
    _read();
  }

  @override
  void didUpdateWidget(covariant PeerCredentialBadge oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.peerId != widget.peerId ||
        oldWidget.readStatus != widget.readStatus) {
      _read();
    }
  }

  void _retry(Object generation) {
    if (!mounted || _pending || !identical(_generation, generation)) return;
    setState(_read);
  }

  @override
  Widget build(BuildContext context) {
    final generation = _generation;
    return FutureBuilder<PeerCredentialStatus>(
      future: _status,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const SizedBox.shrink();
        }
        if (snapshot.hasError) {
          return Tooltip(
            message: '${snapshot.error}\n${widget.retryLabel}',
            child: GestureDetector(
              onTap: () => _retry(generation),
              child: Icon(Icons.error_outline,
                  size: widget.size, color: Colors.white),
            ),
          );
        }
        return snapshot.data?.hasSavedPrs == true
            ? Icon(Icons.key, size: widget.size, color: Colors.white)
            : const SizedBox.shrink();
      },
    );
  }
}
