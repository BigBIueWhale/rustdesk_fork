import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:get/get.dart';
import '../../models/model.dart';
import '../../models/terminal_connection_pool.dart';

/// Manages terminal connections to ensure one FFI instance per peer
class TerminalConnectionManager {
  static final _connections = TerminalConnectionPool<FFI>();
  
  // Track service IDs per peer
  static final Map<String, String> _serviceIds = {};

  /// Get or create an FFI instance for a peer
  static FFI getConnection({
    required String peerId,
    required String? password,
    required String? connToken,
  }) {
    final tag = 'terminal_$peerId';
    final existingFfi = _connections[peerId];
    if (existingFfi != null && !existingFfi.closed) {
      if (!Get.isRegistered<FFI>(tag: tag) ||
          !identical(Get.find<FFI>(tag: tag), existingFfi) ||
          !_connections.retain(peerId, existingFfi)) {
        throw StateError('Terminal connection admission is not owned');
      }
      debugPrint('[TerminalConnectionManager] Reusing existing connection for peer $peerId. Reference count: ${_connections.referenceCount(peerId)}');
      return existingFfi;
    }

    if (Get.isRegistered<FFI>(tag: tag)) {
      if (!identical(Get.find<FFI>(tag: tag), existingFfi) ||
          !GetInstance().delete<FFI>(tag: tag)) {
        throw StateError('Terminal connection registration is not owned');
      }
    }

    // Create new FFI instance for first terminal
    debugPrint('[TerminalConnectionManager] Creating new terminal connection for peer $peerId');
    final ffi = FFI(null);
    ffi.start(
      peerId,
      password: password,
      connToken: connToken,
      isTerminal: true,
    );
    
    _connections.install(peerId, ffi);
    
    // Register the FFI instance with Get for dependency injection
    Get.put<FFI>(ffi, tag: tag);
    
    debugPrint('[TerminalConnectionManager] New connection created. Total connections: ${_connections.length}');
    return ffi;
  }

  /// Release only the connection retained by this page.
  static void releaseConnection(String peerId, FFI owner) {
    final retired = _connections.release(peerId, owner);
    if (retired == null) return;
    final tag = 'terminal_$peerId';
    try {
      if (Get.isRegistered<FFI>(tag: tag) &&
          identical(Get.find<FFI>(tag: tag), retired) &&
          !GetInstance().delete<FFI>(tag: tag)) {
        throw StateError('Terminal connection registration did not retire');
      }
    } finally {
      unawaited(retired.close().catchError((Object error, StackTrace _) {
        debugPrint('Terminal connection close failed: ${error.runtimeType}');
      }));
    }
  }

  /// Check if a connection exists for a peer
  static bool hasConnection(String peerId) {
    final ffi = _connections[peerId];
    return ffi != null && !ffi.closed;
  }
  
  /// Get existing connection without creating new one
  static FFI? getExistingConnection(String peerId) {
    return _connections[peerId];
  }

  /// Get connection count for debugging
  static int getConnectionCount() => _connections.length;
  
  /// Get terminal count for a peer
  static int getTerminalCount(String peerId) =>
      _connections.referenceCount(peerId);
  
  /// Get service ID for a peer
  static String? getServiceId(String peerId) => _serviceIds[peerId];
  
  /// Set service ID for a peer
  static void setServiceId(String peerId, String serviceId) {
    _serviceIds[peerId] = serviceId;
    debugPrint('[TerminalConnectionManager] Service ID for $peerId: $serviceId');
  }
}
