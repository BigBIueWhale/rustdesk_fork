import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:bot_toast/bot_toast.dart';
import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/models/cm_file_model.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/peer_tab_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_hbb/models/desktop_render_texture.dart';
import 'package:flutter_hbb/models/terminal_model.dart';
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/utils/multi_window_manager.dart';
import 'package:image/image.dart' as img2;
import 'package:flutter_svg/flutter_svg.dart';
import 'package:get/get.dart';
import 'package:uuid/uuid.dart';
import 'package:window_manager/window_manager.dart';
import 'package:file_picker/file_picker.dart';
import 'package:vector_math/vector_math.dart' show Vector2;

import '../common.dart';
import '../utils/image.dart' as img;
import '../common/widgets/dialog.dart';
import 'display_selection_queue.dart';
import 'input_model.dart';
import 'latest_frame_queue.dart';
import 'mobile_session_start_queue.dart';
import 'platform_model.dart';
import 'rgba_publication_order.dart';
import 'session_event_queue.dart';
import 'session_stream_finality.dart';
import 'package:flutter_hbb/utils/scale.dart';

import 'package:flutter_hbb/generated_bridge.dart'
    if (dart.library.html) 'package:flutter_hbb/web/bridge.dart';
import 'package:flutter_hbb/native/custom_cursor.dart'
    if (dart.library.html) 'package:flutter_hbb/web/custom_cursor.dart';

typedef HandleMsgBox = Function(Map<String, dynamic> evt, String id);
typedef ReconnectHandle = Function(OverlayDialogManager, SessionID);
// One UUID owns the mobile Flutter isolate. Each outgoing connection receives a different UUID
// below; conflating the two lets a delayed dispose from an old route close its replacement.
final _mobileClientOwnerId = Uuid().v4obj();

class _SessionOwner {
  const _SessionOwner(this.sessionId, this.clientOwnerId);

  final SessionID sessionId;
  final SessionID clientOwnerId;

  @override
  bool operator ==(Object other) =>
      other is _SessionOwner &&
      sessionId == other.sessionId &&
      clientOwnerId == other.clientOwnerId;

  @override
  int get hashCode => Object.hash(sessionId, clientOwnerId);
}

class _WebCursorPosition {
  const _WebCursorPosition(this.x, this.y);

  final int x;
  final int y;
}

class _WebCursorShapeSource {
  const _WebCursorShapeSource({
    required this.id,
    required this.revision,
    required this.hotx,
    required this.hoty,
    required this.width,
    required this.height,
    required this.rgba,
  });

  final String id;
  final int revision;
  final int hotx;
  final int hoty;
  final int width;
  final int height;
  final Uint8List rgba;
}

class _WebCursorShape {
  const _WebCursorShape({
    required this.id,
    required this.sequence,
    this.source,
  });

  final String id;
  final int sequence;
  final _WebCursorShapeSource? source;
}

class _MobileSessionStartRequest {
  const _MobileSessionStartRequest({
    required this.sessionId,
    required this.peerId,
    required this.isFileTransfer,
    required this.isViewCamera,
    required this.isPortForward,
    required this.isRdp,
    required this.isTerminal,
    required this.password,
    required this.isSharedPassword,
    required this.connToken,
  });

  final SessionID sessionId;
  final String peerId;
  final bool isFileTransfer;
  final bool isViewCamera;
  final bool isPortForward;
  final bool isRdp;
  final bool isTerminal;
  final String password;
  final bool isSharedPassword;
  final String? connToken;
}

const int kMaxRemoteCursorPixels = 1024 * 1024;
const int kMaxRemoteCursorRgbaBytes = kMaxRemoteCursorPixels * 4;
const int kCursorShapeCacheMaxEntries = 64;
const int kCursorShapeCacheMaxRgbaBytes = 16 * 1024 * 1024;
const String _maxRemoteCursorId = '18446744073709551615';
const int _minSigned32 = -0x80000000;
const int _maxSigned32 = 0x7fffffff;
const _orderedSessionTopologyEvents = <String>{
  'peer_info',
  'sync_peer_info',
  'sync_platform_additions',
  'switch_display',
  'follow_current_display',
  'use_texture_render',
};

int? _webCursorCoordinate(Object? value) {
  final parsed = value is int
      ? value
      : value is String
          ? int.tryParse(value)
          : null;
  if (parsed == null || parsed < _minSigned32 || parsed > _maxSigned32) {
    return null;
  }
  return parsed;
}

int? _remoteCursorRgbaLen(int width, int height) {
  if (width <= 0 || height <= 0) {
    return null;
  }
  final pixels = width * height;
  if (pixels > kMaxRemoteCursorPixels) {
    return null;
  }
  return pixels * 4;
}

bool _isRemoteCursorId(String id) {
  if (id.isEmpty || id.length > _maxRemoteCursorId.length) {
    return false;
  }
  for (final codeUnit in id.codeUnits) {
    if (codeUnit < 0x30 || codeUnit > 0x39) {
      return false;
    }
  }
  if (id.codeUnitAt(0) == 0x30) {
    return false;
  }
  return id.length < _maxRemoteCursorId.length ||
      id.compareTo(_maxRemoteCursorId) <= 0;
}

class CachedPeerData {
  Map<String, dynamic> updatePrivacyMode = {};
  Map<String, dynamic> peerInfo = {};
  Map<String, bool> permissions = {};

  // R-G3: the `secure`/`direct` cache fields are removed — the fork's channel is always
  // PAKE-keyed and direct (§10 / R-SV4-R-D4), so the badge is a fixed secure-direct indicator
  // that reads neither. Only `streamType` (the "via TCP" suffix) is retained.
  String streamType = '';

  CachedPeerData();

  @override
  String toString() {
    return jsonEncode({
      'updatePrivacyMode': updatePrivacyMode,
      'peerInfo': peerInfo,
      'permissions': permissions,
      'streamType': streamType,
    });
  }

  static CachedPeerData? fromString(String s) {
    try {
      final map = jsonDecode(s);
      final data = CachedPeerData();
      data.updatePrivacyMode = map['updatePrivacyMode'];
      data.peerInfo = map['peerInfo'];
      map['permissions'].forEach((key, value) {
        data.permissions[key] = value;
      });
      data.streamType = map['streamType'];
      return data;
    } catch (e) {
      debugPrint('Failed to parse CachedPeerData: $e');
      return null;
    }
  }
}

class FfiModel with ChangeNotifier {
  CachedPeerData cachedPeerData = CachedPeerData();
  PeerInfo _pi = PeerInfo();
  Rect? _rect;
  int _displayTopologyRevision = 0;

  var _inputBlocked = false;
  final _permissions = <String, bool>{};
  // R-G3: `_secure`/`_direct` badge state removed. `_connectionTypeReceived` is a UI-readiness
  // flag (not a security-state field) gating whether the fixed secure-direct badge is shown yet.
  bool _connectionTypeReceived = false;
  bool _touchMode = false;
  late VirtualMouseMode virtualMouseMode;
  Timer? _timer;
  var _reconnects = 1;
  DateTime? _offlineReconnectStartTime;
  bool _viewOnly = false;
  bool _showMyCursor = false;
  int? _eventListenerGeneration;
  SessionID? _eventListenerSessionId;
  WeakReference<FFI> parent;
  SessionID get sessionId => parent.target!.sessionId;

  RxBool waitForImageDialogShow = true.obs;
  Timer? waitForImageTimer;
  RxBool waitForFirstImage = true.obs;
  bool isRefreshing = false;

  Timer? timerScreenshot;

  Rect? get rect => _rect;
  bool get isOriginalResolutionSet =>
      _pi.tryGetDisplayIfNotAllDisplay()?.isOriginalResolutionSet ?? false;
  bool get isVirtualDisplayResolution =>
      _pi.tryGetDisplayIfNotAllDisplay()?.isVirtualDisplayResolution ?? false;
  bool get isOriginalResolution =>
      _pi.tryGetDisplayIfNotAllDisplay()?.isOriginalResolution ?? false;

  Map<String, bool> get permissions => _permissions;
  setPermissions(Map<String, bool> permissions) {
    _permissions.clear();
    _permissions.addAll(permissions);
  }

  PeerInfo get pi => _pi;

  bool get inputBlocked => _inputBlocked;

  bool get touchMode => _touchMode;

  bool get isPeerAndroid => _pi.platform == kPeerPlatformAndroid;
  bool get isPeerMobile => isPeerAndroid;

  bool get isPeerLinux => _pi.platform == kPeerPlatformLinux;

  bool get viewOnly => _viewOnly;
  bool get showMyCursor => _showMyCursor;

  set inputBlocked(v) {
    _inputBlocked = v;
  }

  FfiModel(this.parent) {
    clear();
    virtualMouseMode = VirtualMouseMode(this);
  }

  bool _isCurrentSession(SessionID expectedSessionId) =>
      parent.target?.isCurrentSession(expectedSessionId) == true;

  int? _beginDisplayTopologyMutation(SessionID expectedSessionId) {
    if (!_isCurrentSession(expectedSessionId)) {
      return null;
    }
    return ++_displayTopologyRevision;
  }

  int? currentDisplayTopologyRevision(SessionID expectedSessionId) =>
      _isCurrentSession(expectedSessionId) ? _displayTopologyRevision : null;

  bool isCurrentDisplayTopology(
          SessionID expectedSessionId, int expectedRevision) =>
      _isCurrentSession(expectedSessionId) &&
      _displayTopologyRevision == expectedRevision;

  Rect? globalDisplaysRect() => _getDisplaysRect(_pi.displays, true);
  Rect? displaysRect() => _getDisplaysRect(_pi.getCurDisplays(), false);
  Rect? _getDisplaysRect(List<Display> displays, bool useDisplayScale) {
    if (displays.isEmpty) {
      return null;
    }
    if (isPeerLinux) {
      useDisplayScale = true;
    }
    int scale(int len, double s) {
      if (useDisplayScale) {
        return len.toDouble() ~/ s;
      } else {
        return len;
      }
    }

    double l = displays[0].x;
    double t = displays[0].y;
    double r = displays[0].x + scale(displays[0].width, displays[0].scale);
    double b = displays[0].y + scale(displays[0].height, displays[0].scale);
    for (var display in displays.sublist(1)) {
      l = min(l, display.x);
      t = min(t, display.y);
      r = max(r, display.x + scale(display.width, display.scale));
      b = max(b, display.y + scale(display.height, display.scale));
    }
    return Rect.fromLTRB(l, t, r, b);
  }

  toggleTouchMode() {
    if (!isPeerAndroid) {
      _touchMode = !_touchMode;
      notifyListeners();
    }
  }

  updatePermission(Map<String, dynamic> evt, String id) {
    // Track previous keyboard permission to detect revocation.
    final hadKeyboardPerm = _permissions['keyboard'] != false;

    evt.forEach((k, v) {
      if (k == 'name' || k.isEmpty) return;
      _permissions[k] = v == 'true';
    });
    // Only inited at remote page
    if (parent.target?.connType == ConnType.defaultConn) {
      KeyboardEnabledState.find(id).value = _permissions['keyboard'] != false;
    }

    // If keyboard permission was revoked while relative mouse mode is active,
    // forcefully disable relative mouse mode to prevent the user from being trapped.
    final hasKeyboardPerm = _permissions['keyboard'] != false;
    if (hadKeyboardPerm && !hasKeyboardPerm) {
      final inputModel = parent.target?.inputModel;
      if (inputModel != null && inputModel.relativeMouseMode.value) {
        inputModel.setRelativeMouseMode(false);
        showToast(translate('rel-mouse-permission-lost-tip'));
      }
    }

    debugPrint('updatePermission: $_permissions');
    notifyListeners();
  }

  bool get keyboard => _permissions['keyboard'] != false;

  clear() {
    ++_displayTopologyRevision;
    cachedPeerData = CachedPeerData();
    _pi = PeerInfo();
    _rect = null;
    _connectionTypeReceived = false;
    _inputBlocked = false;
    _touchMode = false;
    _reconnects = 1;
    _offlineReconnectStartTime = null;
    _viewOnly = false;
    _showMyCursor = false;
    _timer?.cancel();
    _timer = null;
    clearPermissions();
    cachedPeerData.permissions = _permissions;
    waitForImageTimer?.cancel();
    waitForImageTimer = null;
    waitForImageDialogShow.value = true;
    waitForFirstImage.value = true;
    isRefreshing = false;
    timerScreenshot?.cancel();
    timerScreenshot = null;
  }

  setConnectionType(String peerId, String streamType) {
    cachedPeerData.streamType = streamType;
    _connectionTypeReceived = true;
    try {
      var connectionType = ConnectionTypeState.find(peerId);
      connectionType.setStreamType(streamType);
    } catch (e) {
      //
    }
  }

  Widget? getConnectionImageText() {
    if (!_connectionTypeReceived) {
      return null;
    } else {
      // R-G3: always the secure-direct badge. The insecure / secure_relay / insecure_relay
      // assets are deleted and those states are structurally impossible (§10 PAKE-keyed +
      // R-SV4/R-D4 direct-only), so the inherited dynamic `assets/$icon.svg` here would both
      // MISLABEL the channel's actual guarantee AND load a deleted asset (broken render). Mirror
      // the desktop badges (remote_tab_page.dart:181) + getConnectionText (common.dart:4029),
      // which already collapse the four secure×direct branches to the one reachable state.
      final iconWidget =
          SvgPicture.asset('assets/secure.svg', width: 48, height: 48);
      String connectionText = getConnectionText(cachedPeerData.streamType);
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          iconWidget,
          SizedBox(height: 4),
          Text(
            connectionText,
            style: TextStyle(fontSize: 12),
            textAlign: TextAlign.center,
          ),
        ],
      );
    }
  }

  clearPermissions() {
    _inputBlocked = false;
    _permissions.clear();
  }

  Future<void> handleCachedPeerData(
      CachedPeerData data, String peerId, SessionID expectedSessionId) async {
    if (!_isCurrentSession(expectedSessionId)) return;
    handleMsgBox({
      'type': 'success',
      'title': 'Successful',
      'text': kMsgboxTextWaitingForImage,
      'link': '',
    }, expectedSessionId, peerId);
    await updatePrivacyMode(data.updatePrivacyMode, expectedSessionId, peerId);
    if (!_isCurrentSession(expectedSessionId)) return;
    setConnectionType(peerId, data.streamType);
    await handlePeerInfo(data.peerInfo, peerId, true, expectedSessionId);
  }

  // todo: why called by two position
  StreamEventHandler startEventListener(SessionID sessionId, String peerId) {
    final expectedClientOwnerId = parent.target!.clientOwnerId;
    return (evt) {
      if (!_isCurrentSession(sessionId)) return null;
      final name = evt['name'];
      final operation = () => _handleSessionEvent(evt, sessionId, peerId);
      if (name == 'cursor_position' && isWeb) {
        final ffi = parent.target;
        final x = _webCursorCoordinate(evt['x']);
        final y = _webCursorCoordinate(evt['y']);
        if (ffi == null || x == null || y == null) {
          ffi?._reportSessionStreamFailure(sessionId, peerId,
              'The remote session state became inconsistent');
          return null;
        }
        ffi.submitWebCursorPosition(
            sessionId, expectedClientOwnerId, peerId, x, y);
        return null;
      }
      if ((name == 'cursor_data' || name == 'cursor_id') && isWeb) {
        final ffi = parent.target;
        final shape = ffi?.cursorModel.admitWebCursorShape(evt, sessionId);
        if (ffi == null || shape == null) {
          ffi?._reportSessionStreamFailure(sessionId, peerId,
              'The remote session state became inconsistent');
          return null;
        }
        ffi.submitWebCursorShape(
            sessionId, expectedClientOwnerId, peerId, shape);
        return null;
      }
      if (name == 'cursor_position' ||
          name == 'cursor_data' ||
          name == 'cursor_id') {
        parent.target?._reportSessionStreamFailure(sessionId, peerId,
            'The remote session state became inconsistent');
        return null;
      }
      if (name is String && _orderedSessionTopologyEvents.contains(name)) {
        final ffi = parent.target;
        if (ffi == null) return null;
        return _submitOrderedSessionTopologyEvent(
            ffi, sessionId, expectedClientOwnerId, peerId, operation);
      }
      return operation();
    };
  }

  Future<void> _submitOrderedSessionTopologyEvent(
      FFI ffi,
      SessionID sessionId,
      SessionID expectedClientOwnerId,
      String peerId,
      Future<void> Function() operation) async {
    try {
      await ffi.submitSessionEvent(
          sessionId, expectedClientOwnerId, operation);
    } catch (error) {
      debugPrint('Ordered session topology failed: ${error.runtimeType}');
      ffi._reportSessionStreamFailure(sessionId, peerId,
          'The remote session state became inconsistent');
    }
  }

  Future<void> _handleSessionEvent(Map<String, dynamic> evt,
      SessionID sessionId, String peerId) async {
    if (!_isCurrentSession(sessionId)) return;
    var name = evt['name'];
    if (name == 'msgbox') {
      handleMsgBox(evt, sessionId, peerId);
    } else if (name == 'toast') {
      handleToast(evt, sessionId, peerId);
    } else if (name == 'set_multiple_windows_session') {
      handleMultipleWindowsSession(evt, sessionId, peerId);
    } else if (name == 'peer_info') {
      await handlePeerInfo(evt, peerId, false, sessionId);
    } else if (name == 'sync_peer_info') {
      await handleSyncPeerInfo(evt, sessionId, peerId);
    } else if (name == 'sync_platform_additions') {
      await handlePlatformAdditions(evt, sessionId, peerId);
    } else if (name == 'connection_ready') {
      // R-G3: the peer's secure/direct wire flags are ignored — the channel is always
      // PAKE-keyed + direct, so only the stream type (badge suffix) is consumed.
      setConnectionType(peerId, evt['stream_type'] ?? '');
    } else if (name == 'switch_display') {
      // switch display is kept for backward compatibility
      await handleSwitchDisplay(evt, sessionId, peerId);
    } else if (name == 'clipboard') {
      Clipboard.setData(ClipboardData(text: evt['content']));
    } else if (name == 'permission') {
      updatePermission(evt, peerId);
    } else if (name == 'chat_client_mode') {
      parent.target?.chatModel
          .receive(ChatModel.clientModeID, evt['text'] ?? '');
    } else if (name == 'chat_server_mode') {
      parent.target?.chatModel
          .receive(int.parse(evt['id'] as String), evt['text'] ?? '');
    } else if (name == 'terminal_response') {
      parent.target?.routeTerminalResponse(evt);
    } else if (name == 'file_dir') {
      parent.target?.fileModel.receiveFileDir(evt, sessionId);
    } else if (name == 'empty_dirs') {
      parent.target?.fileModel.receiveEmptyDirs(evt, sessionId);
    } else if (name == 'job_progress') {
      parent.target?.fileModel.jobController.tryUpdateJobProgress(evt);
    } else if (name == 'job_done') {
      bool? refresh =
          await parent.target?.fileModel.jobController.jobDone(evt);
      if (_isCurrentSession(sessionId) && refresh == true) {
        // many job done for delete directory
        // todo: refresh may not work when confirm delete local directory
        parent.target?.fileModel.refreshAll();
      }
    } else if (name == 'job_error') {
      parent.target?.fileModel.handleJobError(evt, sessionId);
    } else if (name == 'override_file_confirm') {
      final ffi = parent.target;
      if (ffi != null &&
          !ffi.fileModel.postOverrideFileConfirm(evt, sessionId)) {
        ffi.reportFileDialogFailure(sessionId);
      }
    } else if (name == 'load_last_job') {
      parent.target?.fileModel.jobController.loadLastJob(evt);
    } else if (name == 'update_folder_files') {
      parent.target?.fileModel.jobController.updateFolderFiles(evt);
    } else if (name == 'add_connection') {
      parent.target?.serverModel.addConnection(evt);
    } else if (name == 'on_client_remove') {
      parent.target?.serverModel.onClientRemove(evt);
    } else if (name == 'update_quality_status') {
      parent.target?.qualityMonitorModel.updateQualityStatus(evt);
    } else if (name == 'update_block_input_state') {
      updateBlockInputState(evt, peerId);
    } else if (name == 'update_privacy_mode') {
      await updatePrivacyMode(evt, sessionId, peerId);
    } else if (name == 'cancel_msgbox') {
      cancelMsgBox(evt, sessionId);
    } else if (name == 'on_url_scheme_received') {
      // currently comes from desktop URL IPC
      onUrlSchemeReceived(evt);
    } else if (name == 'on_desktop_instance_activate_requested') {
      onDesktopInstanceActivateRequested();
    } else if (name == 'on_desktop_instances_close_requested') {
      onDesktopInstancesCloseRequested();
    } else if (name == 'on_voice_call_waiting') {
      // Waiting for the response from the peer.
      parent.target?.chatModel.onVoiceCallWaiting();
    } else if (name == 'on_voice_call_started') {
      // Voice call is connected.
      parent.target?.chatModel.onVoiceCallStarted();
    } else if (name == 'on_voice_call_closed') {
      // Voice call is closed with reason.
      final reason = evt['reason'].toString();
      parent.target?.chatModel.onVoiceCallClosed(reason);
    } else if (name == 'on_voice_call_incoming') {
      // Voice call is requested by the peer.
      parent.target?.chatModel.onVoiceCallIncoming();
    } else if (name == 'update_voice_call_state') {
      parent.target?.serverModel.updateVoiceCallState(evt);
    } else if (name == "cm_file_transfer_log") {
      if (isDesktop) {
        gFFI.cmFileModel.onFileTransferLog(evt);
      }
    } else if (name == 'sync_peer_option') {
      _handleSyncPeerOption(evt, peerId);
    } else if (name == 'follow_current_display') {
      await handleFollowCurrentDisplay(evt, sessionId, peerId);
    } else if (name == 'use_texture_render') {
      _handleUseTextureRender(evt, sessionId, peerId);
    } else if (name == "selected_files") {
      if (isWeb) {
        parent.target?.fileModel.onSelectedFiles(evt);
      }
    } else if (name == "send_emptry_dirs") {
      if (isWeb) {
        final future = parent.target?.fileModel.sendEmptyDirs(evt);
        if (future != null) {
          unawaited(future.catchError((Object error) {
            debugPrint('Failed to create remote empty directories: $error');
          }));
        }
      }
    } else if (name == "record_status") {
      if (desktopType == DesktopType.remote ||
          desktopType == DesktopType.viewCamera ||
          isMobile) {
        parent.target?.recordingModel.updateStatus(evt['start'] == 'true');
      }
    } else if (name == 'screenshot') {
      _handleScreenshot(evt, sessionId, peerId);
    } else if (name == 'exit_relative_mouse_mode') {
      // Handle exit shortcut from rdev grab loop (Ctrl+Alt on Win/Linux, Cmd+G on macOS)
      parent.target?.inputModel.exitRelativeMouseModeWithKeyRelease();
    } else {
      debugPrint('Event is not handled in the fixed branch: $name');
    }
  }

  _handleScreenshot(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) {
    if (!_isCurrentSession(sessionId)) return;
    timerScreenshot?.cancel();
    timerScreenshot = null;
    final msg = evt['msg'] ?? '';
    final screenshotId = evt['screenshot_id'] ?? '';
    final msgBoxType = 'custom-nook-nocancel-hasclose';
    final msgBoxTitle = 'Take screenshot';
    final dialogManager = parent.target!.dialogManager;
    if (msg.isNotEmpty) {
      msgBox(sessionId, msgBoxType, msgBoxTitle, msg, '', dialogManager);
    } else {
      final msgBoxText = 'screenshot-action-tip';

      close() {
        if (!_isCurrentSession(sessionId)) return;
        dialogManager.dismissAll();
      }

      saveAs() {
        if (!_isCurrentSession(sessionId)) return;
        close();
        Future.delayed(Duration.zero, () async {
          if (!_isCurrentSession(sessionId)) return;
          final ts = DateTime.now().millisecondsSinceEpoch ~/ 1000;
          String? outputFile = await FilePicker.platform.saveFile(
            dialogTitle: '${translate('Save as')}...',
            fileName: 'screenshot_$ts.png',
            allowedExtensions: ['png'],
            type: FileType.custom,
          );
          if (!_isCurrentSession(sessionId)) return;
          if (outputFile == null) {
            bind.sessionHandleScreenshot(
                sessionId: sessionId, screenshotId: screenshotId, action: '2');
          } else {
            final res = await bind.sessionHandleScreenshot(
                sessionId: sessionId,
                screenshotId: screenshotId,
                action: '0:$outputFile');
            if (!_isCurrentSession(sessionId)) return;
            if (res.isNotEmpty) {
              msgBox(sessionId, 'custom-nook-nocancel-hasclose-error',
                  'Take screenshot', res, '', dialogManager);
            }
          }
        });
      }

      copyToClipboard() {
        if (!_isCurrentSession(sessionId)) return;
        bind.sessionHandleScreenshot(
            sessionId: sessionId, screenshotId: screenshotId, action: '1');
        close();
      }

      cancel() {
        if (!_isCurrentSession(sessionId)) return;
        bind.sessionHandleScreenshot(
            sessionId: sessionId, screenshotId: screenshotId, action: '2');
        close();
      }

      final List<Widget> buttons = [
        dialogButton('${translate('Save as')}...', onPressed: saveAs),
        dialogButton('Copy to clipboard', onPressed: copyToClipboard),
        dialogButton('Cancel', onPressed: cancel),
      ];
      dialogManager.dismissAll();
      dialogManager.show(
        (setState, close, context) => CustomAlertDialog(
          title: null,
          content: SelectionArea(
              child: msgboxContent(msgBoxType, msgBoxTitle, msgBoxText)),
          actions: buttons,
        ),
        tag: '$msgBoxType-$msgBoxTitle-$msgBoxTitle',
      );
    }
  }

  _handleUseTextureRender(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) {
    if (_beginDisplayTopologyMutation(sessionId) == null) return;
    parent.target?.imageModel.setUseTextureRender(evt['v'] == 'Y');
    waitForFirstImage.value = true;
    isRefreshing = true;
    showConnectedWaitingForImage(parent.target!.dialogManager, sessionId,
        'success', 'Successful', kMsgboxTextWaitingForImage);
  }

  _handleSyncPeerOption(Map<String, dynamic> evt, String peer) {
    final k = evt['k'];
    final v = evt['v'];
    if (k == kOptionToggleViewOnly) {
      setViewOnly(peer, v as bool);
    } else if (k == 'keyboard_mode') {
      parent.target?.inputModel.updateKeyboardMode();
    } else if (k == 'input_source') {
      stateGlobal.getInputSource(force: true);
    }
  }

  onUrlSchemeReceived(Map<String, dynamic> evt) {
    final url = evt['url'].toString().trim();
    if (!url.startsWith(bind.mainUriPrefixSync()) ||
        !handleUriLink(uriString: url)) {
      debugPrint("Rejected malformed desktop URL IPC event.");
    }
  }

  onDesktopInstanceActivateRequested() {
    windowOnTop(null);
  }

  onDesktopInstancesCloseRequested() {
    debugPrint("closing all instances");
    Future.microtask(() async {
      await rustDeskWinManager.closeAllSubWindows();
      windowManager.close();
    });
  }

  /// Bind the event listener to receive events from the Rust core.
  updateEventListener(SessionID sessionId, String peerId) {
    final ffi = parent.target;
    if (ffi == null) {
      return;
    }
    final generation = platformFFI.setEventCallback(
      startEventListener(sessionId, peerId),
      onFailure: (error, stackTrace) {
        debugPrint('Global event handoff failed: ${error.runtimeType}');
        ffi._reportSessionStreamFailure(sessionId, peerId,
            'The remote session state became inconsistent');
      },
    );
    _eventListenerGeneration = generation;
    _eventListenerSessionId = sessionId;
  }

  void retireEventListener(SessionID expectedSessionId) {
    if (_eventListenerSessionId != expectedSessionId) {
      return;
    }
    final generation = _eventListenerGeneration;
    if (generation != null) {
      platformFFI.clearEventCallback(generation);
    }
    _eventListenerGeneration = null;
    _eventListenerSessionId = null;
  }

  handleAliasChanged(Map<String, dynamic> evt) {
    if (!(isDesktop || isWebDesktop)) return;
    final String peerId = evt['id'];
    final String alias = evt['alias'];
    String label = getDesktopTabLabel(peerId, alias);
    final rxTabLabel = PeerStringOption.find(evt['id'], 'tabLabel');
    if (rxTabLabel.value != label) {
      rxTabLabel.value = label;
    }
  }

  Future<bool> updateCurDisplay(
      SessionID sessionId, int expectedTopologyRevision,
      {updateCursorPos = false}) async {
    final ffi = parent.target;
    if (ffi == null ||
        !ffi.isCurrentSession(sessionId) ||
        !isCurrentDisplayTopology(sessionId, expectedTopologyRevision)) {
      return false;
    }
    final expectedClientOwnerId = ffi.clientOwnerId;
    final newRect = displaysRect();
    if (newRect == null) {
      return isCurrentDisplayTopology(sessionId, expectedTopologyRevision);
    }
    if (newRect != _rect) {
      if (newRect.left != _rect?.left || newRect.top != _rect?.top) {
        parent.target?.cursorModel.updateDisplayOrigin(
            newRect.left, newRect.top,
            updateCursorPos: updateCursorPos);
      }
      _rect = newRect;
      // Await updateViewStyle to ensure view geometry is fully updated before
      // updating pointer lock center. This prevents stale center calculations.
      await parent.target?.canvasModel.updateViewStyle(
          refreshMousePos: updateCursorPos,
          expectedSessionId: sessionId,
          expectedDisplayTopologyRevision: expectedTopologyRevision);
      if (!ffi.isCurrentSessionOwner(sessionId, expectedClientOwnerId) ||
          !isCurrentDisplayTopology(sessionId, expectedTopologyRevision)) {
        return false;
      }
      await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);

      // Keep pointer lock center in sync when using relative mouse mode.
      // Note: updatePointerLockCenter is async-safe (handles errors internally),
      // so we fire-and-forget here.
      final inputModel = parent.target?.inputModel;
      if (inputModel != null && inputModel.relativeMouseMode.value) {
        inputModel.updatePointerLockCenter();
      }
    }
    return isCurrentDisplayTopology(sessionId, expectedTopologyRevision);
  }

  Future<void> handleSwitchDisplay(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) async {
    final topologyRevision = _beginDisplayTopologyMutation(sessionId);
    if (topologyRevision == null) return;
    final display = int.parse(evt['display']);

    if (_pi.currentDisplay != kAllDisplayValue) {
      if (bind.peerGetSessionsCount(
              id: peerId, connType: parent.target!.connType.index) >
          1) {
        if (display != _pi.currentDisplay) {
          return;
        }
      }
      if (!_pi.isSupportMultiUiSession) {
        _pi.currentDisplay = display;
      }
      // If `isSupportMultiUiSession` is true, the switch display message should not be used to update current display.
      // It is only used to update the display info.
    }

    var newDisplay = Display();
    newDisplay.x = double.tryParse(evt['x']) ?? newDisplay.x;
    newDisplay.y = double.tryParse(evt['y']) ?? newDisplay.y;
    newDisplay.width = int.tryParse(evt['width']) ?? newDisplay.width;
    newDisplay.height = int.tryParse(evt['height']) ?? newDisplay.height;
    newDisplay.cursorEmbedded = int.tryParse(evt['cursor_embedded']) == 1;
    newDisplay.originalWidth = int.tryParse(
            evt['original_width'] ?? kInvalidResolutionValue.toString()) ??
        kInvalidResolutionValue;
    newDisplay.originalHeight = int.tryParse(
            evt['original_height'] ?? kInvalidResolutionValue.toString()) ??
        kInvalidResolutionValue;
    newDisplay._scale = _pi.scaleOfDisplay(display);
    _pi.displays[display] = newDisplay;

    if (!_pi.isSupportMultiUiSession || _pi.currentDisplay == display) {
      if (!await updateCurDisplay(sessionId, topologyRevision)) return;
    }
    if (!isCurrentDisplayTopology(sessionId, topologyRevision)) {
      return;
    }

    if (!_pi.isSupportMultiUiSession) {
      try {
        CurrentDisplayState.find(peerId).value = display;
      } catch (e) {
        //
      }
    }

    if (!_pi.isSupportMultiUiSession || _pi.currentDisplay == display) {
      handleResolutions(peerId, evt['resolutions']);
    }
    notifyListeners();
  }

  cancelMsgBox(Map<String, dynamic> evt, SessionID sessionId) {
    if (parent.target == null) return;
    final dialogManager = parent.target!.dialogManager;
    final tag = '$sessionId-${evt['tag']}';
    dialogManager.dismissByTag(tag);
  }

  handleMultipleWindowsSession(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) {
    if (parent.target == null) return;
    final dialogManager = parent.target!.dialogManager;
    final sessions = evt['windows_sessions'];
    final title = translate('Multiple Windows sessions found');
    final text = translate('Please select the session you want to connect to');
    final type = "";

    showWindowsSessionsDialog(
        type, title, text, dialogManager, sessionId, peerId, sessions);
  }

  /// Handle the message box event based on [evt] and [id].
  handleMsgBox(Map<String, dynamic> evt, SessionID sessionId, String peerId) {
    if (parent.target == null) return;
    final dialogManager = parent.target!.dialogManager;
    final type = evt['type'];
    final title = evt['title'];
    final text = evt['text'];
    final link = evt['link'];

    // Disable relative mouse mode on any error-type message to ensure cursor is released.
    // This includes connection errors, session-ending messages, elevation errors, etc.
    // Safety: releasing pointer lock on errors prevents the user from being stuck.
    if (title == 'Connection Error' ||
        type == 'error' ||
        type == 'restarting' ||
        (type is String && type.contains('error'))) {
      parent.target?.inputModel.setRelativeMouseMode(false);
    }

    if (type == 'connect-password-prompt') {
      // R-S13/A3 (prompt-before-keying): the CPace keying needs the box's password up front;
      // a bare-ID first connect has none, so the keying fails and routes here. Enter it →
      // store + reconnect → key with it. `text` carries the reason (a wrong password, or a box
      // re-provisioned with a new password), so a legitimately re-provisioned box does not dead-end.
      // (There is no post-keying `input-password`/`re-input-password` re-prompt: CPace is the sole
      // authenticator — R-A1 — so the responder never asks to re-enter a login password.)
      enterConnectPasswordDialog(sessionId, dialogManager, text);
    } else if (type == 'restarting') {
      showMsgBox(sessionId, type, title, text, link, false, dialogManager,
          hasCancel: false);
    } else if (text == kMsgboxTextWaitingForImage) {
      showConnectedWaitingForImage(dialogManager, sessionId, type, title, text);
    } else if (title == 'Privacy mode') {
      final hasRetry = evt['hasRetry'] == 'true';
      showPrivacyFailedDialog(
          sessionId, type, title, text, link, hasRetry, dialogManager);
    } else {
      var hasRetry = evt['hasRetry'] == 'true';
      if (!hasRetry) {
        hasRetry = shouldAutoRetryOnOffline(type, title, text);
      }
      showMsgBox(sessionId, type, title, text, link, hasRetry, dialogManager);
    }
  }

  /// Auto-retry check for "Remote desktop is offline" error.
  /// returns true to auto-retry, false otherwise.
  bool shouldAutoRetryOnOffline(
    String type,
    String title,
    String text,
  ) {
    if (type == 'error' &&
        title == 'Connection Error' &&
        text == 'Remote desktop is offline' &&
        _pi.isSet.isTrue) {
      // Auto retry for ~30s (server's peer offline threshold) when controlled peer's account changes
      // (e.g., signout, switch user, login into OS) causes temporary offline via websocket/tcp connection.
      // The actual wait may exceed 30s (e.g., 20s elapsed + 16s next retry = 36s), which is acceptable
      // since the controlled side reconnects quickly after account changes.
      // Uses time-based check instead of _reconnects count because user can manually retry.
      // https://github.com/rustdesk/rustdesk/discussions/14048
      if (_offlineReconnectStartTime == null) {
        // First offline, record time and start retry
        _offlineReconnectStartTime = DateTime.now();
        return true;
      } else {
        final elapsed =
            DateTime.now().difference(_offlineReconnectStartTime!).inSeconds;
        if (elapsed < 30) {
          return true;
        }
      }
    }
    return false;
  }

  handleToast(Map<String, dynamic> evt, SessionID sessionId, String peerId) {
    final type = evt['type'] ?? 'info';
    final text = evt['text'] ?? '';
    final durMsc = evt['dur_msec'] ?? 2000;
    final duration = Duration(milliseconds: durMsc);
    if ((text).isEmpty) {
      BotToast.showLoading(
        duration: duration,
        clickClose: true,
        allowClick: true,
      );
    } else {
      if (type.contains('error')) {
        BotToast.showText(
          contentColor: Colors.red,
          text: translate(text),
          duration: duration,
          clickClose: true,
          onlyOne: true,
        );
      } else {
        BotToast.showText(
          text: translate(text),
          duration: duration,
          clickClose: true,
          onlyOne: true,
        );
      }
    }
  }

  /// Show a message box with [type], [title] and [text].
  showMsgBox(SessionID sessionId, String type, String title, String text,
      String link, bool hasRetry, OverlayDialogManager dialogManager,
      {bool? hasCancel}) async {
    // R-SV/R-G4: the audit note-at-close prompt is removed (the audit GUID is never
    // fetched, so this path only ever fell through to the plain msgBox).
    msgBox(sessionId, type, title, text, link, dialogManager,
        hasCancel: hasCancel,
        reconnect: hasRetry ? reconnect : null,
        reconnectTimeout: hasRetry ? _reconnects : null);
    _timer?.cancel();
    if (hasRetry) {
      _timer = Timer(Duration(seconds: _reconnects), () {
        if (!_isCurrentSession(sessionId)) return;
        reconnect(dialogManager, sessionId);
      });
      _reconnects *= 2;
    } else {
      _reconnects = 1;
      _offlineReconnectStartTime = null;
    }
  }

  void reconnect(OverlayDialogManager dialogManager, SessionID sessionId) {
    if (!_isCurrentSession(sessionId)) return;
    // Disable relative mouse mode before reconnecting to ensure cursor is released.
    parent.target?.inputModel.setRelativeMouseMode(false);
    bind.sessionReconnect(sessionId: sessionId);
    clearPermissions();
    dialogManager.dismissAll();
    dialogManager.showLoading(translate('Connecting...'),
        onCancel: closeConnection);
  }

  void showConnectedWaitingForImage(OverlayDialogManager dialogManager,
      SessionID sessionId, String type, String title, String text) {
    onClose() {
      closeConnection();
    }

    if (waitForFirstImage.isFalse) return;
    dialogManager.show(
      (setState, close, context) => CustomAlertDialog(
          title: null,
          content: SelectionArea(child: msgboxContent(type, title, text)),
          actions: [
            dialogButton("Cancel", onPressed: onClose, isOutline: true)
          ],
          onCancel: onClose),
      tag: '$sessionId-waiting-for-image',
    );
    waitForImageDialogShow.value = true;
    waitForImageTimer = Timer(Duration(milliseconds: 1500), () {
      if (!_isCurrentSession(sessionId)) return;
      if (waitForFirstImage.isTrue && !isRefreshing) {
        bind.sessionInputOsPassword(sessionId: sessionId, value: '');
      }
    });
    bind.sessionOnWaitingForImageDialogShow(sessionId: sessionId);
  }

  void showPrivacyFailedDialog(
      SessionID sessionId,
      String type,
      String title,
      String text,
      String link,
      bool hasRetry,
      OverlayDialogManager dialogManager) {
    // There are display changes on the remote side,
    // which will cause some messages to refresh the canvas and dismiss dialogs.
    // So we add a delay here to ensure the dialog is displayed.
    Future.delayed(Duration(milliseconds: 3000), () {
      if (!_isCurrentSession(sessionId)) return;
      showMsgBox(sessionId, type, title, text, link, hasRetry, dialogManager);
    });
  }

  Future<void> _updateSessionWidthHeight(
      SessionID sessionId, SessionID expectedClientOwnerId) async {
    if (_rect == null) return;
    if (_rect!.width <= 0 || _rect!.height <= 0) {
      debugPrintStack(
          label: 'invalid display size (${_rect!.width},${_rect!.height})');
    } else {
      final displays = _pi.getCurDisplays();
      if (displays.length == 1) {
        await bind.sessionSetSize(
          sessionId: sessionId,
          clientOwnerId: expectedClientOwnerId,
          display:
              pi.currentDisplay == kAllDisplayValue ? 0 : pi.currentDisplay,
          width: displays[0].width,
          height: displays[0].height,
        );
      } else {
        for (int i = 0; i < displays.length; ++i) {
          await bind.sessionSetSize(
            sessionId: sessionId,
            clientOwnerId: expectedClientOwnerId,
            display: i,
            width: displays[i].width,
            height: displays[i].height,
          );
        }
      }
    }
  }

  /// Handle the peer info event based on [evt].
  Future<void> handlePeerInfo(Map<String, dynamic> evt, String peerId,
      bool isCache, SessionID expectedSessionId) async {
    final topologyRevision =
        _beginDisplayTopologyMutation(expectedSessionId);
    if (topologyRevision == null) return;
    final previousCurrentDisplay = _pi.currentDisplay;
    final restoreDisplaySelection = !isCache && _pi.isSet.value;
    final preserveDisplaySelection = isCache || restoreDisplaySelection;
    parent.target?.chatModel.voiceCallStatus.value = VoiceCallStatus.notStarted;

    // Map clone is required here, otherwise "evt" may be changed by other threads through the reference.
    // Because this function is asynchronous, there's an "await" in this function.
    cachedPeerData.peerInfo = {...evt};
    // Do not cache resolutions, because a new display connection have different resolutions.
    cachedPeerData.peerInfo.remove('resolutions');

    // Recent peer is updated by handle_peer_info(ui_session_interface.rs) --> handle_peer_info(client.rs) --> save_config(client.rs)
    bind.mainLoadRecentPeers();

    parent.target?.dialogManager.dismissAll();
    _pi.version = evt['version'];
    // Note: Relative mouse mode is NOT auto-enabled on connect.
    // Users must manually enable it via toolbar or keyboard shortcut (Ctrl+Alt+Shift+M).
    //
    // For desktop/webDesktop, keyboard mode initialization is handled later by
    // updateKeyboardMode(), which computes a runtime compatibility fallback
    // without changing the saved per-peer preference.
    // For mobile, updateKeyboardMode() is currently a no-op (only executes on desktop/web),
    // but we call it here for consistency and future-proofing.
    if (isMobile) {
      parent.target?.inputModel.updateKeyboardMode();
    }
    _pi.isSupportMultiUiSession =
        bind.isSupportMultiUiSession(version: _pi.version);
    _pi.username = evt['username'];
    _pi.hostname = evt['hostname'];
    _pi.platform = evt['platform'];
    _pi.sasEnabled = evt['sas_enabled'] == 'true';
    final currentDisplay = int.parse(evt['current_display']);
    if (_pi.primaryDisplay == kInvalidDisplayIndex) {
      _pi.primaryDisplay = currentDisplay;
    }

    if (!preserveDisplaySelection &&
        bind.peerGetSessionsCount(
                id: peerId, connType: parent.target!.connType.index) <=
            1) {
      _pi.currentDisplay = currentDisplay;
    }

    try {
      CurrentDisplayState.find(peerId).value = _pi.currentDisplay;
    } catch (e) {
      //
    }

    final connType = parent.target?.connType;
    if (isPeerAndroid) {
      _touchMode = true;
    } else {
      // `kOptionTouchMode` is originally peer option, but it is moved to local option later.
      // We check local option first, if not set, then check peer option.
      // Because if local option is not empty:
      // 1. User has set the touch mode explicitly.
      // 2. The advanced option (custom client) is set.
      //    Then we choose to use the local option.
      final optLocal = bind.mainGetLocalOption(key: kOptionTouchMode);
      if (optLocal != '') {
        _touchMode = optLocal == 'Y';
      } else {
        final optSession = await bind.sessionGetOption(
            sessionId: expectedSessionId, arg: kOptionTouchMode);
        if (!isCurrentDisplayTopology(
            expectedSessionId, topologyRevision)) return;
        _touchMode = optSession != '';
      }
    }
    if (isMobile) {
      virtualMouseMode.loadOptions();
    }
    if (connType == ConnType.fileTransfer) {
      await parent.target?.fileModel.onReady(expectedSessionId);
      if (!isCurrentDisplayTopology(
          expectedSessionId, topologyRevision)) return;
    } else if (connType == ConnType.terminal) {
      // Call onReady on all registered terminal models
      final models = parent.target?._terminalModels.values ?? [];
      for (final model in models) {
        model.onReady();
      }
    } else if (connType == ConnType.defaultConn ||
        connType == ConnType.viewCamera) {
      List<Display> newDisplays = [];
      List<dynamic> displays = json.decode(evt['displays']);
      for (int i = 0; i < displays.length; ++i) {
        newDisplays.add(evtToDisplay(displays[i]));
      }
      _pi.displays.value = newDisplays;
      _pi.displaysCount.value = _pi.displays.length;
      if (restoreDisplaySelection) {
        final ffi = parent.target;
        final reconnectDisplays = previousCurrentDisplay == kAllDisplayValue
            ? List.generate(_pi.displays.length, (index) => index)
            : [previousCurrentDisplay];
        if (ffi == null ||
            reconnectDisplays.isEmpty ||
            !await selectRemoteDisplays(
                ffi, expectedSessionId, reconnectDisplays)) {
          ffi?._reportSessionStreamFailure(expectedSessionId, peerId,
              'The previous display selection could not be restored');
          return;
        }
        if (!isCurrentDisplayTopology(
            expectedSessionId, topologyRevision)) return;
      }
      if (_pi.currentDisplay < _pi.displays.length) {
        if (!await updateCurDisplay(
            expectedSessionId, topologyRevision)) return;
      }
      if (displays.isNotEmpty) {
        _reconnects = 1;
        _offlineReconnectStartTime = null;
        waitForFirstImage.value = true;
        isRefreshing = false;
      }
      Map<String, dynamic> features = json.decode(evt['features']);
      _pi.features.privacyMode = features['privacy_mode'] == true;
      if (!isCache) {
        handleResolutions(peerId, evt["resolutions"]);
      }
    }
    if (connType == ConnType.defaultConn) {
      setViewOnly(
          peerId,
          bind.sessionGetToggleOptionSync(
              sessionId: expectedSessionId, arg: kOptionToggleViewOnly));
      setShowMyCursor(bind.sessionGetToggleOptionSync(
          sessionId: expectedSessionId, arg: kOptionToggleShowMyCursor));
    }
    if (connType == ConnType.defaultConn || connType == ConnType.viewCamera) {
      final platformAdditions = evt['platform_additions'];
      if (platformAdditions != null && platformAdditions != '') {
        try {
          _pi.platformAdditions = json.decode(platformAdditions);
        } catch (e) {
          debugPrint('Failed to decode platformAdditions $e');
        }
      }
    }

    _pi.isSet.value = true;
    stateGlobal.resetLastResolutionGroupValues(peerId);

    if (isDesktop || isWebDesktop) {
      await parent.target?.inputModel.updateKeyboardMode();
      if (!isCurrentDisplayTopology(
          expectedSessionId, topologyRevision)) return;
    }

    notifyListeners();

    if (!isCache) {
      await tryUseAllMyDisplaysForTheRemoteSession(
          peerId, expectedSessionId, topologyRevision);
    }
  }

  Future<void> tryUseAllMyDisplaysForTheRemoteSession(
      String peerId,
      SessionID expectedSessionId,
      int expectedTopologyRevision) async {
    if (!isCurrentDisplayTopology(
        expectedSessionId, expectedTopologyRevision)) return;
    if (bind.sessionGetUseAllMyDisplaysForTheRemoteSession(
            sessionId: expectedSessionId) !=
        'Y') {
      return;
    }

    if (!_pi.isSupportMultiDisplay || _pi.displays.length <= 1) {
      return;
    }

    final screenRectList = await getScreenRectList();
    if (!isCurrentDisplayTopology(
        expectedSessionId, expectedTopologyRevision)) return;
    if (screenRectList.length <= 1) {
      return;
    }

    // to-do: peer currentDisplay is the primary display, but the primary display may not be the first display.
    // local primary display also may not be the first display.
    //
    // 0 is assumed to be the primary display here, for now.

    // move to the first display and set fullscreen
    final ffi = parent.target;
    if (ffi == null ||
        !await selectRemoteDisplays(ffi, expectedSessionId, [0])) {
      return;
    }
    if (!await switchToNewDisplay(0, expectedSessionId, peerId,
        expectedTopologyRevision: expectedTopologyRevision)) return;
    await tryMoveToScreenAndSetFullscreen(screenRectList[0]);
    if (!isCurrentDisplayTopology(
        expectedSessionId, expectedTopologyRevision)) return;

    final length = _pi.displays.length < screenRectList.length
        ? _pi.displays.length
        : screenRectList.length;
    for (var i = 1; i < length; i++) {
      openMonitorInNewTabOrWindow(i, peerId, _pi,
          screenRect: screenRectList[i]);
    }
  }

  tryShowAndroidActionsOverlay(SessionID expectedSessionId,
      {int delayMSecs = 10}) {
    if (isPeerAndroid) {
      if (parent.target?.connType == ConnType.defaultConn &&
          parent.target != null &&
          parent.target!.ffiModel.permissions['keyboard'] != false) {
        Timer(Duration(milliseconds: delayMSecs), () {
          if (!_isCurrentSession(expectedSessionId)) return;
          if (parent.target!.dialogManager.mobileActionsOverlayVisible.isTrue) {
            parent.target!.dialogManager
                .showMobileActionsOverlay(ffi: parent.target!);
          }
        });
      }
    }
  }

  handleResolutions(String id, dynamic resolutions) {
    try {
      final resolutionsObj = json.decode(resolutions as String);
      late List<dynamic> dynamicArray;
      if (resolutionsObj is Map) {
        // The web version
        dynamicArray = (resolutionsObj as Map<String, dynamic>)['resolutions']
            as List<dynamic>;
      } else {
        // The rust version
        dynamicArray = resolutionsObj as List<dynamic>;
      }
      List<Resolution> arr = List.empty(growable: true);
      for (int i = 0; i < dynamicArray.length; i++) {
        var width = dynamicArray[i]["width"];
        var height = dynamicArray[i]["height"];
        if (width is int && width > 0 && height is int && height > 0) {
          arr.add(Resolution(width, height));
        }
      }
      arr.sort((a, b) {
        if (b.width != a.width) {
          return b.width - a.width;
        } else {
          return b.height - a.height;
        }
      });
      _pi.resolutions = arr;
    } catch (e) {
      debugPrint("Failed to parse resolutions:$e");
    }
  }

  Display evtToDisplay(Map<String, dynamic> evt) {
    var d = Display();
    d.x = evt['x']?.toDouble() ?? d.x;
    d.y = evt['y']?.toDouble() ?? d.y;
    d.width = evt['width'] ?? d.width;
    d.height = evt['height'] ?? d.height;
    d.cursorEmbedded = evt['cursor_embedded'] == 1;
    d.originalWidth = evt['original_width'] ?? kInvalidResolutionValue;
    d.originalHeight = evt['original_height'] ?? kInvalidResolutionValue;
    d._scale = 1.0;
    final scaledWidth = evt['scaled_width'];
    if (scaledWidth != null) {
      final sw = int.tryParse(scaledWidth.toString());
      if (sw != null && sw > 0 && d.width > 0) {
        d._scale = max(d.width.toDouble() / sw, 1.0);
      } else {
        debugPrint(
            "Invalid scaled_width ($scaledWidth) or width (${d.width}), using default scale 1.0");
      }
    }
    return d;
  }

  /// Handle the peer info synchronization event based on [evt].
  Future<void> handleSyncPeerInfo(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) async {
    if (!_isCurrentSession(sessionId)) return;
    if (evt['displays'] != null) {
      final topologyRevision = _beginDisplayTopologyMutation(sessionId);
      if (topologyRevision == null) return;
      cachedPeerData.peerInfo['displays'] = evt['displays'];
      List<dynamic> displays = json.decode(evt['displays']);
      List<Display> newDisplays = [];
      for (int i = 0; i < displays.length; ++i) {
        newDisplays.add(evtToDisplay(displays[i]));
      }
      _pi.displays.value = newDisplays;
      _pi.displaysCount.value = _pi.displays.length;

      if (_pi.currentDisplay == kAllDisplayValue) {
        if (!await updateCurDisplay(sessionId, topologyRevision)) return;
        // to-do: What if the displays are changed?
      } else {
        if (_pi.currentDisplay >= 0 &&
            _pi.currentDisplay < _pi.displays.length) {
          if (!await updateCurDisplay(sessionId, topologyRevision)) return;
        } else {
          if (_pi.displays.isNotEmpty) {
            // Notify to switch display
            msgBox(sessionId, 'custom-nook-nocancel-hasclose-info', 'Prompt',
                'display_is_plugged_out_msg', '', parent.target!.dialogManager);
            final isPeerPrimaryDisplayValid =
                pi.primaryDisplay == kInvalidDisplayIndex ||
                    pi.primaryDisplay >= pi.displays.length;
            final newDisplay =
                isPeerPrimaryDisplayValid ? 0 : pi.primaryDisplay;
            final ffi = parent.target;
            if (ffi == null ||
                !await selectRemoteDisplays(ffi, sessionId, [newDisplay])) {
              return;
            }
            if (!isCurrentDisplayTopology(sessionId, topologyRevision)) {
              return;
            }

            if (_pi.isSupportMultiUiSession) {
              // If the peer supports multi-ui-session, no switch display message will be send back.
              // We need to update the display manually.
              if (!await switchToNewDisplay(newDisplay, sessionId, peerId,
                  expectedTopologyRevision: topologyRevision)) return;
            }
          } else {
            msgBox(sessionId, 'nocancel-error', 'Prompt', 'No Displays', '',
                parent.target!.dialogManager);
          }
        }
      }
      if (!isCurrentDisplayTopology(sessionId, topologyRevision)) return;
      await parent.target!.canvasModel.tryUpdateScrollStyle(
          Duration(milliseconds: 300), null,
          expectedSessionId: sessionId,
          expectedDisplayTopologyRevision: topologyRevision);
      if (!isCurrentDisplayTopology(sessionId, topologyRevision)) return;
    }
    notifyListeners();
  }

  Future<void> handlePlatformAdditions(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) async {
    final topologyRevision = _beginDisplayTopologyMutation(sessionId);
    if (topologyRevision == null) return;
    final updateData = evt['platform_additions'] as String?;
    if (updateData == null) {
      return;
    }

    if (updateData.isEmpty) {
      _pi.platformAdditions.remove(kPlatformAdditionsAmyuniVirtualDisplays);
    } else {
      final updateJson = json.decode(updateData) as Map<String, dynamic>;
      for (final key in updateJson.keys) {
        _pi.platformAdditions[key] = updateJson[key];
      }
      if (!updateJson.containsKey(kPlatformAdditionsAmyuniVirtualDisplays)) {
        _pi.platformAdditions.remove(kPlatformAdditionsAmyuniVirtualDisplays);
      }
    }

    cachedPeerData.peerInfo['platform_additions'] =
        json.encode(_pi.platformAdditions);
  }

  Future<void> handleFollowCurrentDisplay(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) async {
    if (evt['display_idx'] != null) {
      if (pi.currentDisplay == kAllDisplayValue) {
        return;
      }
      final topologyRevision = _beginDisplayTopologyMutation(sessionId);
      if (topologyRevision == null) return;
      final display = int.parse(evt['display_idx']);
      final ffi = parent.target;
      if (ffi == null ||
          !await selectRemoteDisplays(ffi, sessionId, [display])) {
        return;
      }
      if (!await switchToNewDisplay(display, sessionId, peerId,
          expectedTopologyRevision: topologyRevision)) return;
    }
    notifyListeners();
  }

  Future<bool> switchToNewDisplay(
      int display, SessionID sessionId, String peerId,
      {bool updateCursorPos = false,
      int? expectedTopologyRevision}) async {
    if (expectedTopologyRevision == null) {
      final ffi = parent.target;
      if (ffi == null || !ffi.isCurrentSession(sessionId)) return false;
      final expectedClientOwnerId = ffi.clientOwnerId;
      var applied = false;
      try {
        final disposition = await ffi.submitSessionEvent(
            sessionId, expectedClientOwnerId, () async {
          applied = await _applyDisplaySwitch(
              display, sessionId, peerId, updateCursorPos, null);
        });
        return disposition == SessionEventDisposition.completed &&
            applied &&
            ffi.isCurrentSessionOwner(sessionId, expectedClientOwnerId);
      } catch (error) {
        debugPrint('Local display topology failed: ${error.runtimeType}');
        ffi._reportSessionStreamFailure(sessionId, peerId,
            'The remote session state became inconsistent');
        return false;
      }
    }
    return _applyDisplaySwitch(display, sessionId, peerId, updateCursorPos,
        expectedTopologyRevision);
  }

  Future<bool> _applyDisplaySwitch(int display, SessionID sessionId,
      String peerId, bool updateCursorPos, int? expectedTopologyRevision) async {
    final topologyRevision = expectedTopologyRevision ??
        _beginDisplayTopologyMutation(sessionId);
    if (topologyRevision == null ||
        !isCurrentDisplayTopology(sessionId, topologyRevision)) {
      return false;
    }
    pi.currentDisplay = display;
    if (!await updateCurDisplay(sessionId, topologyRevision,
        updateCursorPos: updateCursorPos)) return false;
    try {
      CurrentDisplayState.find(peerId).value = display;
    } catch (e) {
      //
    }
    return isCurrentDisplayTopology(sessionId, topologyRevision);
  }

  updateBlockInputState(Map<String, dynamic> evt, String peerId) {
    _inputBlocked = evt['input_state'] == 'on';
    notifyListeners();
    try {
      BlockInputState.find(peerId).value = evt['input_state'] == 'on';
    } catch (e) {
      //
    }
  }

  updatePrivacyMode(
      Map<String, dynamic> evt, SessionID sessionId, String peerId) async {
    if (!_isCurrentSession(sessionId)) return;
    notifyListeners();
    try {
      final isOn = bind.sessionGetToggleOptionSync(
          sessionId: sessionId, arg: 'privacy-mode');
      if (isOn) {
        var privacyModeImpl = await bind.sessionGetOption(
            sessionId: sessionId, arg: 'privacy-mode-impl-key');
        if (!_isCurrentSession(sessionId)) return;
        // For compatibility, version < 1.2.4, the default value is 'privacy_mode_impl_mag'.
        final initDefaultPrivacyMode = 'privacy_mode_impl_mag';
        PrivacyModeState.find(peerId).value =
            privacyModeImpl ?? initDefaultPrivacyMode;
      } else {
        PrivacyModeState.find(peerId).value = '';
      }
    } catch (e) {
      //
    }
  }

  void setViewOnly(String id, bool value) {
    if (versionCmp(_pi.version, '1.2.0') < 0) return;
    // tmp fix for https://github.com/rustdesk/rustdesk/pull/3706#issuecomment-1481242389
    // because below rx not used in mobile version, so not initialized, below code will cause crash
    // current our flutter code quality is fucking shit now. !!!!!!!!!!!!!!!!
    try {
      if (value) {
        ShowRemoteCursorState.find(id).value = value;
      } else {
        ShowRemoteCursorState.find(id).value = bind.sessionGetToggleOptionSync(
            sessionId: sessionId, arg: 'show-remote-cursor');
      }
    } catch (e) {
      //
    }
    if (_viewOnly != value) {
      _viewOnly = value;
      notifyListeners();
    }
  }

  void setShowMyCursor(bool value) {
    if (_showMyCursor != value) {
      _showMyCursor = value;
      notifyListeners();
    }
  }
}

class VirtualMouseMode with ChangeNotifier {
  bool _showVirtualMouse = false;
  double _virtualMouseScale = 1.0;
  bool _showVirtualJoystick = false;

  bool get showVirtualMouse => _showVirtualMouse;
  double get virtualMouseScale => _virtualMouseScale;
  bool get showVirtualJoystick => _showVirtualJoystick;

  FfiModel ffiModel;

  VirtualMouseMode(this.ffiModel);

  bool _shouldShow() => !ffiModel.isPeerAndroid;

  setShowVirtualMouse(bool b) {
    if (b == _showVirtualMouse) return;
    if (_shouldShow()) {
      _showVirtualMouse = b;
      notifyListeners();
    }
  }

  setVirtualMouseScale(double s) {
    if (s <= 0) return;
    if (s == _virtualMouseScale) return;
    _virtualMouseScale = s;
    bind.mainSetLocalOption(key: kOptionVirtualMouseScale, value: s.toString());
    notifyListeners();
  }

  setShowVirtualJoystick(bool b) {
    if (b == _showVirtualJoystick) return;
    if (_shouldShow()) {
      _showVirtualJoystick = b;
      notifyListeners();
    }
  }

  void loadOptions() {
    _showVirtualMouse =
        bind.mainGetLocalOption(key: kOptionShowVirtualMouse) == 'Y';
    _virtualMouseScale = double.tryParse(
            bind.mainGetLocalOption(key: kOptionVirtualMouseScale)) ??
        1.0;
    _showVirtualJoystick =
        bind.mainGetLocalOption(key: kOptionShowVirtualJoystick) == 'Y';
    notifyListeners();
  }

  Future<void> toggleVirtualMouse() async {
    await bind.mainSetLocalOption(
        key: kOptionShowVirtualMouse, value: showVirtualMouse ? 'N' : 'Y');
    setShowVirtualMouse(
        bind.mainGetLocalOption(key: kOptionShowVirtualMouse) == 'Y');
  }

  Future<void> toggleVirtualJoystick() async {
    await bind.mainSetLocalOption(
        key: kOptionShowVirtualJoystick,
        value: showVirtualJoystick ? 'N' : 'Y');
    setShowVirtualJoystick(
        bind.mainGetLocalOption(key: kOptionShowVirtualJoystick) == 'Y');
  }
}

class ImageModel with ChangeNotifier {
  ui.Image? _image;
  final ExactRgbaPublicationOrder<SessionID> _rgbaPublicationOrder =
      ExactRgbaPublicationOrder<SessionID>();

  ui.Image? get image => _image;

  String id = '';

  SessionID get sessionId => parent.target!.sessionId;

  bool _useTextureRender = false;

  WeakReference<FFI> parent;

  final List<Function(String)> callbacksOnFirstImage = [];

  ImageModel(this.parent);

  get useTextureRender => _useTextureRender;

  addCallbackOnFirstImage(Function(String) cb) => callbacksOnFirstImage.add(cb);

  void clearImage() {
    _rgbaPublicationOrder.retire();
    _image?.dispose();
    _image = null;
  }

  Future<bool> onRgba(
      SessionID expectedSessionId, int display, Uint8List rgba,
      {int? publication, required int expectedDisplayTopologyRevision}) async {
    RgbaPublicationAdmission<SessionID>? admission;
    if (publication != null) {
      if (parent.target?.ffiModel.isCurrentDisplayTopology(
              expectedSessionId, expectedDisplayTopologyRevision) ==
          true) {
        admission = _rgbaPublicationOrder.admit(
            expectedSessionId, display, publication);
      }
      if (admission == null) {
        platformFFI.nextRgba(expectedSessionId, display, publication);
        return false;
      }
    }
    try {
      return await decodeAndUpdate(expectedSessionId, display, rgba,
          expectedRgbaPublication: admission,
          expectedDisplayTopologyRevision:
              expectedDisplayTopologyRevision);
    } catch (e) {
      debugPrint('onRgba error: $e');
      return false;
    } finally {
      if (publication != null) {
        platformFFI.nextRgba(expectedSessionId, display, publication);
      }
    }
  }

  Future<bool> decodeAndUpdate(
      SessionID expectedSessionId, int display, Uint8List rgba,
      {RgbaPublicationAdmission<SessionID>? expectedRgbaPublication,
      required int expectedDisplayTopologyRevision}) async {
    if (parent.target?.ffiModel.isCurrentDisplayTopology(
            expectedSessionId, expectedDisplayTopologyRevision) !=
        true ||
        (expectedRgbaPublication != null &&
            !_rgbaPublicationOrder.isCurrent(expectedRgbaPublication))) {
      return false;
    }
    final rect = parent.target?.ffiModel.pi.getDisplayRect(display);
    final image = await img.decodeImageFromPixels(
      rgba,
      rect?.width.toInt() ?? 0,
      rect?.height.toInt() ?? 0,
      isWeb | isWindows | isLinux
          ? ui.PixelFormat.rgba8888
          : ui.PixelFormat.bgra8888,
    );
    if (image == null) {
      return false;
    }
    if (parent.target?.ffiModel.isCurrentDisplayTopology(
            expectedSessionId, expectedDisplayTopologyRevision) !=
        true ||
        (expectedRgbaPublication != null &&
            !_rgbaPublicationOrder.isCurrent(expectedRgbaPublication))) {
      image.dispose();
      return false;
    }
    return update(image,
        expectedSessionId: expectedSessionId,
        expectedRgbaPublication: expectedRgbaPublication,
        expectedDisplayTopologyRevision: expectedDisplayTopologyRevision);
  }

  Future<bool> update(ui.Image? image,
      {SessionID? expectedSessionId,
      bool allowClosedSession = false,
      RgbaPublicationAdmission<SessionID>? expectedRgbaPublication,
      int? expectedDisplayTopologyRevision}) async {
    bool acceptsExpectedImage() =>
        (expectedSessionId == null ||
            (allowClosedSession
                ? parent.target?.sessionId == expectedSessionId
                : parent.target?.isCurrentSession(expectedSessionId) ==
                    true)) &&
        (expectedRgbaPublication == null ||
            _rgbaPublicationOrder.isCurrent(expectedRgbaPublication)) &&
        (expectedDisplayTopologyRevision == null ||
            (expectedSessionId != null &&
                parent.target?.ffiModel.isCurrentDisplayTopology(
                        expectedSessionId,
                        expectedDisplayTopologyRevision) ==
                    true));

    if (!acceptsExpectedImage()) {
      image?.dispose();
      return false;
    }
    if (_image == null && image != null) {
      if (isDesktop || isWebDesktop) {
        await parent.target?.canvasModel
            .updateViewStyle(
                expectedSessionId: expectedSessionId,
                expectedDisplayTopologyRevision:
                    expectedDisplayTopologyRevision);
        if (!acceptsExpectedImage()) {
          image.dispose();
          return false;
        }
        await parent.target?.canvasModel
            .updateScrollStyle(
                expectedSessionId: expectedSessionId,
                expectedDisplayTopologyRevision:
                    expectedDisplayTopologyRevision);
        if (!acceptsExpectedImage()) {
          image.dispose();
          return false;
        }
        await parent.target?.canvasModel.initializeEdgeScrollEdgeThickness(
            expectedSessionId: expectedSessionId,
            expectedDisplayTopologyRevision:
                expectedDisplayTopologyRevision);
        if (!acceptsExpectedImage()) {
          image.dispose();
          return false;
        }
      }
      if (parent.target != null) {
        await initializeCursorAndCanvas(parent.target!,
            expectedSessionId: expectedSessionId,
            expectedDisplayTopologyRevision:
                expectedDisplayTopologyRevision);
        if (!acceptsExpectedImage()) {
          image.dispose();
          return false;
        }
      }
    }
    if (!acceptsExpectedImage()) {
      image?.dispose();
      return false;
    }
    if (image == null) {
      _rgbaPublicationOrder.retire();
    }
    _image?.dispose();
    _image = image;
    if (image != null) notifyListeners();
    return true;
  }

  // mobile only
  double get maxScale {
    if (_image == null) return 1.5;
    final size = parent.target!.canvasModel.getSize();
    final xscale = size.width / _image!.width;
    final yscale = size.height / _image!.height;
    return max(1.5, max(xscale, yscale));
  }

  // mobile only
  double get minScale {
    if (_image == null) return 1.5;
    final size = parent.target!.canvasModel.getSize();
    final xscale = size.width / _image!.width;
    final yscale = size.height / _image!.height;
    return min(xscale, yscale) / 1.5;
  }

  updateUserTextureRender() {
    final preValue = _useTextureRender;
    _useTextureRender = isDesktop && bind.mainGetUseTextureRender();
    if (preValue != _useTextureRender) {
      notifyListeners();
    }
  }

  setUseTextureRender(bool value) {
    _useTextureRender = value;
    notifyListeners();
  }

  void disposeImage() {
    clearImage();
  }
}

enum ScrollStyle {
  scrollbar(kRemoteScrollStyleBar),
  scrollauto(kRemoteScrollStyleAuto),
  scrolledge(kRemoteScrollStyleEdge);

  const ScrollStyle(this.stringValue);

  final String stringValue;

  String toJson() {
    return name;
  }

  static ScrollStyle fromJson(String json, [ScrollStyle? fallbackValue]) {
    switch (json) {
      case 'scrollbar':
        return scrollbar;
      case 'scrollauto':
        return scrollauto;
      case 'scrolledge':
        return scrolledge;
    }

    if (fallbackValue != null) {
      return fallbackValue;
    }

    throw ArgumentError("Unknown ScrollStyle JSON value: '$json'");
  }

  @override
  String toString() {
    return stringValue;
  }

  static ScrollStyle fromString(String string, [ScrollStyle? fallbackValue]) {
    switch (string) {
      case kRemoteScrollStyleBar:
        return scrollbar;
      case kRemoteScrollStyleAuto:
        return scrollauto;
      case kRemoteScrollStyleEdge:
        return scrolledge;
    }

    if (fallbackValue != null) {
      return fallbackValue;
    }

    throw ArgumentError("Unknown ScrollStyle string value: '$string'");
  }
}

class ViewStyle {
  final String style;
  final double width;
  final double height;
  final int displayWidth;
  final int displayHeight;
  ViewStyle({
    required this.style,
    required this.width,
    required this.height,
    required this.displayWidth,
    required this.displayHeight,
  });

  static defaultViewStyle() {
    final desktop = (isDesktop || isWebDesktop);
    final w =
        desktop ? kDesktopDefaultDisplayWidth : kMobileDefaultDisplayWidth;
    final h =
        desktop ? kDesktopDefaultDisplayHeight : kMobileDefaultDisplayHeight;
    return ViewStyle(
      style: '',
      width: w.toDouble(),
      height: h.toDouble(),
      displayWidth: w,
      displayHeight: h,
    );
  }

  static int _double2Int(double v) => (v * 100).round().toInt();

  @override
  bool operator ==(Object other) =>
      other is ViewStyle &&
      other.runtimeType == runtimeType &&
      _innerEqual(other);

  bool _innerEqual(ViewStyle other) {
    return style == other.style &&
        ViewStyle._double2Int(other.width) == ViewStyle._double2Int(width) &&
        ViewStyle._double2Int(other.height) == ViewStyle._double2Int(height) &&
        other.displayWidth == displayWidth &&
        other.displayHeight == displayHeight;
  }

  @override
  int get hashCode => Object.hash(
        style,
        ViewStyle._double2Int(width),
        ViewStyle._double2Int(height),
        displayWidth,
        displayHeight,
      ).hashCode;

  double get scale {
    double s = 1.0;
    if (style == kRemoteViewStyleAdaptive) {
      if (width != 0 &&
          height != 0 &&
          displayWidth != 0 &&
          displayHeight != 0) {
        final s1 = width / displayWidth;
        final s2 = height / displayHeight;
        s = s1 < s2 ? s1 : s2;
      }
    } else if (style == kRemoteViewStyleCustom) {
      // Custom scale is session-scoped and applied in CanvasModel.updateViewStyle()
    }
    return s;
  }
}

enum EdgeScrollState {
  inactive,
  armed,
  active,
}

class EdgeScrollFallbackState {
  final CanvasModel _owner;

  late Ticker _ticker;

  Duration _lastTotalElapsed = Duration.zero;
  bool _nextEventIsFirst = true;
  Vector2 _encroachment = Vector2.zero();

  EdgeScrollFallbackState(this._owner, TickerProvider tickerProvider) {
    _ticker = tickerProvider.createTicker(emitTick);
  }

  void setEncroachment(Vector2 encroachment) {
    _encroachment = encroachment;
  }

  void emitTick(Duration totalElapsed) {
    if (_nextEventIsFirst) {
      _lastTotalElapsed = totalElapsed;
      _nextEventIsFirst = false;
    } else {
      final thisTickElapsed = totalElapsed - _lastTotalElapsed;

      const double kFrameTime = 1000.0 / 60.0;
      const double kSpeedFactor = 0.1;

      var delta = _encroachment *
          (kSpeedFactor * thisTickElapsed.inMilliseconds / kFrameTime);

      _owner.performEdgeScroll(delta);

      _lastTotalElapsed = totalElapsed;
    }
  }

  void start() {
    if (!_ticker.isActive) {
      _nextEventIsFirst = true;
      _ticker.start();
    }
  }

  void stop() {
    _ticker.stop();
  }
}

class CanvasModel with ChangeNotifier {
  // image offset of canvas
  double _x = 0;
  // image offset of canvas
  double _y = 0;
  // image scale
  double _scale = 1.0;
  double _devicePixelRatio = 1.0;
  Size _size = Size.zero;
  // the tabbar over the image
  // double tabBarHeight = 0.0;
  // the window border's width
  // double windowBorderWidth = 0.0;
  // remote id
  String id = '';
  SessionID get sessionId => parent.target!.sessionId;
  // scroll offset x percent
  double _scrollX = 0.0;
  // scroll offset y percent
  double _scrollY = 0.0;
  ScrollStyle _scrollStyle = ScrollStyle.scrollauto;
  // edge scroll mode: trigger scrolling when the cursor is close to the edge of the view
  int _edgeScrollEdgeThickness = 100;
  // tracks whether edge scroll should be active, prevents spurious
  // scrolling when the cursor enters the view from outside
  EdgeScrollState _edgeScrollState = EdgeScrollState.inactive;
  // fallback strategy for when Bump Mouse isn't available
  EdgeScrollFallbackState? _edgeScrollFallbackState;
  // to avoid hammering a non-functional Bump Mouse
  bool _bumpMouseIsWorking = true;
  ViewStyle _lastViewStyle = ViewStyle.defaultViewStyle();

  Timer? _timerMobileFocusCanvasCursor;
  Timer? _timerMobileRestoreCanvasOffset;
  Offset? _offsetBeforeMobileSoftKeyboard;
  double? _scaleBeforeMobileSoftKeyboard;

  // `isMobileCanvasChanged` is used to avoid canvas reset when changing the input method
  // after showing the soft keyboard.
  bool isMobileCanvasChanged = false;

  final ScrollController _horizontal = ScrollController();
  final ScrollController _vertical = ScrollController();

  final _imageOverflow = false.obs;

  WeakReference<FFI> parent;

  CanvasModel(this.parent);

  double get x => _x;
  double get y => _y;
  double get scale => _scale;
  double get devicePixelRatio => _devicePixelRatio;
  Size get size => _size;
  ScrollStyle get scrollStyle => _scrollStyle;
  ViewStyle get viewStyle => _lastViewStyle;
  RxBool get imageOverflow => _imageOverflow;

  _resetScroll() => setScrollPercent(0.0, 0.0);

  void setScrollPercent(double x, double y) {
    _scrollX = x.isFinite ? x : 0.0;
    _scrollY = y.isFinite ? y : 0.0;
  }

  void pushScrollPositionToUI(double scrollPixelX, double scrollPixelY) {
    if (_horizontal.hasClients) {
      _horizontal.jumpTo(scrollPixelX);
    }
    if (_vertical.hasClients) {
      _vertical.jumpTo(scrollPixelY);
    }
  }

  ScrollController get scrollHorizontal => _horizontal;
  ScrollController get scrollVertical => _vertical;
  double get scrollX => _scrollX;
  double get scrollY => _scrollY;

  static double get leftToEdge =>
      isDesktop ? windowBorderWidth + kDragToResizeAreaPadding.left : 0;
  static double get rightToEdge =>
      isDesktop ? windowBorderWidth + kDragToResizeAreaPadding.right : 0;
  static double get topToEdge => isDesktop
      ? tabBarHeight + windowBorderWidth + kDragToResizeAreaPadding.top
      : 0;
  static double get bottomToEdge =>
      isDesktop ? windowBorderWidth + kDragToResizeAreaPadding.bottom : 0;

  Size getSize() {
    final mediaData = MediaQueryData.fromView(ui.window);
    final size = mediaData.size;
    // If minimized, w or h may be negative here.
    double w = size.width - leftToEdge - rightToEdge;
    double h = size.height - topToEdge - bottomToEdge;
    if (isMobile) {
      // Account for horizontal safe area insets on both orientations.
      w = w - mediaData.padding.left - mediaData.padding.right;
      // Vertically, subtract the bottom keyboard inset (viewInsets.bottom) and any
      // bottom overlay (e.g. key-help tools) so the canvas is not covered.
      h = h -
          mediaData.viewInsets.bottom -
          (parent.target?.cursorModel.keyHelpToolsRectToAdjustCanvas?.bottom ??
              0);
      // Orientation-specific handling:
      //  - Portrait: additionally subtract top padding (e.g. status bar / notch)
      //  - Landscape: does not subtract mediaData.padding.top/bottom (home indicator auto-hides)
      final isPortrait = size.height > size.width;
      if (isPortrait) {
        // In portrait mode, subtract the top safe-area padding (e.g. status bar / notch)
        // so the remote image is not truncated, while keeping the bottom inset to avoid
        // introducing unnecessary blank space around the canvas.
        //
        // iOS -> Android, portrait, adjust mode:
        // h = h (no padding subtracted): top and bottom are truncated
        //   https://github.com/user-attachments/assets/30ed4559-c27e-432b-847f-8fec23c9f998
        // h = h - top - bottom: extra blank spaces appear
        //   https://github.com/user-attachments/assets/12a98817-3b4e-43aa-be0f-4b03cf364b7e
        // h = h - top (current): works fine
        //   https://github.com/user-attachments/assets/95f047f2-7f47-4a36-8113-5023989a0c81
        h = h - mediaData.padding.top;
      }
    }
    return Size(w < 0 ? 0 : w, h < 0 ? 0 : h);
  }

  // mobile only
  double getAdjustY() {
    final bottom =
        parent.target?.cursorModel.keyHelpToolsRectToAdjustCanvas?.bottom ?? 0;
    return max(bottom - MediaQueryData.fromView(ui.window).padding.top, 0);
  }

  updateSize() => _size = getSize();

  bool _acceptsExpectedDisplayTopology(SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision) {
    if (expectedSessionId == null) {
      return expectedDisplayTopologyRevision == null;
    }
    if (parent.target?.isCurrentSession(expectedSessionId) != true) {
      return false;
    }
    return expectedDisplayTopologyRevision == null ||
        parent.target?.ffiModel.isCurrentDisplayTopology(
                expectedSessionId, expectedDisplayTopologyRevision) ==
            true;
  }

  updateViewStyle(
      {refreshMousePos = true,
      notify = true,
      SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) async {
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;
    final selectedSessionId = expectedSessionId ?? sessionId;
    final style = await bind.sessionGetViewStyle(sessionId: selectedSessionId);
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;
    if (style == null) {
      return;
    }

    final nextSize = getSize();
    final displayWidth = getDisplayWidth();
    final displayHeight = getDisplayHeight();
    final viewStyle = ViewStyle(
      style: style,
      width: nextSize.width,
      height: nextSize.height,
      displayWidth: displayWidth,
      displayHeight: displayHeight,
    );
    // If only the Custom scale percent changed, proceed to update even if
    // the basic ViewStyle fields are equal.
    // In Custom scale mode, the scale percent can change independently of the other
    // ViewStyle fields and is not captured by the equality check. Therefore, we must
    // allow updates to proceed when style == kRemoteViewStyleCustom, even if the
    // rest of the ViewStyle fields are unchanged.
    if (_lastViewStyle == viewStyle && style != kRemoteViewStyleCustom) {
      return;
    }
    var nextScale = viewStyle.scale;

    // Apply custom scale percent when in Custom mode
    if (style == kRemoteViewStyleCustom) {
      try {
        nextScale = await getSessionCustomScale(selectedSessionId);
      } catch (e, stack) {
        debugPrint('Error in getSessionCustomScale: $e');
        debugPrintStack(stackTrace: stack);
        nextScale = 1.0;
      }
      if (!_acceptsExpectedDisplayTopology(
          expectedSessionId, expectedDisplayTopologyRevision)) return;
    }

    if (_lastViewStyle.style != viewStyle.style) {
      _resetScroll();
    }
    _size = nextSize;
    _lastViewStyle = viewStyle;
    _scale = nextScale;

    _devicePixelRatio = ui.window.devicePixelRatio;
    if (kIgnoreDpi) {
      if (style == kRemoteViewStyleOriginal) {
        _scale = 1.0 / _devicePixelRatio;
      } else if (_scale != 0 && style == kRemoteViewStyleCustom) {
        _scale /= _devicePixelRatio;
      }
    }
    _resetCanvasOffset(displayWidth, displayHeight);
    final overflow = _x < 0 || y < 0;
    if (_imageOverflow.value != overflow) {
      _imageOverflow.value = overflow;
    }
    if (notify) {
      notifyListeners();
    }
    if (!isMobile && refreshMousePos) {
      parent.target?.inputModel.refreshMousePos();
    }
    tryUpdateScrollStyle(Duration.zero, style,
        expectedSessionId: expectedSessionId,
        expectedDisplayTopologyRevision: expectedDisplayTopologyRevision);
  }

  _resetCanvasOffset(int displayWidth, int displayHeight) {
    _x = (size.width - displayWidth * _scale) / 2;
    _y = (size.height - displayHeight * _scale) / 2;
    if (isMobile) {
      _moveToCenterCursor();
    }
  }

  tryUpdateScrollStyle(Duration duration, String? style,
      {SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) async {
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;
    if (_scrollStyle == ScrollStyle.scrollauto) return;
    style ??= await bind.sessionGetViewStyle(
        sessionId: expectedSessionId ?? sessionId);
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;
    if (style != kRemoteViewStyleOriginal && style != kRemoteViewStyleCustom) {
      return;
    }

    _resetScroll();

    Future.delayed(duration, () async {
      if (!_acceptsExpectedDisplayTopology(
          expectedSessionId, expectedDisplayTopologyRevision)) return;
      updateScrollPercent();
    });
  }

  Future<void> updateScrollStyle(
      {SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) async {
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;
    final style = await bind.sessionGetScrollStyle(
        sessionId: expectedSessionId ?? sessionId);
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;

    _scrollStyle =
        style != null ? ScrollStyle.fromString(style) : ScrollStyle.scrollauto;

    if (_scrollStyle != ScrollStyle.scrollauto) {
      _resetScroll();
    }

    notifyListeners();
  }

  Future<void> initializeEdgeScrollEdgeThickness(
      {SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) async {
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;
    final savedValue = await bind.sessionGetEdgeScrollEdgeThickness(
        sessionId: expectedSessionId ?? sessionId);
    if (!_acceptsExpectedDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return;

    if (savedValue != null) {
      _edgeScrollEdgeThickness = savedValue;
    }
  }

  void updateEdgeScrollEdgeThickness(int newThickness) {
    _edgeScrollEdgeThickness = newThickness;
    notifyListeners();
  }

  void update(double x, double y, double scale) {
    _x = x;
    _y = y;
    _scale = scale;
    notifyListeners();
  }

  bool get cursorEmbedded =>
      parent.target?.ffiModel._pi.cursorEmbedded ?? false;

  int getDisplayWidth() {
    final defaultWidth = (isDesktop || isWebDesktop)
        ? kDesktopDefaultDisplayWidth
        : kMobileDefaultDisplayWidth;
    return parent.target?.ffiModel.rect?.width.toInt() ?? defaultWidth;
  }

  int getDisplayHeight() {
    final defaultHeight = (isDesktop || isWebDesktop)
        ? kDesktopDefaultDisplayHeight
        : kMobileDefaultDisplayHeight;
    return parent.target?.ffiModel.rect?.height.toInt() ?? defaultHeight;
  }

  static double get windowBorderWidth => stateGlobal.windowBorderWidth.value;
  static double get tabBarHeight => stateGlobal.tabBarHeight;

  void activateLocalCursor() {
    if (isDesktop || isWebDesktop) {
      try {
        RemoteCursorMovedState.find(id).value = false;
      } catch (e) {
        //
      }
    }
  }

  void updateLocalCursor(double x, double y) {
    // If keyboard is not permitted, do not move cursor when mouse is moving.
    if (parent.target != null && parent.target!.ffiModel.keyboard) {
      // Draw cursor if is not desktop.
      if (!(isDesktop || isWebDesktop)) {
        parent.target!.cursorModel.moveLocal(x, y);
      } else {
        try {
          RemoteCursorMovedState.find(id).value = false;
        } catch (e) {
          //
        }
      }
    }
  }

  void moveDesktopMouse(double x, double y) {
    if (size.width == 0 || size.height == 0) {
      return;
    }

    // On mobile platforms, move the canvas with the cursor.
    final dw = getDisplayWidth() * _scale;
    final dh = getDisplayHeight() * _scale;
    var dxOffset = 0;
    var dyOffset = 0;
    try {
      if (dw > size.width) {
        dxOffset = (x - dw * (x / size.width) - _x).toInt();
      }
      if (dh > size.height) {
        dyOffset = (y - dh * (y / size.height) - _y).toInt();
      }
    } catch (e) {
      debugPrintStack(
          label:
              '(x,y) ($x,$y), (_x,_y) ($_x,$_y), _scale $_scale, display size (${getDisplayWidth()},${getDisplayHeight()}), size $size, , $e');
      return;
    }

    _x += dxOffset;
    _y += dyOffset;
    if (dxOffset != 0 || dyOffset != 0) {
      notifyListeners();
    }
  }

  void initializeEdgeScrollFallback(TickerProvider tickerProvider) {
    _edgeScrollFallbackState?.stop();
    _edgeScrollFallbackState = EdgeScrollFallbackState(this, tickerProvider);
  }

  void disableEdgeScroll() {
    _edgeScrollState = EdgeScrollState.inactive;
    cancelEdgeScroll();
  }

  void rearmEdgeScroll() {
    _edgeScrollState = EdgeScrollState.armed;
  }

  void cancelEdgeScroll() {
    _edgeScrollFallbackState?.stop();
  }

  (Vector2, Vector2) getScrollInfo() {
    final scrollPixel = Vector2(
        _horizontal.hasClients ? _horizontal.position.pixels : 0,
        _vertical.hasClients ? _vertical.position.pixels : 0);

    final max = Vector2(
        _horizontal.hasClients ? _horizontal.position.maxScrollExtent : 0,
        _vertical.hasClients ? _vertical.position.maxScrollExtent : 0);

    return (scrollPixel, max);
  }

  void edgeScrollMouse(double x, double y) async {
    if ((_edgeScrollState == EdgeScrollState.inactive) ||
        (size.width == 0 || size.height == 0) ||
        !(_horizontal.hasClients || _vertical.hasClients)) {
      return;
    }

    if (_edgeScrollState == EdgeScrollState.armed) {
      // Edge scroll is armed to become active once the cursor
      // is observed within the rectangle interior to the
      // edge scroll regions. If the user has just moved the
      // cursor in from outside of the window, edge scrolling
      // doesn't happen yet.
      final clientArea = Rect.fromLTWH(0, 0, size.width, size.height);

      final innerZone = clientArea.deflate(_edgeScrollEdgeThickness.toDouble());

      if (innerZone.contains(Offset(x, y))) {
        _edgeScrollState = EdgeScrollState.active;
      } else {
        // Not yet.
        return;
      }
    }

    var dxOffset = 0.0;
    var dyOffset = 0.0;

    if (x < _edgeScrollEdgeThickness) {
      dxOffset = x - _edgeScrollEdgeThickness;
    } else if (x >= size.width - _edgeScrollEdgeThickness) {
      dxOffset = x - (size.width - _edgeScrollEdgeThickness);
    }

    if (y < _edgeScrollEdgeThickness) {
      dyOffset = y - _edgeScrollEdgeThickness;
    } else if (y >= size.height - _edgeScrollEdgeThickness) {
      dyOffset = y - (size.height - _edgeScrollEdgeThickness);
    }

    var encroachment = Vector2(dxOffset, dyOffset);

    var (scrollPixel, max) = getScrollInfo();

    encroachment.clamp(-scrollPixel, max - scrollPixel);

    if (encroachment.length2 == 0) {
      _edgeScrollFallbackState?.stop();
    } else {
      var bumpAmount = -encroachment;

      // Round away from 0: this ensures that the mouse will be bumped clear of
      // whichever edge scroll zone(s) it is in
      bumpAmount.x += bumpAmount.x.sign * 0.5;
      bumpAmount.y += bumpAmount.y.sign * 0.5;

      var bumpMouseSucceeded = _bumpMouseIsWorking &&
          (await rustDeskWinManager.call(WindowType.Main, kWindowBumpMouse,
                  {"dx": bumpAmount.x.round(), "dy": bumpAmount.y.round()}))
              .result;

      if (bumpMouseSucceeded) {
        performEdgeScroll(encroachment);
      } else {
        // If we can't BumpMouse, then we switch to slower scrolling with autorepeat

        // Don't keep hammering BumpMouse if it's not working.
        _bumpMouseIsWorking = false;

        // Keep scrolling as long as the user is overtop of an edge.
        _edgeScrollFallbackState?.setEncroachment(encroachment);
        _edgeScrollFallbackState?.start();
      }
    }
  }

  void performEdgeScroll(Vector2 delta) {
    var (scrollPixel, max) = getScrollInfo();

    scrollPixel += delta;

    scrollPixel.clamp(Vector2.zero(), max);

    var scrollPixelPercent = scrollPixel.clone();

    scrollPixelPercent.divide(max);
    scrollPixelPercent.scale(100.0);

    setScrollPercent(scrollPixelPercent.x, scrollPixelPercent.y);
    pushScrollPositionToUI(scrollPixel.x, scrollPixel.y);

    notifyListeners();
  }

  panX(double dx) {
    _x += dx;
    if (isMobile) {
      isMobileCanvasChanged = true;
    }
    notifyListeners();
  }

  resetOffset() {
    if (isWebDesktop) {
      updateViewStyle();
    } else {
      _resetCanvasOffset(getDisplayWidth(), getDisplayHeight());
    }
    notifyListeners();
  }

  panY(double dy) {
    _y += dy;
    if (isMobile) {
      isMobileCanvasChanged = true;
    }
    notifyListeners();
  }

  // mobile only
  updateScale(double v, Offset focalPoint) {
    if (parent.target?.imageModel.image == null) return;
    final s = _scale;
    _scale *= v;
    final maxs = parent.target?.imageModel.maxScale ?? 1;
    final mins = parent.target?.imageModel.minScale ?? 1;
    if (_scale > maxs) _scale = maxs;
    if (_scale < mins) _scale = mins;
    // (focalPoint.dx - _x_1) / s1 + displayOriginX = (focalPoint.dx - _x_2) / s2 + displayOriginX
    // _x_2 = focalPoint.dx - (focalPoint.dx - _x_1) / s1 * s2
    _x = focalPoint.dx - (focalPoint.dx - _x) / s * _scale;
    final adjust = getAdjustY();
    // (focalPoint.dy - _y_1 - adjust) / s1 + displayOriginY = (focalPoint.dy - _y_2 - adjust) / s2 + displayOriginY
    // _y_2 = focalPoint.dy - adjust - (focalPoint.dy - _y_1 - adjust) / s1 * s2
    _y = focalPoint.dy - adjust - (focalPoint.dy - _y - adjust) / s * _scale;
    if (isMobile) {
      isMobileCanvasChanged = true;
    }
    notifyListeners();
  }

  // For reset canvas to the last view style
  reset() {
    _scale = _lastViewStyle.scale;
    _devicePixelRatio = ui.window.devicePixelRatio;
    if (kIgnoreDpi && _lastViewStyle.style == kRemoteViewStyleOriginal) {
      _scale = 1.0 / _devicePixelRatio;
    }
    _resetCanvasOffset(getDisplayWidth(), getDisplayHeight());
    bind.sessionSetViewStyle(sessionId: sessionId, value: _lastViewStyle.style);
    notifyListeners();
  }

  clear() {
    _x = 0;
    _y = 0;
    _scale = 1.0;
    _scrollX = 0;
    _scrollY = 0;
    _scrollStyle = ScrollStyle.scrollauto;
    _edgeScrollEdgeThickness = 100;
    _edgeScrollState = EdgeScrollState.inactive;
    _edgeScrollFallbackState?.stop();
    _edgeScrollFallbackState = null;
    _bumpMouseIsWorking = true;
    _imageOverflow.value = false;
    isMobileCanvasChanged = false;
    _lastViewStyle = ViewStyle.defaultViewStyle();
    _timerMobileFocusCanvasCursor?.cancel();
    _timerMobileFocusCanvasCursor = null;
    _timerMobileRestoreCanvasOffset?.cancel();
    _timerMobileRestoreCanvasOffset = null;
    _offsetBeforeMobileSoftKeyboard = null;
    _scaleBeforeMobileSoftKeyboard = null;
  }

  updateScrollPercent() {
    final percentX = _horizontal.hasClients
        ? _horizontal.position.extentBefore /
            (_horizontal.position.extentBefore +
                _horizontal.position.extentInside +
                _horizontal.position.extentAfter)
        : 0.0;
    final percentY = _vertical.hasClients
        ? _vertical.position.extentBefore /
            (_vertical.position.extentBefore +
                _vertical.position.extentInside +
                _vertical.position.extentAfter)
        : 0.0;
    setScrollPercent(percentX, percentY);
  }

  void mobileFocusCanvasCursor() {
    final expectedSessionId = parent.target?.sessionId;
    if (expectedSessionId == null) return;
    _timerMobileFocusCanvasCursor?.cancel();
    _timerMobileFocusCanvasCursor =
        Timer(Duration(milliseconds: 100), () async {
      if (parent.target?.isCurrentSession(expectedSessionId) != true) return;
      updateSize();
      _resetCanvasOffset(getDisplayWidth(), getDisplayHeight());
      notifyListeners();
    });
  }

  void saveMobileOffsetBeforeSoftKeyboard() {
    _timerMobileRestoreCanvasOffset?.cancel();
    _offsetBeforeMobileSoftKeyboard = Offset(_x, _y);
    _scaleBeforeMobileSoftKeyboard = _scale;
  }

  void restoreMobileOffsetAfterSoftKeyboard() {
    final expectedSessionId = parent.target?.sessionId;
    if (expectedSessionId == null) return;
    _timerMobileRestoreCanvasOffset?.cancel();
    _timerMobileFocusCanvasCursor?.cancel();
    final targetOffset = _offsetBeforeMobileSoftKeyboard;
    final targetScale = _scaleBeforeMobileSoftKeyboard;
    if (targetOffset == null || targetScale == null) {
      return;
    }
    _timerMobileRestoreCanvasOffset = Timer(Duration(milliseconds: 100), () {
      if (parent.target?.isCurrentSession(expectedSessionId) != true) return;
      updateSize();
      _x = targetOffset.dx;
      _y = targetOffset.dy;
      _scale = targetScale;
      _offsetBeforeMobileSoftKeyboard = null;
      _scaleBeforeMobileSoftKeyboard = null;
      notifyListeners();
    });
  }

  // mobile only
  // Move the canvas to make the cursor visible(center) on the screen.
  void _moveToCenterCursor() {
    Rect? imageRect = parent.target?.ffiModel.rect;
    if (imageRect == null) {
      // unreachable
      return;
    }
    final maxX = 0.0;
    final minX = _size.width + (imageRect.left - imageRect.right) * _scale;
    final maxY = 0.0;
    final minY = _size.height + (imageRect.top - imageRect.bottom) * _scale;
    Offset offsetToCenter =
        parent.target?.cursorModel.getCanvasOffsetToCenterCursor() ??
            Offset.zero;
    if (minX < 0) {
      _x = min(max(offsetToCenter.dx, minX), maxX);
    } else {
      // _size.width > (imageRect.right, imageRect.left) * _scale, we should not change _x
    }
    if (minY < 0) {
      _y = min(max(offsetToCenter.dy, minY), maxY);
    } else {
      // _size.height > (imageRect.bottom - imageRect.top) * _scale, , we should not change _y
    }
  }
}

// data for cursor
class CursorData {
  final String id;
  final int revision;
  final img2.Image image;
  final Uint8List baseData;
  final double hotxOrigin;
  final double hotyOrigin;
  final int width;
  final int height;

  CursorData({
    required this.id,
    required this.revision,
    required this.image,
    required this.baseData,
    required this.hotxOrigin,
    required this.hotyOrigin,
    required this.width,
    required this.height,
  });

  CursorScaleTarget? scaleTarget(double requestedScale) {
    if (!requestedScale.isFinite || requestedScale <= 0) {
      return null;
    }
    var scale = requestedScale;
    var scaledWidth = width * scale;
    var scaledHeight = height * scale;
    if (!scaledWidth.isFinite || !scaledHeight.isFinite) {
      return null;
    }
    if (scaledWidth > kMaxRemoteCursorPixels ||
        scaledHeight > kMaxRemoteCursorPixels) {
      return null;
    }
    if (scaledWidth < kMinCursorSize || scaledHeight < kMinCursorSize) {
      scale = max(kMinCursorSize / width, kMinCursorSize / height);
      scaledWidth = width * scale;
      scaledHeight = height * scale;
    }
    if (!scaledWidth.isFinite ||
        !scaledHeight.isFinite ||
        scaledWidth < 1 ||
        scaledHeight < 1 ||
        scaledWidth > kMaxRemoteCursorPixels ||
        scaledHeight > kMaxRemoteCursorPixels) {
      return null;
    }
    final targetWidth = scaledWidth.toInt();
    final targetHeight = scaledHeight.toInt();
    final rgbaBytes = _remoteCursorRgbaLen(targetWidth, targetHeight);
    if (rgbaBytes == null) {
      return null;
    }
    final maxHotX = max(0, targetWidth - 1).toDouble();
    final maxHotY = max(0, targetHeight - 1).toDouble();
    return CursorScaleTarget(
      logicalKey: '${id}_${revision}_${targetWidth}x$targetHeight',
      width: targetWidth,
      height: targetHeight,
      hotx: (hotxOrigin * scale).clamp(0.0, maxHotX).toDouble(),
      hoty: (hotyOrigin * scale).clamp(0.0, maxHotY).toDouble(),
      rgbaBytes: rgbaBytes,
    );
  }

  Uint8List? dataForTarget(CursorScaleTarget target) {
    try {
      if (target.width == width && target.height == height) {
        return baseData;
      }
      final resized = img2.copyResize(
        image,
        width: target.width,
        height: target.height,
        interpolation: img2.Interpolation.average,
      );
      if (isWindows) {
        return resized.getBytes(order: img2.ChannelOrder.bgra);
      }
      return Uint8List.fromList(img2.encodePng(resized));
    } catch (_) {
      return null;
    }
  }
}

class CursorScaleTarget {
  const CursorScaleTarget({
    required this.logicalKey,
    required this.width,
    required this.height,
    required this.hotx,
    required this.hoty,
    required this.rgbaBytes,
  });

  final String logicalKey;
  final int width;
  final int height;
  final double hotx;
  final double hoty;
  final int rgbaBytes;
}

class _PreparedCursorShape {
  const _PreparedCursorShape({
    required this.id,
    required this.revision,
    required this.image,
    required this.cursorData,
    required this.rgbaBytes,
  });

  final String id;
  final int revision;
  final ui.Image image;
  final CursorData cursorData;
  final int rgbaBytes;

  void dispose() => image.dispose();
}

class _CursorShapeCacheEntry {
  const _CursorShapeCacheEntry({
    required this.revision,
    required this.image,
    required this.cursorData,
    required this.rgbaBytes,
  });

  final int revision;
  final ui.Image image;
  final CursorData cursorData;
  final int rgbaBytes;
}

const _forbiddenCursorPng =
    'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAAXNSR0IB2cksfwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAkZQTFRFAAAA2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4G2B4GWAwCAAAAAAAA2B4GAAAAMTExAAAAAAAA2B4G2B4G2B4GAAAAmZmZkZGRAQEBAAAA2B4G2B4G2B4G////oKCgAwMDag8D2B4G2B4G2B4Gra2tBgYGbg8D2B4G2B4Gubm5CQkJTwsCVgwC2B4GxcXFDg4OAAAAAAAA2B4G2B4Gz8/PFBQUAAAAAAAA2B4G2B4G2B4G2B4G2B4G2B4G2B4GDgIA2NjYGxsbAAAAAAAA2B4GFwMB4eHhIyMjAAAAAAAA2B4G6OjoLCwsAAAAAAAA2B4G2B4G2B4G2B4G2B4GCQEA4ODgv7+/iYmJY2NjAgICAAAA9PT0Ojo6AAAAAAAAAAAA+/v7SkpKhYWFr6+vAAAAAAAA8/PzOTk5ERER9fX1KCgoAAAAgYGBKioqAAAAAAAApqamlpaWAAAAAAAAAAAAAAAAAAAAAAAALi4u/v7+GRkZAAAAAAAAAAAAAAAAAAAAfn5+AAAAAAAAV1dXkJCQAAAAAAAAAQEBAAAAAAAAAAAA7Hz6BAAAAMJ0Uk5TAAIWEwEynNz6//fVkCAatP2fDUHs6cDD8d0mPfT5fiEskiIR584A0gejr3AZ+P4plfALf5ZiTL85a4ziD6697fzN3UYE4v/4TwrNHuT///tdRKZh///+1U/ZBv///yjb///eAVL//50Cocv//6oFBbPvpGZCbfT//7cIhv///8INM///zBEcWYSZmO7//////1P////ts/////8vBv//////gv//R/z///QQz9sevP///2waXhNO/+fc//8mev/5gAe2r90MAAAByUlEQVR4nGNggANGJmYWBpyAlY2dg5OTi5uHF6s0H78AJxRwCAphyguLgKRExcQlQLSkFLq8tAwnp6ycPNABjAqKQKNElVDllVU4OVVhVquJA81Q10BRoAkUUYbJa4Edoo0sr6PLqaePLG/AyWlohKTAmJPTBFnelAFoixmSAnNOTgsUeQZLTk4rJAXWnJw2EHlbiDyDPCenHZICe04HFrh+RydnBgYWPU5uJAWinJwucPNd3dw9GDw5Ob2QFHBzcnrD7ffx9fMPCOTkDEINhmC4+3x8Q0LDwlEDIoKTMzIKKg9SEBIdE8sZh6SAJZ6Tkx0qD1YQkpCYlIwclCng0AXLQxSEpKalZyCryATKZwkhKQjJzsnNQ1KQXwBUUVhUXBJYWgZREFJeUVmFpMKlWg+anmqgCkJq6+obkG1pLEBTENLU3NKKrIKhrb2js8u4G6Kgpze0r3/CRAZMAHbkpJDJU6ZMmTqtFbuC6TNmhsyaMnsOFlmwgrnzpsxfELJwEXZ5Bp/FS3yWLlsesmLlKuwKVk9Ys5Zh3foN0zduwq5g85atDAzbpqSGbN9RhV0FGOzctWH3lD14FOzdt3H/gQw8Cg4u2gQPAwBYDXXdIH+wqAAAAABJRU5ErkJggg==';
const _defaultCursorPng =
    'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAFmSURBVFiF7dWxSlxREMbx34QFDRowYBchZSxSCWlMCOwD5FGEFHap06UI7KPsAyyEEIQFqxRaCqYTsqCJFsKkuAeRXb17wrqV918dztw55zszc2fo6Oh47MR/e3zO1/iAHWmznHKGQwx9ip/LEbCfazbsoY8j/JLOhcC6sCW9wsjEwJf483AC9nPNc1+lFRwI13d+l3rYFS799rFGxJMqARv2pBXh+72XQ7gWvklPS7TmMl9Ak/M+DqrENvxAv/guKKApuKPWl0/TROK4+LbSqzhuB+OZ3fRSeFPWY+Fkyn56Y29hfgTSpnQ+s98cvorVey66uPlNFxKwZOYLCGfCs5n9NMYVrsp6mvXSoFqpqYFDvMBkStgJJe93dZOwVXxbqUnBENulydSReqUrDhcX0PT2EXarBYS3GNXMhboinBgIl9K71kg0L3+PvyYGdVpruT2MwrF0iotiXfIwus0Dj+OOjo6Of+e7ab74RkpgAAAAAElFTkSuQmCC';

const kPreForbiddenCursorId = "-2";
final preForbiddenCursor = PredefinedCursor(
  png: _forbiddenCursorPng,
  id: kPreForbiddenCursorId,
);
const kPreDefaultCursorId = "-1";
final preDefaultCursor = PredefinedCursor(
  png: _defaultCursorPng,
  id: kPreDefaultCursorId,
  hotxGetter: (double w) => w / 2,
  hotyGetter: (double h) => h / 2,
);

class PredefinedCursor {
  ui.Image? _image;
  img2.Image? _image2;
  CursorData? _cache;
  String png;
  String id;
  double Function(double)? hotxGetter;
  double Function(double)? hotyGetter;

  PredefinedCursor(
      {required this.png, required this.id, this.hotxGetter, this.hotyGetter}) {
    init();
  }

  ui.Image? get image => _image;
  CursorData? get cache => _cache;

  init() {
    _image2 = img2.decodePng(base64Decode(png));
    if (_image2 != null) {
      // The png type of forbidden cursor image is `PngColorType.indexed`.
      if (id == kPreForbiddenCursorId) {
        _image2 = _image2!.convert(format: img2.Format.uint8, numChannels: 4);
      }

      () async {
        final defaultImg = _image2!;
        // This function is called only one time, no need to care about the performance.
        Uint8List data = defaultImg.getBytes(order: img2.ChannelOrder.rgba);
        _image?.dispose();
        _image = await img.decodeImageFromPixels(
            data, defaultImg.width, defaultImg.height, ui.PixelFormat.rgba8888);
        if (_image == null) {
          print("decodeImageFromPixels failed, pre-defined cursor $id");
          return;
        }
        if (isWindows) {
          data = _image2!.getBytes(order: img2.ChannelOrder.bgra);
        } else {
          data = Uint8List.fromList(img2.encodePng(_image2!));
        }

        _cache = CursorData(
          id: id,
          revision: 1,
          image: _image2!.clone(),
          baseData: data,
          hotxOrigin:
              hotxGetter != null ? hotxGetter!(_image2!.width.toDouble()) : 0,
          hotyOrigin:
              hotyGetter != null ? hotyGetter!(_image2!.height.toDouble()) : 0,
          width: _image2!.width,
          height: _image2!.height,
        );
      }();
    }
  }
}

class CursorModel with ChangeNotifier {
  ui.Image? _image;
  CursorData? _cache;
  final LinkedHashMap<String, _CursorShapeCacheEntry> _shapeCache =
      LinkedHashMap();
  int _shapeCacheRgbaBytes = 0;
  final LinkedHashMap<String, _WebCursorShapeSource> _webShapeSources =
      LinkedHashMap();
  int _webShapeSourceRgbaBytes = 0;
  int _webCursorRevision = 0;
  int _webCursorSequence = 0;
  int _webDesiredCursorSequence = 0;
  String _customCursorOwner = Uuid().v4();
  bool _customCursorOwnerRetired = false;
  double _x = -10000;
  double _y = -10000;
  // int.parse(evt['id']) may cause FormatException
  // So we use String here.
  String _id = "-1";
  double _hotx = 0;
  double _hoty = 0;
  double _displayOriginX = 0;
  double _displayOriginY = 0;
  DateTime? _firstUpdateMouseTime;
  Rect? _windowRect;
  List<RemoteWindowCoords> _remoteWindowCoords = [];
  bool gotMouseControl = true;
  DateTime _lastPeerMouse = DateTime.now()
      .subtract(Duration(milliseconds: 3000 * kMouseControlTimeoutMSec));
  String peerId = '';
  WeakReference<FFI> parent;

  // Only for mobile, touch mode
  // To block touch event above the KeyHelpTools
  //
  // A better way is to not listen events from the KeyHelpTools.
  // But we're now using a Container(child: Stack(...)) to wrap the KeyHelpTools,
  // and the listener is on the Container.
  Rect? _keyHelpToolsRect;
  // `lastIsBlocked` is only used in common/widgets/remote_input.dart -> _RawTouchGestureDetectorRegionState -> onDoubleTap()
  // Because onDoubleTap() doesn't have the `event` parameter, we can't get the touch event's position.
  bool _lastIsBlocked = false;
  bool _lastKeyboardIsVisible = false;

  bool get lastKeyboardIsVisible => _lastKeyboardIsVisible;

  Rect? get keyHelpToolsRectToAdjustCanvas =>
      _lastKeyboardIsVisible ? _keyHelpToolsRect : null;
  // The blocked rect is used to block the pointer/touch events in the remote page.
  final List<Rect> _blockedRects = [];
  // Used in shouldBlock().
  // _blockEvents is a flag to block pointer/touch events on the remote image.
  // It is set to true to prevent accidental touch events in the following scenarios:
  //   1. In floating mouse mode, when the scroll circle is shown.
  //   2. In floating mouse widgets mode, when the left/right buttons are moving.
  //   3. In floating mouse widgets mode, when using the virtual joystick.
  // When _blockEvents is true, all pointer/touch events are blocked regardless of the contents of _blockedRects.
  // _blockedRects contains specific rectangular regions where events are blocked; these are checked when _blockEvents is false.
  // In summary: _blockEvents acts as a global block, while _blockedRects provides fine-grained blocking.
  bool _blockEvents = false;
  List<Rect> get blockedRects => List.unmodifiable(_blockedRects);

  set blockEvents(bool v) => _blockEvents = v;

  keyHelpToolsVisibilityChanged(Rect? rect, bool keyboardIsVisible) {
    _keyHelpToolsRect = rect;
    if (rect == null) {
      _lastIsBlocked = false;
    } else {
      // Block the touch event is safe here.
      // `lastIsBlocked` is only used in onDoubleTap() to block the touch event from the KeyHelpTools.
      // `lastIsBlocked` will be set when the cursor is moving or touch somewhere else.
      _lastIsBlocked = true;
    }
    if (isMobile && _lastKeyboardIsVisible != keyboardIsVisible) {
      if (keyboardIsVisible) {
        parent.target?.canvasModel.saveMobileOffsetBeforeSoftKeyboard();
        parent.target?.canvasModel.mobileFocusCanvasCursor();
        parent.target?.canvasModel.isMobileCanvasChanged = false;
      } else {
        parent.target?.canvasModel.restoreMobileOffsetAfterSoftKeyboard();
      }
    }
    _lastKeyboardIsVisible = keyboardIsVisible;
  }

  addBlockedRect(Rect rect) {
    _blockedRects.add(rect);
  }

  removeBlockedRect(Rect rect) {
    _blockedRects.remove(rect);
  }

  get lastIsBlocked => _lastIsBlocked;

  ui.Image? get image => _image;
  CursorData? get cache => _cache;

  double get x => _x - _displayOriginX;
  double get y => _y - _displayOriginY;

  double get devicePixelRatio => parent.target!.canvasModel.devicePixelRatio;

  Offset get offset => Offset(_x, _y);

  double get hotx => _hotx;
  double get hoty => _hoty;

  bool get isPeerControlProtected =>
      DateTime.now().difference(_lastPeerMouse).inMilliseconds <
      kMouseControlTimeoutMSec;

  bool isConnIn2Secs() {
    if (_firstUpdateMouseTime == null) {
      _firstUpdateMouseTime = DateTime.now();
      return true;
    } else {
      return DateTime.now().difference(_firstUpdateMouseTime!).inSeconds < 2;
    }
  }

  CursorModel(this.parent);

  String get customCursorOwner => _customCursorOwner;

  void retireCursorResources() {
    if (!_customCursorOwnerRetired) {
      _customCursorOwnerRetired = true;
      retireCustomCursorOwner(_customCursorOwner);
    }
    _id = kPreDefaultCursorId;
    _image = null;
    _cache = null;
    _hotx = 0;
    _hoty = 0;
    _disposeImages();
    _webShapeSources.clear();
    _webShapeSourceRgbaBytes = 0;
    _webCursorRevision = 0;
    _webCursorSequence = 0;
    _webDesiredCursorSequence = 0;
  }

  // remote physical display coordinate
  // For update pan (mobile), onOneFingerPanStart, onOneFingerPanUpdate, onHoldDragUpdate
  Rect getVisibleRect() {
    final size = parent.target?.canvasModel.getSize() ??
        MediaQueryData.fromView(ui.window).size;
    final xoffset = parent.target?.canvasModel.x ?? 0;
    final yoffset = parent.target?.canvasModel.y ?? 0;
    final scale = parent.target?.canvasModel.scale ?? 1;
    final x0 = _displayOriginX - xoffset / scale;
    final y0 = _displayOriginY - yoffset / scale;
    return Rect.fromLTWH(x0, y0, size.width / scale, size.height / scale);
  }

  Offset getCanvasOffsetToCenterCursor() {
    // Cursor should be at the center of the visible rect.
    // _x = rect.left + rect.width / 2
    // _y = rect.right + rect.height / 2
    // See `getVisibleRect()`
    // _x = _displayOriginX - xoffset / scale + size.width / scale * 0.5;
    // _y = _displayOriginY - yoffset / scale + size.height / scale * 0.5;
    final size = parent.target?.canvasModel.getSize() ??
        MediaQueryData.fromView(ui.window).size;
    final xoffset = (_displayOriginX - _x) * scale + size.width * 0.5;
    final yoffset = (_displayOriginY - _y) * scale + size.height * 0.5;
    return Offset(xoffset, yoffset);
  }

  get scale => parent.target?.canvasModel.scale ?? 1.0;

  // mobile Soft keyboard, block touch event from the KeyHelpTools
  shouldBlock(double x, double y) {
    if (_blockEvents) {
      return true;
    }
    final offset = Offset(x, y);
    for (final rect in _blockedRects) {
      if (isPointInRect(offset, rect)) {
        return true;
      }
    }

    // For help tools rectangle, only block touch event when in touch mode.
    if (!(parent.target?.ffiModel.touchMode ?? false)) {
      return false;
    }
    if (_keyHelpToolsRect != null &&
        isPointInRect(offset, _keyHelpToolsRect!)) {
      return true;
    }
    return false;
  }

  // For touch mode
  Future<bool> move(double x, double y) async {
    if (shouldBlock(x, y)) {
      _lastIsBlocked = true;
      return false;
    }
    _lastIsBlocked = false;
    if (!_moveLocalIfInRemoteRect(x, y)) {
      return false;
    }
    await parent.target?.inputModel.moveMouse(_x, _y);
    return true;
  }

  Future<void> syncCursorPosition() async {
    await parent.target?.inputModel.moveMouse(_x, _y);
  }

  bool isInRemoteRect(Offset offset) {
    return getRemotePosInRect(offset) != null;
  }

  Offset? getRemotePosInRect(Offset offset) {
    final adjust = parent.target?.canvasModel.getAdjustY() ?? 0;
    final newPos = _getNewPos(offset.dx, offset.dy, adjust);
    final visibleRect = getVisibleRect();
    if (!isPointInRect(newPos, visibleRect)) {
      return null;
    }
    final rect = parent.target?.ffiModel.rect;
    if (rect != null) {
      if (!isPointInRect(newPos, rect)) {
        return null;
      }
    }
    return newPos;
  }

  Offset _getNewPos(double x, double y, double adjust) {
    final xoffset = parent.target?.canvasModel.x ?? 0;
    final yoffset = parent.target?.canvasModel.y ?? 0;
    final newX = (x - xoffset) / scale + _displayOriginX;
    final newY = (y - yoffset - adjust) / scale + _displayOriginY;
    return Offset(newX, newY);
  }

  bool _moveLocalIfInRemoteRect(double x, double y) {
    final newPos = getRemotePosInRect(Offset(x, y));
    if (newPos == null) {
      return false;
    }
    _x = newPos.dx;
    _y = newPos.dy;
    notifyListeners();
    return true;
  }

  moveLocal(double x, double y, {double adjust = 0}) {
    final newPos = _getNewPos(x, y, adjust);
    _x = newPos.dx;
    _y = newPos.dy;
    notifyListeners();
  }

  reset() {
    _x = _displayOriginX;
    _y = _displayOriginY;
    parent.target?.inputModel.moveMouse(_x, _y);
    parent.target?.canvasModel.reset();
    notifyListeners();
  }

  updatePan(Offset delta, Offset localPosition, bool touchMode) async {
    if (touchMode) {
      await _handleTouchMode(delta, localPosition);
      return;
    }
    double dx = delta.dx;
    double dy = delta.dy;
    if (parent.target?.imageModel.image == null) return;
    final scale = parent.target?.canvasModel.scale ?? 1.0;
    dx /= scale;
    dy /= scale;
    final r = getVisibleRect();
    var cx = r.center.dx;
    var cy = r.center.dy;
    var tryMoveCanvasX = false;
    final displayRect = parent.target?.ffiModel.rect;
    if (dx > 0) {
      final maxCanvasCanMove = _displayOriginX +
          (displayRect?.width ?? 1280) -
          r.right.roundToDouble();
      tryMoveCanvasX = _x + dx > cx && maxCanvasCanMove > 0;
      if (tryMoveCanvasX) {
        dx = min(dx, maxCanvasCanMove);
      } else {
        final maxCursorCanMove = r.right - _x;
        dx = min(dx, maxCursorCanMove);
      }
    } else if (dx < 0) {
      final maxCanvasCanMove = _displayOriginX - r.left.roundToDouble();
      tryMoveCanvasX = _x + dx < cx && maxCanvasCanMove < 0;
      if (tryMoveCanvasX) {
        dx = max(dx, maxCanvasCanMove);
      } else {
        final maxCursorCanMove = r.left - _x;
        dx = max(dx, maxCursorCanMove);
      }
    }
    var tryMoveCanvasY = false;
    if (dy > 0) {
      final mayCanvasCanMove = _displayOriginY +
          (displayRect?.height ?? 720) -
          r.bottom.roundToDouble();
      tryMoveCanvasY = _y + dy > cy && mayCanvasCanMove > 0;
      if (tryMoveCanvasY) {
        dy = min(dy, mayCanvasCanMove);
      } else {
        final mayCursorCanMove = r.bottom - _y;
        dy = min(dy, mayCursorCanMove);
      }
    } else if (dy < 0) {
      final mayCanvasCanMove = _displayOriginY - r.top.roundToDouble();
      tryMoveCanvasY = _y + dy < cy && mayCanvasCanMove < 0;
      if (tryMoveCanvasY) {
        dy = max(dy, mayCanvasCanMove);
      } else {
        final mayCursorCanMove = r.top - _y;
        dy = max(dy, mayCursorCanMove);
      }
    }

    if (dx == 0 && dy == 0) return;

    Point<double>? newPos;
    final rect = parent.target?.ffiModel.rect;
    if (rect == null) {
      // unreachable
      return;
    }
    newPos = InputModel.getPointInRemoteRect(
        false,
        parent.target?.ffiModel.pi.platform,
        kPointerEventKindMouse,
        kMouseEventTypeDefault,
        _x + dx,
        _y + dy,
        rect,
        buttons: kPrimaryButton);
    if (newPos == null) {
      return;
    }
    dx = newPos.x - _x;
    dy = newPos.y - _y;
    _x = newPos.x;
    _y = newPos.y;
    if (tryMoveCanvasX && dx != 0) {
      parent.target?.canvasModel.panX(-dx * scale);
    }
    if (tryMoveCanvasY && dy != 0) {
      parent.target?.canvasModel.panY(-dy * scale);
    }

    parent.target?.inputModel.moveMouse(_x, _y);
    notifyListeners();
  }

  bool _isInCurrentWindow(double x, double y) {
    final w = _windowRect!.width / devicePixelRatio;
    final h = _windowRect!.width / devicePixelRatio;
    return x >= 0 && y >= 0 && x <= w && y <= h;
  }

  _handleTouchMode(Offset delta, Offset localPosition) async {
    bool isMoved = false;
    if (_remoteWindowCoords.isNotEmpty &&
        _windowRect != null &&
        !_isInCurrentWindow(localPosition.dx, localPosition.dy)) {
      final coords = InputModel.findRemoteCoords(localPosition.dx,
          localPosition.dy, _remoteWindowCoords, devicePixelRatio);
      if (coords != null) {
        double x2 =
            (localPosition.dx - coords.relativeOffset.dx / devicePixelRatio) /
                coords.canvas.scale;
        double y2 =
            (localPosition.dy - coords.relativeOffset.dy / devicePixelRatio) /
                coords.canvas.scale;
        x2 += coords.cursor.offset.dx;
        y2 += coords.cursor.offset.dy;
        await parent.target?.inputModel.moveMouse(x2, y2);
        isMoved = true;
      }
    }
    if (!isMoved) {
      final rect = parent.target?.ffiModel.rect;
      if (rect == null) {
        // unreachable
        return;
      }

      Offset? movementInRect(double x, double y, Rect r) {
        final isXInRect = x >= r.left && x <= r.right;
        final isYInRect = y >= r.top && y <= r.bottom;
        if (!(isXInRect || isYInRect)) {
          return null;
        }
        if (x < r.left) {
          x = r.left;
        } else if (x > r.right) {
          x = r.right;
        }
        if (y < r.top) {
          y = r.top;
        } else if (y > r.bottom) {
          y = r.bottom;
        }
        return Offset(x, y);
      }

      final scale = parent.target?.canvasModel.scale ?? 1.0;
      var movement =
          movementInRect(_x + delta.dx / scale, _y + delta.dy / scale, rect);
      if (movement == null) {
        return;
      }
      movement = movementInRect(movement.dx, movement.dy, getVisibleRect());
      if (movement == null) {
        return;
      }

      _x = movement.dx;
      _y = movement.dy;
      await parent.target?.inputModel.moveMouse(_x, _y);
    }
    notifyListeners();
  }

  void _disposeImages() {
    for (final entry in _shapeCache.values) {
      entry.image.dispose();
    }
    _shapeCache.clear();
    _shapeCacheRgbaBytes = 0;
  }

  Future<_PreparedCursorShape?> prepareCursorShape({
    required String id,
    required int revision,
    required int hotx,
    required int hoty,
    required int width,
    required int height,
    required Uint8List rgba,
    required SessionID expectedSessionId,
  }) {
    return _prepareCursorShape(
      id: id,
      revision: revision,
      hotx: hotx.toDouble(),
      hoty: hoty.toDouble(),
      width: width,
      height: height,
      rgba: rgba,
      expectedSessionId: expectedSessionId,
    );
  }

  _WebCursorShape? admitWebCursorShape(
      Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (_customCursorOwnerRetired ||
        parent.target?.isCurrentSession(expectedSessionId) != true) {
      return null;
    }
    final name = evt['name'];
    final id = evt['id']?.toString();
    if (id == null || !_isRemoteCursorId(id)) {
      return null;
    }
    final sequence = _nextWebCursorSequence();
    if (sequence == null) {
      return null;
    }
    if (name == 'cursor_id') {
      final source = _webShapeSources.remove(id);
      if (source != null) {
        _webShapeSources[id] = source;
      }
      _webDesiredCursorSequence = sequence;
      return _WebCursorShape(id: id, sequence: sequence, source: source);
    }
    if (name != 'cursor_data') {
      return null;
    }
    final previous = _webShapeSources.remove(id);
    if (previous != null) {
      _webShapeSourceRgbaBytes -= previous.rgba.length;
    }
    final hotx = _webCursorCoordinate(evt['hotx']);
    final hoty = _webCursorCoordinate(evt['hoty']);
    final width = int.tryParse(evt['width']?.toString() ?? '');
    final height = int.tryParse(evt['height']?.toString() ?? '');
    if (hotx == null ||
        hoty == null ||
        width == null ||
        height == null) {
      _webDesiredCursorSequence = sequence;
      return _WebCursorShape(id: id, sequence: sequence);
    }

    final expectedLen = _remoteCursorRgbaLen(width, height);
    final colorsJson = evt['colors'];
    if (expectedLen == null ||
        hotx < 0 ||
        hoty < 0 ||
        hotx >= width ||
        hoty >= height ||
        colorsJson is! String ||
        colorsJson.length > expectedLen * 4 + 2) {
      _webDesiredCursorSequence = sequence;
      return _WebCursorShape(id: id, sequence: sequence);
    }

    dynamic decoded;
    try {
      decoded = json.decode(colorsJson);
    } catch (_) {
      _webDesiredCursorSequence = sequence;
      return _WebCursorShape(id: id, sequence: sequence);
    }
    if (decoded is! List || decoded.length != expectedLen) {
      _webDesiredCursorSequence = sequence;
      return _WebCursorShape(id: id, sequence: sequence);
    }
    final rgba = Uint8List(expectedLen);
    for (var i = 0; i < decoded.length; i++) {
      final value = decoded[i];
      if (value is! int || value < 0 || value > 255) {
        _webDesiredCursorSequence = sequence;
        return _WebCursorShape(id: id, sequence: sequence);
      }
      rgba[i] = value;
    }
    if (_webCursorRevision >= 0x1fffffffffffff) {
      _webShapeSources.clear();
      _webShapeSourceRgbaBytes = 0;
      _webDesiredCursorSequence = sequence;
      return _WebCursorShape(id: id, sequence: sequence);
    }
    _webCursorRevision += 1;
    final source = _WebCursorShapeSource(
      id: id,
      revision: _webCursorRevision,
      hotx: hotx,
      hoty: hoty,
      width: width,
      height: height,
      rgba: rgba,
    );
    _webShapeSources[id] = source;
    _webShapeSourceRgbaBytes += rgba.length;
    while (_webShapeSources.length > kCursorShapeCacheMaxEntries ||
        _webShapeSourceRgbaBytes > kCursorShapeCacheMaxRgbaBytes) {
      final victim = _webShapeSources.keys.first;
      final removed = _webShapeSources.remove(victim);
      if (removed != null) {
        _webShapeSourceRgbaBytes -= removed.rgba.length;
      }
    }
    _webDesiredCursorSequence = sequence;
    return _WebCursorShape(id: id, sequence: sequence, source: source);
  }

  int? _nextWebCursorSequence() {
    if (_webCursorSequence >= 0x1fffffffffffff) {
      _webShapeSources.clear();
      _webShapeSourceRgbaBytes = 0;
      _webDesiredCursorSequence = 0;
      return null;
    }
    _webCursorSequence += 1;
    return _webCursorSequence;
  }

  bool isCurrentWebCursorShape(
          _WebCursorShape shape, SessionID expectedSessionId) =>
      parent.target?.isCurrentSession(expectedSessionId) == true &&
      shape.sequence == _webDesiredCursorSequence;

  Future<_PreparedCursorShape?> prepareWebCursorShape(
      _WebCursorShape shape, SessionID expectedSessionId) {
    final source = shape.source;
    if (source == null || !isCurrentWebCursorShape(shape, expectedSessionId)) {
      return Future.value(null);
    }
    return _prepareCursorShape(
      id: source.id,
      revision: source.revision,
      hotx: source.hotx.toDouble(),
      hoty: source.hoty.toDouble(),
      width: source.width,
      height: source.height,
      rgba: source.rgba,
      expectedSessionId: expectedSessionId,
    );
  }

  Future<_PreparedCursorShape?> _prepareCursorShape({
    required String id,
    required int revision,
    required double hotx,
    required double hoty,
    required int width,
    required int height,
    required Uint8List rgba,
    required SessionID expectedSessionId,
  }) async {
    if (parent.target?.isCurrentSession(expectedSessionId) != true ||
        _customCursorOwnerRetired ||
        !_isRemoteCursorId(id) ||
        revision <= 0 ||
        !hotx.isFinite ||
        !hoty.isFinite ||
        hotx < 0 ||
        hoty < 0 ||
        hotx >= width ||
        hoty >= height) {
      return null;
    }
    final expectedLen = _remoteCursorRgbaLen(width, height);
    if (expectedLen == null || rgba.length != expectedLen) {
      return null;
    }
    final ownedRgba = Uint8List.fromList(rgba);
    ui.Image? decodedImage;
    try {
      decodedImage = await img.decodeImageFromPixels(
          ownedRgba, width, height, ui.PixelFormat.rgba8888);
      if (decodedImage == null) {
        return null;
      }
      if (_customCursorOwnerRetired ||
          parent.target?.isCurrentSession(expectedSessionId) != true) {
        decodedImage.dispose();
        return null;
      }
      final image = img2.Image.fromBytes(
        width: width,
        height: height,
        bytes: ownedRgba.buffer,
        order: img2.ChannelOrder.rgba,
      );
      final baseData = isWindows
          ? image.getBytes(order: img2.ChannelOrder.bgra)
          : Uint8List.fromList(img2.encodePng(image));
      if (_customCursorOwnerRetired ||
          parent.target?.isCurrentSession(expectedSessionId) != true) {
        decodedImage.dispose();
        return null;
      }
      return _PreparedCursorShape(
        id: id,
        revision: revision,
        image: decodedImage,
        cursorData: CursorData(
          id: id,
          revision: revision,
          image: image,
          baseData: baseData,
          hotxOrigin: hotx,
          hotyOrigin: hoty,
          width: width,
          height: height,
        ),
        rgbaBytes: expectedLen,
      );
    } catch (_) {
      decodedImage?.dispose();
      return null;
    }
  }

  bool commitCursorShape(
      _PreparedCursorShape prepared, SessionID expectedSessionId) {
    if (_customCursorOwnerRetired ||
        parent.target?.isCurrentSession(expectedSessionId) != true) {
      prepared.dispose();
      return false;
    }
    final previous = _shapeCache.remove(prepared.id);
    if (previous != null) {
      _shapeCacheRgbaBytes -= previous.rgbaBytes;
      previous.image.dispose();
    }
    _shapeCache[prepared.id] = _CursorShapeCacheEntry(
      revision: prepared.revision,
      image: prepared.image,
      cursorData: prepared.cursorData,
      rgbaBytes: prepared.rgbaBytes,
    );
    _shapeCacheRgbaBytes += prepared.rgbaBytes;
    _id = prepared.id;
    _evictCursorShapes();
    return _activateCursorShape(prepared.id, prepared.revision);
  }

  bool activateCursorShape(
      String id, int? revision, SessionID expectedSessionId) {
    if (_customCursorOwnerRetired ||
        parent.target?.isCurrentSession(expectedSessionId) != true) {
      return false;
    }
    if (_activateCursorShape(id, revision)) {
      return true;
    }
    setCursorUnavailable(expectedSessionId);
    return false;
  }

  bool hasCursorShape(
      String id, int revision, SessionID expectedSessionId) {
    if (_customCursorOwnerRetired ||
        parent.target?.isCurrentSession(expectedSessionId) != true) {
      return false;
    }
    return _shapeCache[id]?.revision == revision;
  }

  bool _activateCursorShape(String id, int? revision) {
    final entry = _shapeCache[id];
    if (entry == null || (revision != null && entry.revision != revision)) {
      return false;
    }
    _shapeCache.remove(id);
    _shapeCache[id] = entry;
    _id = id;
    _image = entry.image;
    _cache = entry.cursorData;
    _hotx = entry.cursorData.hotxOrigin;
    _hoty = entry.cursorData.hotyOrigin;
    _notifyCursorListeners();
    return true;
  }

  void _evictCursorShapes() {
    while (_shapeCache.length > kCursorShapeCacheMaxEntries ||
        _shapeCacheRgbaBytes > kCursorShapeCacheMaxRgbaBytes) {
      String? victim;
      for (final id in _shapeCache.keys) {
        if (id != _id) {
          victim = id;
          break;
        }
      }
      if (victim == null) {
        break;
      }
      final removed = _shapeCache.remove(victim);
      if (removed != null) {
        _shapeCacheRgbaBytes -= removed.rgbaBytes;
        removed.image.dispose();
      }
    }
  }

  void setCursorUnavailable(SessionID expectedSessionId) {
    if (_customCursorOwnerRetired ||
        parent.target?.isCurrentSession(expectedSessionId) != true) {
      return;
    }
    _id = kPreDefaultCursorId;
    _image = null;
    _cache = null;
    _hotx = 0;
    _hoty = 0;
    _notifyCursorListeners();
  }

  void _notifyCursorListeners() {
    try {
      notifyListeners();
    } catch (error) {
      debugPrint(
          'Cursor-shape listener notification failed: ${error.runtimeType}');
    }
  }

  /// Update the cursor position.
  bool updateCursorPosition(int x, int y, String id,
      SessionID expectedSessionId, int expectedDisplayTopologyRevision) {
    if (parent.target?.ffiModel.isCurrentDisplayTopology(
            expectedSessionId, expectedDisplayTopologyRevision) !=
        true) {
      return false;
    }
    if (!isConnIn2Secs()) {
      gotMouseControl = false;
      _lastPeerMouse = DateTime.now();
    }
    _x = x.toDouble();
    _y = y.toDouble();
    try {
      RemoteCursorMovedState.find(id).value = true;
    } catch (e) {
      //
    }
    notifyListeners();
    return true;
  }

  updateDisplayOrigin(double x, double y, {updateCursorPos = true}) {
    _displayOriginX = x;
    _displayOriginY = y;
    if (updateCursorPos) {
      _x = x + 1;
      _y = y + 1;
      parent.target?.inputModel.moveMouse(x, y);
    }
    parent.target?.canvasModel.resetOffset();
    notifyListeners();
  }

  updateDisplayOriginWithCursor(
      double x, double y, double xCursor, double yCursor) {
    _displayOriginX = x;
    _displayOriginY = y;
    _x = xCursor;
    _y = yCursor;
    parent.target?.inputModel.moveMouse(x, y);
    notifyListeners();
  }

  clear() {
    retireCursorResources();
    _customCursorOwner = Uuid().v4();
    _customCursorOwnerRetired = false;
    _x = -10000;
    _y = -10000;
    _id = "-1";
    _hotx = 0;
    _hoty = 0;
    _displayOriginX = 0;
    _displayOriginY = 0;
    _firstUpdateMouseTime = null;
    _windowRect = null;
    _remoteWindowCoords.clear();
    gotMouseControl = true;
    _lastPeerMouse = DateTime.now()
        .subtract(Duration(milliseconds: 3000 * kMouseControlTimeoutMSec));
    peerId = '';
    _keyHelpToolsRect = null;
    _lastIsBlocked = false;
    _lastKeyboardIsVisible = false;
    _blockedRects.clear();
    _blockEvents = false;
  }

  trySetRemoteWindowCoords() {
    final expectedSessionId = parent.target?.sessionId;
    if (expectedSessionId == null) return;
    Future.delayed(Duration.zero, () async {
      final remoteWindowCoords = <RemoteWindowCoords>[];
      final windowRect =
          await InputModel.fillRemoteCoordsAndGetCurFrame(remoteWindowCoords);
      if (parent.target?.isCurrentSession(expectedSessionId) != true) return;
      _remoteWindowCoords
        ..clear()
        ..addAll(remoteWindowCoords);
      _windowRect = windowRect;
    });
  }

  clearRemoteWindowCoords() {
    _windowRect = null;
    _remoteWindowCoords.clear();
  }
}

class QualityMonitorData {
  String? speed;
  String? fps;
  String? delay;
  String? targetBitrate;
  String? codecFormat;
  String? chroma;
}

class QualityMonitorModel with ChangeNotifier {
  WeakReference<FFI> parent;

  QualityMonitorModel(this.parent);
  var _show = false;
  var _data = QualityMonitorData();

  bool get show => _show;
  QualityMonitorData get data => _data;

  checkShowQualityMonitor(SessionID sessionId) async {
    final show = await bind.sessionGetToggleOption(
            sessionId: sessionId, arg: 'show-quality-monitor') ==
        true;
    if (parent.target?.isCurrentSession(sessionId) != true) return;
    if (_show != show) {
      _show = show;
      notifyListeners();
    }
  }

  void reset() {
    _show = false;
    _data = QualityMonitorData();
  }

  updateQualityStatus(Map<String, dynamic> evt) {
    try {
      if (evt.containsKey('speed') && (evt['speed'] as String).isNotEmpty) {
        _data.speed = evt['speed'];
      }
      if (evt.containsKey('fps') && (evt['fps'] as String).isNotEmpty) {
        final fps = jsonDecode(evt['fps']) as Map<String, dynamic>;
        final pi = parent.target?.ffiModel.pi;
        if (pi != null) {
          final currentDisplay = pi.currentDisplay;
          if (currentDisplay != kAllDisplayValue) {
            final fps2 = fps[currentDisplay.toString()];
            if (fps2 != null) {
              _data.fps = fps2.toString();
            }
          } else if (fps.isNotEmpty) {
            final fpsList = [];
            for (var i = 0; i < pi.displays.length; i++) {
              fpsList.add((fps[i.toString()] ?? 0).toString());
            }
            _data.fps = fpsList.join(' ');
          }
        } else {
          _data.fps = null;
        }
      }
      if (evt.containsKey('delay') && (evt['delay'] as String).isNotEmpty) {
        _data.delay = evt['delay'];
      }
      if (evt.containsKey('target_bitrate') &&
          (evt['target_bitrate'] as String).isNotEmpty) {
        _data.targetBitrate = evt['target_bitrate'];
      }
      if (evt.containsKey('codec_format') &&
          (evt['codec_format'] as String).isNotEmpty) {
        _data.codecFormat = evt['codec_format'];
      }
      if (evt.containsKey('chroma') && (evt['chroma'] as String).isNotEmpty) {
        _data.chroma = evt['chroma'];
      }
      notifyListeners();
    } catch (e) {
      //
    }
  }
}

class RecordingModel with ChangeNotifier {
  WeakReference<FFI> parent;
  RecordingModel(this.parent);
  bool _start = false;
  bool get start => _start;

  toggle() async {
    if (isIOS) return;
    final ffi = parent.target;
    if (ffi == null) return;
    final sessionId = ffi.sessionId;
    bool value = !_start;
    if (value) {
      await sessionRefreshVideo(sessionId, ffi.clientOwnerId);
    }
    await bind.sessionRecordScreen(sessionId: sessionId, start: value);
  }

  updateStatus(bool status) {
    _start = status;
    notifyListeners();
  }

  void reset() {
    _start = false;
  }
}

// The index values of `ConnType` are same as rust protobuf.
enum ConnType {
  defaultConn,
  fileTransfer,
  portForward,
  rdp,
  viewCamera,
  terminal
}

/// Flutter state manager and data communication with the Rust core.
class FFI {
  var id = '';
  var version = '';
  var connType = ConnType.defaultConn;
  var closed = false;

  /// dialogManager use late to ensure init after main page binding [globalKey]
  late final dialogManager = OverlayDialogManager();

  late SessionID sessionId;
  late final SessionID clientOwnerId;
  late final ImageModel imageModel; // session
  late final FfiModel ffiModel; // session
  late final CursorModel cursorModel; // session
  late final CanvasModel canvasModel; // session
  late final ServerModel serverModel; // global
  late final ChatModel chatModel; // session
  late final FileModel fileModel; // session
  // R-G4 / R-SV6 (§19): the account (UserModel), address-book (AbModel) and "Accessible devices"
  // (GroupModel) models are EXCISED — a direct-IP fork has no account server. Only the local,
  // login-free peer-tab model + Recent/Favorite peer lists remain.
  late final PeerTabModel peerTabModel; // global
  late final QualityMonitorModel qualityMonitorModel; // session
  late final RecordingModel recordingModel; // session
  late final InputModel inputModel; // session
  late final CmFileModel cmFileModel; // cm
  late final TextureModel textureModel; //session
  late final Peers recentPeersModel; // global
  late final Peers favoritePeersModel; // global
  late final MobileSessionStartQueue<_MobileSessionStartRequest>
      _mobileSessionStarts;
  late _SessionOwner _sessionOwner;
  late DisplaySelectionQueue<_SessionOwner> _displaySelections;
  late SessionEventQueue<_SessionOwner> _sessionEvents;
  late LatestFrameQueue<_SessionOwner, int, Uint8List> _webRgbaFrames;
  late LatestFrameQueue<_SessionOwner, int, _WebCursorPosition>
      _webCursorPositions;
  late LatestFrameQueue<_SessionOwner, int, _WebCursorShape>
      _webCursorShapes;
  Future<bool>? _firstImageInitialization;

  // Terminal model registry for multiple terminals
  final Map<int, TerminalModel> _terminalModels = {};

  // Getter for terminal models
  Map<int, TerminalModel> get terminalModels => _terminalModels;

  bool isCurrentSession(SessionID expectedSessionId) =>
      !closed && sessionId == expectedSessionId;

  bool isCurrentSessionOwner(
          SessionID expectedSessionId, SessionID expectedClientOwnerId) =>
      isCurrentSession(expectedSessionId) &&
      clientOwnerId == expectedClientOwnerId;

  Future<bool> submitDisplaySelection(
      SessionID expectedSessionId,
      SessionID expectedClientOwnerId,
      Future<bool> Function() operation) {
    final expectedOwner =
        _SessionOwner(expectedSessionId, expectedClientOwnerId);
    if (expectedOwner != _sessionOwner) {
      return Future.value(false);
    }
    return _displaySelections.submit(expectedOwner, operation);
  }

  Future<SessionEventDisposition> submitSessionEvent(
      SessionID expectedSessionId,
      SessionID expectedClientOwnerId,
      Future<void> Function() operation) {
    final expectedOwner =
        _SessionOwner(expectedSessionId, expectedClientOwnerId);
    if (expectedOwner != _sessionOwner) {
      return Future.value(SessionEventDisposition.retired);
    }
    return _sessionEvents.submit(expectedOwner, operation);
  }

  bool submitWebCursorPosition(
      SessionID expectedSessionId,
      SessionID expectedClientOwnerId,
      String peerId,
      int x,
      int y) {
    final expectedOwner =
        _SessionOwner(expectedSessionId, expectedClientOwnerId);
    if (expectedOwner != _sessionOwner) {
      return false;
    }
    final sessionEvents = _sessionEvents;
    return _webCursorPositions.submitObserved(
        expectedOwner, 0, _WebCursorPosition(x, y), (position) async {
      final topologyRevision = await _displayTopologyAfterCheckpoint(
          sessionEvents, expectedOwner, expectedSessionId);
      if (topologyRevision == null) return;
      cursorModel.updateCursorPosition(position.x, position.y, peerId,
          expectedSessionId, topologyRevision);
    }, onError: (error, stackTrace) {
      debugPrint('Web cursor publication failed: ${error.runtimeType}');
      _reportSessionStreamFailure(expectedSessionId, peerId,
          'The remote session state became inconsistent');
    });
  }

  bool submitWebCursorShape(
      SessionID expectedSessionId,
      SessionID expectedClientOwnerId,
      String peerId,
      _WebCursorShape shape) {
    final expectedOwner =
        _SessionOwner(expectedSessionId, expectedClientOwnerId);
    if (expectedOwner != _sessionOwner) {
      return false;
    }
    return _webCursorShapes.submitObserved(
        expectedOwner,
        0,
        shape,
        (current) =>
            _handleWebCursorShape(expectedOwner, expectedSessionId, current),
        onError: (error, stackTrace) {
      debugPrint('Web cursor-shape publication failed: ${error.runtimeType}');
      _reportSessionStreamFailure(expectedSessionId, peerId,
          'The remote session state became inconsistent');
    });
  }

  void _installSessionOwner(SessionID nextSessionId) {
    final nextOwner = _SessionOwner(nextSessionId, clientOwnerId);
    _sessionOwner = nextOwner;
    _displaySelections = DisplaySelectionQueue(nextOwner);
    _sessionEvents = SessionEventQueue(nextOwner);
    _webRgbaFrames = LatestFrameQueue(nextOwner);
    _webCursorPositions = LatestFrameQueue(nextOwner, maxKeys: 1);
    _webCursorShapes = LatestFrameQueue(nextOwner, maxKeys: 1);
    _firstImageInitialization = null;
  }

  void _retireSessionOwner(SessionID retiringSessionId) {
    final retiringOwner =
        _SessionOwner(retiringSessionId, clientOwnerId);
    final sessionEventsRetired = _sessionEvents.retire(retiringOwner);
    final displaySelectionsRetired = _displaySelections.retire(retiringOwner);
    final webRgbaFramesRetired = _webRgbaFrames.retire(retiringOwner);
    final webCursorPositionsRetired =
        _webCursorPositions.retire(retiringOwner);
    final webCursorShapesRetired = _webCursorShapes.retire(retiringOwner);
    if (!sessionEventsRetired ||
        !displaySelectionsRetired ||
        !webRgbaFramesRetired ||
        !webCursorPositionsRetired ||
        !webCursorShapesRetired) {
      throw StateError('session owner changed before retirement');
    }
    ffiModel.retireEventListener(retiringSessionId);
    cursorModel.retireCursorResources();
    _firstImageInitialization = null;
  }

  FFI(SessionID? sId) {
    sessionId = sId ?? Uuid().v4obj();
    // A desktop tab-to-window transfer intentionally reuses the connection
    // UUID. The UI owner must still change so delayed work from the old view
    // cannot mutate the replacement handler.
    clientOwnerId = isMobile ? _mobileClientOwnerId : Uuid().v4obj();
    _installSessionOwner(sessionId);
    imageModel = ImageModel(WeakReference(this));
    ffiModel = FfiModel(WeakReference(this));
    cursorModel = CursorModel(WeakReference(this));
    canvasModel = CanvasModel(WeakReference(this));
    serverModel = ServerModel(WeakReference(this));
    chatModel = ChatModel(WeakReference(this));
    fileModel = FileModel(WeakReference(this));
    peerTabModel = PeerTabModel(WeakReference(this));
    qualityMonitorModel = QualityMonitorModel(WeakReference(this));
    recordingModel = RecordingModel(WeakReference(this));
    inputModel = InputModel(WeakReference(this));
    cmFileModel = CmFileModel(WeakReference(this));
    textureModel = TextureModel(WeakReference(this));
    recentPeersModel = Peers(
        name: PeersModelName.recent,
        loadEvent: LoadEvent.recent,
        getInitPeers: null);
    favoritePeersModel = Peers(
        name: PeersModelName.favorite,
        loadEvent: LoadEvent.favorite,
        getInitPeers: null);
    _mobileSessionStarts = MobileSessionStartQueue<_MobileSessionStartRequest>(
        _runMobileSessionStart);
  }

  /// Mobile reuse FFI
  void mobileReset(SessionID previousSessionId) {
    chatModel.close();
    for (final model in _terminalModels.values) {
      model.dispose();
    }
    _terminalModels.clear();
    imageModel.callbacksOnFirstImage.clear();
    imageModel.disposeImage();
    cursorModel.clear();
    ffiModel.clear();
    canvasModel.clear();
    qualityMonitorModel.reset();
    recordingModel.reset();
    inputModel.resetForSession(previousSessionId);
  }

  void _scheduleMobileSessionStart(_MobileSessionStartRequest request) {
    final start = _mobileSessionStarts.submit(request);
    unawaited(start.then<void>((_) {},
        onError: (Object error, StackTrace stackTrace) {
      debugPrint('Mobile session preparation failed: ${error.runtimeType}');
      _reportSessionStreamFailure(request.sessionId, request.peerId,
          'The connection could not be started');
    }));
  }

  Future<void> _runMobileSessionStart(
      _MobileSessionStartRequest request) async {
    try {
      await bind.sessionAddMobile(
        sessionId: request.sessionId,
        clientOwnerId: clientOwnerId,
        id: request.peerId,
        isFileTransfer: request.isFileTransfer,
        isViewCamera: request.isViewCamera,
        isPortForward: request.isPortForward,
        isRdp: request.isRdp,
        isTerminal: request.isTerminal,
        password: request.password,
        isSharedPassword: request.isSharedPassword,
        connToken: request.connToken,
      );
    } catch (error) {
      debugPrint('Mobile session add failed: ${error.runtimeType}');
      _reportSessionStreamFailure(request.sessionId, request.peerId,
          'The connection could not be started');
      return;
    }

    if (!isCurrentSession(request.sessionId)) {
      await _closeNativeSession(request.sessionId);
      return;
    }

    late final Stream<EventToUI> stream;
    try {
      stream = bind.sessionStart(
          sessionId: request.sessionId,
          clientOwnerId: clientOwnerId,
          id: request.peerId);
    } catch (error) {
      debugPrint('Mobile session stream failed to start: ${error.runtimeType}');
      _reportSessionStreamFailure(request.sessionId, request.peerId,
          'The connection could not be started');
      return;
    }
    _listenToSessionStream(
        stream, request.sessionId, request.peerId, null, null);
    if (!request.isFileTransfer &&
        !request.isPortForward &&
        !request.isRdp &&
        !request.isTerminal) {
      unawaited(qualityMonitorModel.checkShowQualityMonitor(request.sessionId));
    }
  }

  Future<void> _closeNativeSession(SessionID closingSessionId) async {
    try {
      await bind.sessionClose(sessionId: closingSessionId);
    } catch (error) {
      debugPrint(
          'Exact native session retirement failed: ${error.runtimeType}');
    }
  }

  Future<void> _awaitMobileSessionStart(SessionID closingSessionId) async {
    final preparation = _mobileSessionStarts.cancelPendingOrGetRunning(
        (request) => request.sessionId == closingSessionId);
    if (preparation == null) {
      return;
    }
    try {
      await preparation;
    } catch (error) {
      debugPrint(
          'Mobile session preparation drain failed: ${error.runtimeType}');
    }
  }

  void _reportSessionStreamFailure(
      SessionID expectedSessionId, String peerId, String text) {
    if (!isCurrentSession(expectedSessionId)) {
      return;
    }
    closed = true;
    _retireSessionOwner(expectedSessionId);
    dialogManager.dismissAll();
    ffiModel.handleMsgBox({
      'type': 'error',
      'title': 'Connection Error',
      'text': text,
      'link': '',
      'hasRetry': 'false',
    }, expectedSessionId, peerId);
    unawaited(_closeNativeSession(expectedSessionId));
  }

  void reportFileDialogFailure(SessionID expectedSessionId) {
    _reportSessionStreamFailure(expectedSessionId, id,
        'The remote file transfer became inconsistent');
  }

  Future<int?> _displayTopologyAfterCheckpoint(
      SessionEventQueue<_SessionOwner> sessionEvents,
      _SessionOwner streamOwner,
      SessionID activeSessionId) async {
    final checkpoint = sessionEvents.checkpoint(streamOwner);
    final disposition = await checkpoint.done;
    if (disposition != SessionEventDisposition.completed ||
        !sessionEvents.isCurrent(checkpoint) ||
        !isCurrentSessionOwner(activeSessionId, streamOwner.clientOwnerId)) {
      return null;
    }
    return ffiModel.currentDisplayTopologyRevision(activeSessionId);
  }

  Future<void> _handleSoftwareRgba(
      SessionEventQueue<_SessionOwner> sessionEvents,
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      int display,
      int publication) async {
    final topologyRevision = await _displayTopologyAfterCheckpoint(
        sessionEvents, streamOwner, activeSessionId);
    if (topologyRevision == null) {
      platformFFI.nextRgba(activeSessionId, display, publication);
      return;
    }

    var imageOwnsAcknowledgement = false;
    try {
      // Copy the exact publication through the generated bridge. Flutter never
      // borrows a pointer into a Rust mailbox across an asynchronous decode.
      final rgba =
          platformFFI.copyRgba(activeSessionId, display, publication);
      if (rgba == null) {
        platformFFI.nextRgba(activeSessionId, display, publication);
        return;
      }
      imageOwnsAcknowledgement = true;
      final presented = await imageModel.onRgba(
          activeSessionId, display, rgba,
          publication: publication,
          expectedDisplayTopologyRevision: topologyRevision);
      if (presented) {
        await onEvent2UIRgba(activeSessionId, topologyRevision,
            imageGeometryInitialized: true);
      }
    } catch (error) {
      if (!imageOwnsAcknowledgement) {
        platformFFI.nextRgba(activeSessionId, display, publication);
      }
      debugPrint('Software RGBA presentation failed: ${error.runtimeType}');
    }
  }

  Future<void> _handleCursorPosition(
      SessionEventQueue<_SessionOwner> sessionEvents,
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      String peerId,
      int x,
      int y,
      int publication) async {
    final topologyRevision = await _displayTopologyAfterCheckpoint(
        sessionEvents, streamOwner, activeSessionId);
    final accepted = platformFFI.takeCursorPosition(
        activeSessionId,
        streamOwner.clientOwnerId,
        x,
        y,
        publication);
    if (!accepted || topologyRevision == null) return;
    cursorModel.updateCursorPosition(
        x, y, peerId, activeSessionId, topologyRevision);
  }

  Future<void> _handleCursorData(
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      String id,
      int revision,
      int hotx,
      int hoty,
      int width,
      int height,
      Uint8List rgba,
      int publication) async {
    final prepared = await cursorModel.prepareCursorShape(
      id: id,
      revision: revision,
      hotx: hotx,
      hoty: hoty,
      width: width,
      height: height,
      rgba: rgba,
      expectedSessionId: activeSessionId,
    );
    final currentOwner = isCurrentSessionOwner(
        activeSessionId, streamOwner.clientOwnerId);
    final shape = prepared;
    final canCommit = currentOwner && shape != null;
    final accepted = platformFFI.takeCursorShape(
      activeSessionId,
      streamOwner.clientOwnerId,
      id,
      revision,
      publication,
      canCommit,
    );
    if (!accepted) {
      shape?.dispose();
      return;
    }
    if (canCommit && shape != null) {
      final committed = cursorModel.commitCursorShape(shape, activeSessionId);
      if (!committed && currentOwner) {
        cursorModel.setCursorUnavailable(activeSessionId);
      }
    } else {
      shape?.dispose();
      if (currentOwner) {
        cursorModel.setCursorUnavailable(activeSessionId);
      }
    }
  }

  Future<void> _handleCursorId(
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      String id,
      int revision,
      int publication) async {
    final currentOwner = isCurrentSessionOwner(
        activeSessionId, streamOwner.clientOwnerId);
    final canActivate = currentOwner &&
        cursorModel.hasCursorShape(id, revision, activeSessionId);
    final accepted = platformFFI.takeCursorShape(
      activeSessionId,
      streamOwner.clientOwnerId,
      id,
      revision,
      publication,
      canActivate,
    );
    if (!accepted) {
      return;
    }
    if (!canActivate ||
        !cursorModel.activateCursorShape(
            id, revision, activeSessionId)) {
      if (currentOwner) {
        cursorModel.setCursorUnavailable(activeSessionId);
      }
    }
  }

  Future<void> _handleCursorUnavailable(
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      String id,
      int publication) async {
    final currentOwner = isCurrentSessionOwner(
        activeSessionId, streamOwner.clientOwnerId);
    final accepted = platformFFI.takeCursorShape(
      activeSessionId,
      streamOwner.clientOwnerId,
      id,
      0,
      publication,
      false,
    );
    if (accepted && currentOwner) {
      cursorModel.setCursorUnavailable(activeSessionId);
    }
  }

  Future<void> _handleTextureRgba(
      SessionEventQueue<_SessionOwner> sessionEvents,
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      int display) async {
    final topologyRevision = await _displayTopologyAfterCheckpoint(
        sessionEvents, streamOwner, activeSessionId);
    if (topologyRevision == null) return;
    debugPrint('EventToUI_Texture display:$display');
    await onEvent2UIRgba(activeSessionId, topologyRevision,
        imageGeometryInitialized: false);
  }

  Future<void> _handleWebRgba(
      SessionEventQueue<_SessionOwner> sessionEvents,
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      int display,
      Uint8List data) async {
    final topologyRevision = await _displayTopologyAfterCheckpoint(
        sessionEvents, streamOwner, activeSessionId);
    if (topologyRevision == null) return;
    final presented = await imageModel.onRgba(activeSessionId, display, data,
        expectedDisplayTopologyRevision: topologyRevision);
    if (presented) {
      await onEvent2UIRgba(activeSessionId, topologyRevision,
          imageGeometryInitialized: true);
    }
  }

  Future<void> _handleWebCursorShape(
      _SessionOwner streamOwner,
      SessionID activeSessionId,
      _WebCursorShape shape) async {
    final prepared =
        await cursorModel.prepareWebCursorShape(shape, activeSessionId);
    final current = isCurrentSessionOwner(
            activeSessionId, streamOwner.clientOwnerId) &&
        cursorModel.isCurrentWebCursorShape(shape, activeSessionId);
    if (!current) {
      prepared?.dispose();
      return;
    }
    if (prepared == null) {
      cursorModel.setCursorUnavailable(activeSessionId);
      return;
    }
    if (!cursorModel.commitCursorShape(prepared, activeSessionId)) {
      cursorModel.setCursorUnavailable(activeSessionId);
    }
  }

  void _observeSessionTask(
      Future<void> task, SessionID activeSessionId, String description) {
    unawaited(task.then<void>((_) {},
        onError: (Object error, StackTrace stackTrace) {
      if (isCurrentSession(activeSessionId)) {
        debugPrint('$description failed: ${error.runtimeType}');
      }
    }));
  }

  void _observeQueuedSessionState(
      Future<SessionEventDisposition> task,
      SessionID activeSessionId,
      String peerId) {
    unawaited(task.then<void>((_) {},
        onError: (Object error, StackTrace stackTrace) {
      debugPrint('Queued session state failed: ${error.runtimeType}');
      _reportSessionStreamFailure(activeSessionId, peerId,
          'The remote session state became inconsistent');
    }));
  }

  void _listenToSessionStream(
    Stream<EventToUI> stream,
    SessionID activeSessionId,
    String peerId,
    int? tabWindowId,
    int? display,
  ) {
    final streamOwner = _SessionOwner(activeSessionId, clientOwnerId);
    if (streamOwner != _sessionOwner) {
      _reportSessionStreamFailure(activeSessionId, peerId,
          'The remote session state became inconsistent');
      return;
    }
    final sessionEvents = _sessionEvents;
    if (isWeb) {
      final webRgbaFrames = _webRgbaFrames;
      platformFFI.setRgbaCallback((int display, Uint8List data) {
        // JS/Wasm may detach or reuse the callback buffer after this returns.
        // Take ownership synchronously, then retain only one running and the
        // latest pending frame for each display while topology work completes.
        final ownedData = Uint8List.fromList(data);
        final frame = webRgbaFrames.submit(
            streamOwner,
            display,
            ownedData,
            (rgba) => _handleWebRgba(sessionEvents, streamOwner,
                activeSessionId, display, rgba));
        unawaited(frame.then<void>((_) {},
            onError: (Object error, StackTrace stackTrace) {
          debugPrint('Web RGBA presentation failed: ${error.runtimeType}');
          _reportSessionStreamFailure(activeSessionId, peerId,
              'The remote session presentation became inconsistent');
        }));
      });
      return;
    }

    final cb = ffiModel.startEventListener(activeSessionId, peerId);
    imageModel.updateUserTextureRender();
    final SimpleWrapper<bool> isToNewWindowNotified = SimpleWrapper(false);
    final streamFinality = SessionStreamFinality();
    // Preserved for the rgba data.
    stream.listen((message) {
      if (closed || sessionId != activeSessionId) return;
      if (tabWindowId != null && !isToNewWindowNotified.value) {
        // Session is ready to be moved to a new window.
        // Get the cached data and handle the cached data.
        final cachedState = sessionEvents.submit(streamOwner, () async {
          final args = jsonEncode({'id': peerId, 'close': display == null});
          final cachedData = await DesktopMultiWindow.invokeMethod(
              tabWindowId, kWindowEventGetCachedSessionData, args);
          if (!isCurrentSession(activeSessionId)) return;
          if (cachedData == null) {
            throw StateError('cached session state is empty');
          }
          final data = CachedPeerData.fromString(cachedData);
          if (data == null) {
            throw StateError('cached session state cannot be decoded');
          }
          ffiModel.setPermissions(data.permissions);
          await ffiModel.handleCachedPeerData(data, peerId, activeSessionId);
          if (!isCurrentSession(activeSessionId)) return;
          await sessionRefreshVideo(activeSessionId, clientOwnerId);
          if (!isCurrentSession(activeSessionId)) return;
          await bind.sessionRequestNewDisplayInitMsgs(
              sessionId: activeSessionId, display: ffiModel.pi.currentDisplay);
        });
        _observeQueuedSessionState(cachedState, activeSessionId, peerId);
        isToNewWindowNotified.value = true;
      }
      if (message is EventToUI_Event) {
        if (message.field0 == 'close') {
          streamFinality.acceptExpectedClose();
          sessionEvents.retire(streamOwner);
          if (isCurrentSessionOwner(
              activeSessionId, streamOwner.clientOwnerId)) {
            closed = true;
            _retireSessionOwner(activeSessionId);
          }
          debugPrint('Exit session event loop');
          return;
        }

        try {
          final decoded = json.decode(message.field0);
          if (decoded is! Map<String, dynamic>) {
            throw FormatException('session event is not an object');
          }
          _observeSessionTask(cb(decoded), activeSessionId, 'Session event');
        } catch (error) {
          debugPrint('Session event decoding failed: ${error.runtimeType}');
          _reportSessionStreamFailure(activeSessionId, peerId,
              'The remote session state became inconsistent');
        }
      } else if (message is EventToUI_Rgba) {
        _observeSessionTask(
            _handleSoftwareRgba(sessionEvents, streamOwner, activeSessionId,
                message.field0, message.field1),
            activeSessionId,
            'Software RGBA presentation');
      } else if (message is EventToUI_CursorPosition) {
        _observeSessionTask(
            _handleCursorPosition(
                sessionEvents,
                streamOwner,
                activeSessionId,
                peerId,
                message.field0,
                message.field1,
                message.field2),
            activeSessionId,
            'Cursor-position presentation');
      } else if (message is EventToUI_CursorData) {
        _observeSessionTask(
            _handleCursorData(
                streamOwner,
                activeSessionId,
                message.field0,
                message.field1,
                message.field2,
                message.field3,
                message.field4,
                message.field5,
                message.field6,
                message.field7),
            activeSessionId,
            'Cursor-shape presentation');
      } else if (message is EventToUI_CursorId) {
        _observeSessionTask(
            _handleCursorId(
                streamOwner,
                activeSessionId,
                message.field0,
                message.field1,
                message.field2),
            activeSessionId,
            'Cursor-shape reference');
      } else if (message is EventToUI_CursorUnavailable) {
        _observeSessionTask(
            _handleCursorUnavailable(
                streamOwner,
                activeSessionId,
                message.field0,
                message.field1),
            activeSessionId,
            'Cursor-shape fallback');
      } else if (message is EventToUI_Texture) {
        _observeSessionTask(
            _handleTextureRgba(sessionEvents, streamOwner, activeSessionId,
                message.field0),
            activeSessionId,
            'Texture presentation');
      }
    }, onError: (Object error, StackTrace stackTrace) {
      sessionEvents.retire(streamOwner);
      if (!streamFinality.acceptUnexpectedTermination()) {
        return;
      }
      debugPrint('Remote session stream failed: ${error.runtimeType}');
      _reportSessionStreamFailure(
          activeSessionId, peerId, 'The connection could not be started');
    }, onDone: () {
      sessionEvents.retire(streamOwner);
      if (!streamFinality.acceptUnexpectedTermination()) {
        return;
      }
      _reportSessionStreamFailure(
          activeSessionId, peerId, 'The connection ended unexpectedly');
    });
  }

  /// Start with the given [id]. Only transfer file if [isFileTransfer], only view camera if [isViewCamera], only port forward if [isPortForward].
  SessionID start(
    String id, {
    bool isFileTransfer = false,
    bool isViewCamera = false,
    bool isPortForward = false,
    bool isRdp = false,
    bool isTerminal = false,
    String? password,
    bool? isSharedPassword,
    String? connToken,
    int? tabWindowId,
    int? display,
    List<int>? displays,
  }) {
    if (isMobile) {
      final previousSessionId = sessionId;
      _retireSessionOwner(previousSessionId);
      mobileReset(previousSessionId);
      sessionId = Uuid().v4obj();
      _installSessionOwner(sessionId);
    }
    final activeSessionId = sessionId;
    closed = false;
    if (isMobile) {
      fileModel.beginSession(activeSessionId);
    }
    assert(
        (!(isPortForward && isViewCamera)) &&
            (!(isViewCamera && isPortForward)) &&
            (!(isPortForward && isFileTransfer)) &&
            (!(isTerminal && isFileTransfer)) &&
            (!(isTerminal && isViewCamera)) &&
            (!(isTerminal && isPortForward)),
        'more than one connect type');
    if (isFileTransfer) {
      connType = ConnType.fileTransfer;
    } else if (isViewCamera) {
      connType = ConnType.viewCamera;
    } else if (isPortForward) {
      connType = ConnType.portForward;
    } else if (isTerminal) {
      connType = ConnType.terminal;
    } else {
      chatModel.resetClientMode();
      connType = ConnType.defaultConn;
      canvasModel.id = id;
      imageModel.id = id;
      cursorModel.peerId = id;
    }

    final isNewPeer = tabWindowId == null;
    this.id = id;
    if (isMobile && isNewPeer) {
      _scheduleMobileSessionStart(_MobileSessionStartRequest(
        sessionId: activeSessionId,
        peerId: id,
        isFileTransfer: isFileTransfer,
        isViewCamera: isViewCamera,
        isPortForward: isPortForward,
        isRdp: isRdp,
        isTerminal: isTerminal,
        password: password ?? '',
        isSharedPassword: isSharedPassword ?? false,
        connToken: connToken,
      ));
      return activeSessionId;
    }

    // If tabWindowId != null, this session is a "tab -> window" one.
    // Else this session is a new one.
    if (isNewPeer) {
      final addRes = bind.sessionAddSync(
        sessionId: activeSessionId,
        clientOwnerId: clientOwnerId,
        id: id,
        isFileTransfer: isFileTransfer,
        isViewCamera: isViewCamera,
        isPortForward: isPortForward,
        isRdp: isRdp,
        isTerminal: isTerminal,
        password: password ?? '',
        isSharedPassword: isSharedPassword ?? false,
        connToken: connToken,
      );
      if (addRes != '') {
        debugPrint('Failed to add session to $id, $addRes');
        _reportSessionStreamFailure(
            activeSessionId, id, 'The connection could not be started');
        return activeSessionId;
      }
    } else if (display != null) {
      if (displays == null) {
        debugPrint(
            'Unreachable, failed to add existed session to $id, the displays is null while display is $display');
        return activeSessionId;
      }
      if (!displays.contains(display) ||
          displays.any((candidate) =>
              candidate < -0x80000000 || candidate > 0x7fffffff)) {
        debugPrint(
            'Unreachable, failed to add existed session to $id, the selected display is incoherent or outside the protocol range');
        _reportSessionStreamFailure(
            activeSessionId, id, 'The connection could not be started');
        return activeSessionId;
      }
      final requestedDisplays = Int32List.fromList(displays);
      final addRes = bind.sessionAddExistedSync(
          id: id,
          sessionId: activeSessionId,
          clientOwnerId: clientOwnerId,
          displays: requestedDisplays,
          isViewCamera: isViewCamera);
      if (addRes != '') {
        debugPrint(
            'Unreachable, failed to add existed session to $id, $addRes');
        _reportSessionStreamFailure(
            activeSessionId, id, 'The connection could not be started');
        return activeSessionId;
      }
      if (ffiModel._beginDisplayTopologyMutation(activeSessionId) == null) {
        _reportSessionStreamFailure(
            activeSessionId, id, 'The connection could not be started');
        return activeSessionId;
      }
      ffiModel.pi.currentDisplay = display;
    }
    if (isDesktop && connType == ConnType.defaultConn) {
      textureModel.updateCurrentDisplay(display ?? 0);
    }
    // FIXME: separate cameras displays or shift all indices.
    if (isDesktop && connType == ConnType.viewCamera) {
      // FIXME: currently the default 0 is not used.
      textureModel.updateCurrentDisplay(display ?? 0);
    }

    if (isDesktop) {
      inputModel.updateTrackpadSpeed();
    }

    // CAUTION: sessionStart() returns the stream immediately. Existing-window
    // capture admission is therefore completed by sessionAddExistedSync above;
    // no display command may depend on asynchronous stream attachment.
    late final Stream<EventToUI> stream;
    // Existing-window display capture was admitted synchronously by
    // sessionAddExistedSync before local currentDisplay state was committed.
    // Stream attachment must not submit a second, independently ordered capture.
    stream = bind.sessionStart(
        sessionId: activeSessionId, clientOwnerId: clientOwnerId, id: id);
    _listenToSessionStream(stream, activeSessionId, id, tabWindowId, display);
    return activeSessionId;
  }

  Future<bool> _initializeFirstImage(
      SessionID expectedSessionId,
      int expectedDisplayTopologyRevision,
      bool imageGeometryInitialized) async {
    bool acceptsTopology() => ffiModel.isCurrentDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision);

    if (!acceptsTopology()) return false;
    if (!imageGeometryInitialized) {
      await canvasModel.updateViewStyle(
          expectedSessionId: expectedSessionId,
          expectedDisplayTopologyRevision:
              expectedDisplayTopologyRevision);
      if (!acceptsTopology()) return false;
      await canvasModel.updateScrollStyle(
          expectedSessionId: expectedSessionId,
          expectedDisplayTopologyRevision:
              expectedDisplayTopologyRevision);
      if (!acceptsTopology()) return false;
      await canvasModel.initializeEdgeScrollEdgeThickness(
          expectedSessionId: expectedSessionId,
          expectedDisplayTopologyRevision:
              expectedDisplayTopologyRevision);
      if (!acceptsTopology()) return false;
    }

    ffiModel.waitForFirstImage.value = false;
    dialogManager.dismissAll();
    for (final cb in imageModel.callbacksOnFirstImage) {
      cb(id);
    }
    return true;
  }

  Future<bool> onEvent2UIRgba(SessionID expectedSessionId,
      int expectedDisplayTopologyRevision,
      {required bool imageGeometryInitialized}) async {
    if (!ffiModel.isCurrentDisplayTopology(
        expectedSessionId, expectedDisplayTopologyRevision)) return false;
    if (ffiModel.waitForImageDialogShow.isTrue) {
      ffiModel.waitForImageDialogShow.value = false;
      ffiModel.waitForImageTimer?.cancel();
      clearWaitingForImage(dialogManager, expectedSessionId);
    }

    while (true) {
      if (!ffiModel.isCurrentDisplayTopology(
          expectedSessionId, expectedDisplayTopologyRevision)) return false;
      if (ffiModel.waitForFirstImage.value != true) {
        return true;
      }

      final inProgress = _firstImageInitialization;
      if (inProgress != null) {
        final completed = await inProgress;
        if (completed) return true;
        continue;
      }
      final initialization = _initializeFirstImage(expectedSessionId,
          expectedDisplayTopologyRevision, imageGeometryInitialized);
      _firstImageInitialization = initialization;
      try {
        return await initialization;
      } finally {
        if (identical(_firstImageInitialization, initialization)) {
          _firstImageInitialization = null;
        }
      }
    }
  }

  /// Login with [password], choose if the client should [remember] it.
  void login(SessionID sessionId, String password, bool remember) {
    bind.sessionLogin(
        sessionId: sessionId, password: password, remember: remember);
  }

  // R-X7 / §18: send2FA (the connection 2FA-code sender) is removed — 2FA is excised.

  /// Close the remote session.
  Future<void> close(
      {bool closeSession = true, SessionID? expectedSessionId}) async {
    final closingSessionId = expectedSessionId ?? sessionId;
    if (closingSessionId == sessionId) {
      closed = true;
      _retireSessionOwner(closingSessionId);
    }
    if (sessionId != closingSessionId) {
      if (closeSession) {
        if (isMobile) {
          await _awaitMobileSessionStart(closingSessionId);
        }
        await bind.sessionClose(sessionId: closingSessionId);
      }
      return;
    }
    chatModel.close();
    // Close all terminal models
    for (final model in _terminalModels.values) {
      model.dispose();
    }
    _terminalModels.clear();
    try {
      if (imageModel.image != null && !isWebDesktop) {
        await setCanvasConfig(
            closingSessionId,
            cursorModel.x,
            cursorModel.y,
            canvasModel.x,
            canvasModel.y,
            canvasModel.scale,
            ffiModel.pi.currentDisplay);
      }
    } finally {
      // Persist state while the exact old native handler still exists, then close that captured
      // connection UUID. A replacement may rotate the shared model during the save, but it cannot
      // be selected by this close. The finally block makes native retirement independent of a
      // best-effort state-persistence failure.
      if (closeSession) {
        if (isMobile) {
          await _awaitMobileSessionStart(closingSessionId);
        }
        await bind.sessionClose(sessionId: closingSessionId);
      }
    }
    if (sessionId != closingSessionId) {
      return;
    }
    imageModel.callbacksOnFirstImage.clear();
    await imageModel.update(null,
        expectedSessionId: closingSessionId, allowClosedSession: true);
    if (sessionId != closingSessionId) {
      return;
    }
    cursorModel.clear();
    ffiModel.clear();
    canvasModel.clear();
    if (isMobile) {
      inputModel.resetForSession(closingSessionId);
    } else {
      inputModel.resetModifiers();
      // Dispose relative mouse mode resources to ensure cursor is restored.
      inputModel.disposeRelativeMouseMode(expectedSessionId: closingSessionId);
      inputModel.disposeSideButtonTracking(expectedSessionId: closingSessionId);
    }
    debugPrint('model $id closed');
    if (sessionId == closingSessionId) {
      id = '';
    }
  }

  void setMethodCallHandler(FMethod callback) {
    platformFFI.setMethodCallHandler(callback);
  }

  Future<bool> invokeMethod(String method, [dynamic arguments]) async {
    return await platformFFI.invokeMethod(method, arguments);
  }

  // Terminal model management
  void registerTerminalModel(int terminalId, TerminalModel model) {
    debugPrint('[FFI] Registering terminal model for terminal $terminalId');
    _terminalModels[terminalId] = model;
  }

  void unregisterTerminalModel(int terminalId) {
    debugPrint('[FFI] Unregistering terminal model for terminal $terminalId');
    _terminalModels.remove(terminalId);
  }

  void routeTerminalResponse(Map<String, dynamic> evt) {
    final int terminalId = TerminalModel.getTerminalIdFromEvt(evt);

    // Route to specific terminal model if it exists
    final model = _terminalModels[terminalId];
    if (model != null) {
      model.handleTerminalResponse(evt);
    }
  }
}

const kInvalidResolutionValue = -1;
const kVirtualDisplayResolutionValue = 0;

class Display {
  double x = 0;
  double y = 0;
  int width = 0;
  int height = 0;
  bool cursorEmbedded = false;
  int originalWidth = kInvalidResolutionValue;
  int originalHeight = kInvalidResolutionValue;
  double _scale = 1.0;
  double get scale => _scale > 1.0 ? _scale : 1.0;

  Display() {
    width = (isDesktop || isWebDesktop)
        ? kDesktopDefaultDisplayWidth
        : kMobileDefaultDisplayWidth;
    height = (isDesktop || isWebDesktop)
        ? kDesktopDefaultDisplayHeight
        : kMobileDefaultDisplayHeight;
  }

  @override
  bool operator ==(Object other) =>
      other is Display &&
      other.runtimeType == runtimeType &&
      _innerEqual(other);

  bool _innerEqual(Display other) =>
      other.x == x &&
      other.y == y &&
      other.width == width &&
      other.height == height &&
      other.cursorEmbedded == cursorEmbedded;

  bool get isOriginalResolutionSet =>
      originalWidth != kInvalidResolutionValue &&
      originalHeight != kInvalidResolutionValue;
  bool get isVirtualDisplayResolution =>
      originalWidth == kVirtualDisplayResolutionValue &&
      originalHeight == kVirtualDisplayResolutionValue;
  bool get isOriginalResolution =>
      width == (originalWidth * scale).round() &&
      height == (originalHeight * scale).round();
}

class Resolution {
  int width = 0;
  int height = 0;
  Resolution(this.width, this.height);

  @override
  String toString() {
    return 'Resolution($width,$height)';
  }
}

class Features {
  bool privacyMode = false;
}

const kInvalidDisplayIndex = -1;

class PeerInfo with ChangeNotifier {
  String version = '';
  String username = '';
  String hostname = '';
  String platform = '';
  bool sasEnabled = false;
  bool isSupportMultiUiSession = false;
  int currentDisplay = 0;
  int primaryDisplay = kInvalidDisplayIndex;
  RxList<Display> displays = <Display>[].obs;
  Features features = Features();
  List<Resolution> resolutions = [];
  Map<String, dynamic> platformAdditions = {};

  RxInt displaysCount = 0.obs;
  RxBool isSet = false.obs;

  bool get isWayland => platformAdditions[kPlatformAdditionsIsWayland] == true;
  bool get isHeadless => platformAdditions[kPlatformAdditionsHeadless] == true;
  bool get isInstalled =>
      platform != kPeerPlatformWindows ||
      platformAdditions[kPlatformAdditionsIsInstalled] == true;
  int get amyuniVirtualDisplayCount =>
      platformAdditions[kPlatformAdditionsAmyuniVirtualDisplays] ?? 0;

  bool get isSupportMultiDisplay =>
      (isDesktop || isWebDesktop) && isSupportMultiUiSession;
  bool get forceTextureRender => currentDisplay == kAllDisplayValue;

  bool get cursorEmbedded => tryGetDisplay()?.cursorEmbedded ?? false;

  bool get isAmyuniIdd =>
      platformAdditions[kPlatformAdditionsIddImpl] == 'amyuni_idd';

  Display? tryGetDisplay({int? display}) {
    if (displays.isEmpty) {
      return null;
    }
    display ??= currentDisplay;
    if (display == kAllDisplayValue) {
      return displays[0];
    } else {
      if (display > 0 && display < displays.length) {
        return displays[display];
      } else {
        return displays[0];
      }
    }
  }

  Display? tryGetDisplayIfNotAllDisplay({int? display}) {
    if (displays.isEmpty) {
      return null;
    }
    display ??= currentDisplay;
    if (display == kAllDisplayValue) {
      return null;
    }
    if (display >= 0 && display < displays.length) {
      return displays[display];
    } else {
      return null;
    }
  }

  List<Display> getCurDisplays() {
    if (currentDisplay == kAllDisplayValue) {
      return displays;
    } else {
      if (currentDisplay >= 0 && currentDisplay < displays.length) {
        return [displays[currentDisplay]];
      } else {
        return [];
      }
    }
  }

  double scaleOfDisplay(int display) {
    if (display >= 0 && display < displays.length) {
      return displays[display].scale;
    }
    return 1.0;
  }

  Rect? getDisplayRect(int display) {
    final d = tryGetDisplayIfNotAllDisplay(display: display);
    if (d == null) return null;
    return Rect.fromLTWH(d.x, d.y, d.width.toDouble(), d.height.toDouble());
  }
}

const canvasKey = 'canvas';

Future<void> setCanvasConfig(
    SessionID sessionId,
    double xCursor,
    double yCursor,
    double xCanvas,
    double yCanvas,
    double scale,
    int currentDisplay) async {
  final p = <String, dynamic>{};
  p['xCursor'] = xCursor;
  p['yCursor'] = yCursor;
  p['xCanvas'] = xCanvas;
  p['yCanvas'] = yCanvas;
  p['scale'] = scale;
  p['currentDisplay'] = currentDisplay;
  await bind.sessionSetFlutterOption(
      sessionId: sessionId, k: canvasKey, v: jsonEncode(p));
}

Future<Map<String, dynamic>?> getCanvasConfig(SessionID sessionId) async {
  if (!isWebDesktop) return null;
  var p =
      await bind.sessionGetFlutterOption(sessionId: sessionId, k: canvasKey);
  if (p == null || p.isEmpty) return null;
  try {
    Map<String, dynamic> m = json.decode(p);
    return m;
  } catch (e) {
    return null;
  }
}

Future<void> initializeCursorAndCanvas(FFI ffi,
    {SessionID? expectedSessionId,
    int? expectedDisplayTopologyRevision}) async {
  bool acceptsExpectedTopology() =>
      expectedSessionId == null
          ? expectedDisplayTopologyRevision == null
          : ffi.isCurrentSession(expectedSessionId) &&
              (expectedDisplayTopologyRevision == null ||
                  ffi.ffiModel.isCurrentDisplayTopology(
                      expectedSessionId, expectedDisplayTopologyRevision));

  if (!acceptsExpectedTopology()) return;
  final selectedSessionId = expectedSessionId ?? ffi.sessionId;
  var p = await getCanvasConfig(selectedSessionId);
  if (!acceptsExpectedTopology()) return;
  int currentDisplay = 0;
  if (p != null) {
    currentDisplay = p['currentDisplay'];
  }
  if (p == null || currentDisplay != ffi.ffiModel.pi.currentDisplay) {
    if (!acceptsExpectedTopology()) return;
    ffi.cursorModel.updateDisplayOrigin(
        ffi.ffiModel.rect?.left ?? 0, ffi.ffiModel.rect?.top ?? 0);
    return;
  }
  double xCursor = p['xCursor'];
  double yCursor = p['yCursor'];
  double xCanvas = p['xCanvas'];
  double yCanvas = p['yCanvas'];
  double scale = p['scale'];
  if (!acceptsExpectedTopology()) return;
  ffi.cursorModel.updateDisplayOriginWithCursor(ffi.ffiModel.rect?.left ?? 0,
      ffi.ffiModel.rect?.top ?? 0, xCursor, yCursor);
  ffi.canvasModel.update(xCanvas, yCanvas, scale);
}

clearWaitingForImage(OverlayDialogManager? dialogManager, SessionID sessionId) {
  dialogManager?.dismissByTag('$sessionId-waiting-for-image');
}
