import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/main.dart';
import 'package:flutter_hbb/mobile/pages/settings_page.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'package:window_manager/window_manager.dart';

import '../common.dart';
import '../common/formatter/id_formatter.dart';
import '../desktop/pages/server_page.dart' as desktop;
import '../desktop/pages/desktop_home_page.dart' show setPasswordDialog;
import '../desktop/widgets/tabbar_widget.dart';
import '../mobile/pages/server_page.dart';
import 'model.dart';

const kLoginDialogTag = "LOGIN";

// R-X7/R-A6: the `use-temporary-password` token is excised (the OTP path is gone; the permanent
// password is the box's sole credential). Only the permanent/both methods survive.
const kUsePermanentPassword = "use-permanent-password";
const kUseBothPasswords = "use-both-passwords";

class ServerModel with ChangeNotifier {
  bool _isStart = false; // Android MainService status
  bool _mediaOk = false;
  bool _inputOk = false;
  bool _audioOk = false;
  bool _fileOk = false;
  // M1/R-G1: the clipboard capability has NO Android runtime permission (no OS "half"). Under the
  // pinned policy (enable-clipboard=Y, R-S16) it is always granted, so it carries no toggle/flag
  // here — it is shown READ-ONLY ("Set by policy") from the funnel, not driven by a model bool.
  bool hideCm = false;
  String _verificationMethod = "";
  // R-X7/R-G4: the rotating OTP credential is excised (no temporary-password backend) — its
  // length / numeric-mode state and the OTP-refresh sync are removed from this model; the
  // permanent password is the box's sole credential.
  String _approveMode = "";
  int _zeroClientLengthCounter = 0;

  final _serverPasswd =
      TextEditingController(text: translate("Generating ..."));

  final tabController = DesktopTabController(tabType: DesktopTabType.cm);

  final List<Client> _clients = [];

  Timer? cmHiddenTimer;

  final _wakelockKey = UniqueKey();

  bool get isStart => _isStart;

  bool get mediaOk => _mediaOk;

  bool get inputOk => _inputOk;

  bool get audioOk => _audioOk;

  bool get fileOk => _fileOk;

  String get verificationMethod {
    final index = [
      kUsePermanentPassword,
      kUseBothPasswords
    ].indexOf(_verificationMethod);
    if (index < 0) {
      return kUseBothPasswords;
    }
    return _verificationMethod;
  }

  String get approveMode => _approveMode;

  TextEditingController get serverPasswd => _serverPasswd;

  List<Client> get clients => _clients;

  final controller = ScrollController();

  WeakReference<FFI> parent;

  ServerModel(this.parent) {
    /*
    // initital _hideCm at startup
    final verificationMethod =
        bind.mainGetOptionSync(key: kOptionVerificationMethod);
    final approveMode = bind.mainGetOptionSync(key: kOptionApproveMode);
    _hideCm = option2bool(
        'allow-hide-cm', bind.mainGetOptionSync(key: 'allow-hide-cm'));
    if (!(approveMode == 'password' &&
        verificationMethod == kUsePermanentPassword)) {
      _hideCm = false;
    }
    */

    timerCallback() async {
      // I-1 / R-G2: the rendezvous `status_num` poll is removed (the mediator is excised; the
      // service-listening indicator is driven by the `stop-service` flag). Only the live CM-window
      // bookkeeping + password model refresh remain.
      if (desktopType == DesktopType.cm) {
        final res = await bind.cmCheckClientsLength(length: _clients.length);
        if (res != null) {
          debugPrint("clients not match!");
          updateClientState(res);
        } else {
          if (_clients.isEmpty) {
            hideCmWindow();
            if (_zeroClientLengthCounter++ == 12) {
              // 6 second
              windowManager.close();
            }
          } else {
            _zeroClientLengthCounter = 0;
            if (!hideCm) showCmWindow();
          }
        }
      }

      updatePasswordModel();
    }

    if (!isTest) {
      Future.delayed(Duration.zero, () async {
        if (await bind.optionSynced()) {
          await timerCallback();
        }
      });
      Timer.periodic(Duration(milliseconds: 500), (timer) async {
        await timerCallback();
      });
    }

    // M2 / R-S16: the inherited "initial keyboard status off on mobile" write
    // (mainSetOption(enable-keyboard, 'N')) is REMOVED — enable-keyboard is policy-pinned Y
    // (config.rs PINNED_SETTINGS), so is_option_can_save rejected it: a dead no-op fired at every
    // mobile startup. Remote input is gated by the on-device AccessibilityService grant (inputOk),
    // not by this option, so nothing depends on the write.
  }

  /// M1: reflect the on-device OS runtime-permission state into the capability flags.
  /// The peer capabilities themselves are policy-pinned Y (R-S16), so the inherited enable-*
  /// writes here (enable-audio/enable-file-transfer = N) were rejected no-ops (is_option_can_save)
  /// that only desynced the local flag — the R-G1 snap-back footgun — and are EXCISED. What remains
  /// is the honest device-permission state each capability needs to actually function on Android:
  ///   audio = RECORD_AUDIO held (Android 10+; below that, capture is unsupported);
  ///   file  = MANAGE_EXTERNAL_STORAGE held.
  /// Clipboard has NO device permission (policy-only), so it carries no flag — it is shown read-only.
  checkAndroidPermission() async {
    _audioOk = androidVersion >= 30 &&
        await AndroidPermissionManager.check(kRecordAudio);

    _fileOk = await AndroidPermissionManager.check(kManageExternalStorage);

    notifyListeners();
  }

  updatePasswordModel() async {
    var update = false;
    final verificationMethod =
        await bind.mainGetOption(key: kOptionVerificationMethod);
    final approveMode = await bind.mainGetOption(key: kOptionApproveMode);
    /*
    var hideCm = option2bool(
        'allow-hide-cm', await bind.mainGetOption(key: 'allow-hide-cm'));
    if (!(approveMode == 'password' &&
        verificationMethod == kUsePermanentPassword)) {
      hideCm = false;
    }
    */
    if (_approveMode != approveMode) {
      _approveMode = approveMode;
      update = true;
    }
    final oldPwdText = _serverPasswd.text;
    // R-X7/R-G3: the permanent password is never shown here (it is set via the menu / Safety
    // settings) — under the pinned use-permanent-password policy (R-S16) this field is always the
    // hidden "-" placeholder; the temporary-password display path (and the stop-service gate it
    // shared) is excised.
    _serverPasswd.text = '-';
    if (oldPwdText != _serverPasswd.text) {
      update = true;
    }
    if (_verificationMethod != verificationMethod) {
      _verificationMethod = verificationMethod;
      update = true;
    }
    /*
    if (_hideCm != hideCm) {
      _hideCm = hideCm;
      if (desktopType == DesktopType.cm) {
        if (hideCm) {
          await hideCmWindow();
        } else {
          await showCmWindow();
        }
      }
      update = true;
    }
    */
    if (update) {
      notifyListeners();
    }
  }

  /// M1 / R-G7 / R-S16: request the Android RECORD_AUDIO runtime permission (Android 10+). This is
  /// an on-device OS-permission ONBOARDING affordance, NOT a policy toggle: enable-audio is
  /// policy-pinned Y (R-S16) and shown READ-ONLY in the UI. There is NO enable-audio config write —
  /// the pin rejects it (is_option_can_save), so the inherited write only made the switch snap back
  /// (the R-G1 misleading-control footgun). The OS grant is one-way from the app (revoke is a
  /// system-settings action), so once it is held there is nothing to toggle off.
  requestAudioPermission() async {
    if (_audioOk) return;
    if (clients.any((c) => !c.disconnected)) {
      await showClientsMayNotBeChangedAlert(parent.target);
    }
    if (!await AndroidPermissionManager.check(kRecordAudio)) {
      final res = await AndroidPermissionManager.request(kRecordAudio);
      if (!res) {
        showToast(translate('Failed'));
        return;
      }
    }
    _audioOk = await AndroidPermissionManager.check(kRecordAudio);
    notifyListeners();
  }

  /// M1 / R-G7 / R-S16: request the Android MANAGE_EXTERNAL_STORAGE runtime permission. On-device
  /// OS-permission onboarding, decoupled from the pinned policy — enable-file-transfer is
  /// policy-pinned Y (R-S16), shown READ-ONLY in the UI. No enable-file-transfer write (the pin
  /// rejects it — the snap-back footgun, R-G1). One-way from the app; read-only once granted.
  requestFilePermission() async {
    if (_fileOk) return;
    if (clients.any((c) => !c.disconnected)) {
      await showClientsMayNotBeChangedAlert(parent.target);
    }
    if (!await AndroidPermissionManager.check(kManageExternalStorage)) {
      final res =
          await AndroidPermissionManager.request(kManageExternalStorage);
      if (!res) {
        showToast(translate('Failed'));
        return;
      }
    }
    _fileOk = await AndroidPermissionManager.check(kManageExternalStorage);
    notifyListeners();
  }

  /// M1 / M2 / R-G7 / R-S16: grant or revoke the Android AccessibilityService that injects remote
  /// input — an on-device OS-permission control, NOT a policy toggle. enable-keyboard is policy-pinned
  /// Y (R-S16) and shown READ-ONLY in the UI; the inherited enable-keyboard write here (the sibling of
  /// the dead startup write and the changeStatue write, all excised by M2) is REMOVED — it was rejected
  /// by the pin and only desynced the state. Grant -> open Accessibility settings (showInputWarnAlert);
  /// revoke -> InputService.disableSelf via the native "stop_input". _inputOk is driven by the native
  /// on_state_changed -> changeStatue("input"), so the row reflects the REAL service state — that native
  /// feedback is the re-sync the M2 note asks for, so no config re-read (the sibling asymmetry) is needed.
  toggleInput() async {
    if (clients.any((c) => !c.disconnected)) {
      await showClientsMayNotBeChangedAlert(parent.target);
    }
    if (_inputOk) {
      parent.target?.invokeMethod("stop_input");
    } else {
      if (parent.target != null) {
        /// the result of toggle-on depends on user actions in the settings page.
        /// handle result, see [ServerModel.changeStatue]
        showInputWarnAlert(parent.target!);
      }
    }
  }

  Future<bool> checkRequestNotificationPermission() async {
    debugPrint("androidVersion $androidVersion");
    if (androidVersion < 33) {
      return true;
    }
    if (await AndroidPermissionManager.check(kAndroid13Notification)) {
      debugPrint("notification permission already granted");
      return true;
    }
    var res = await AndroidPermissionManager.request(kAndroid13Notification);
    debugPrint("notification permission request result: $res");
    return res;
  }

  /// Toggle the screen sharing service.
  toggleService() async {
    if (_isStart) {
      final res = await parent.target?.dialogManager
          .show<bool>((setState, close, context) {
        submit() => close(true);
        return CustomAlertDialog(
          title: Row(children: [
            const Icon(Icons.warning_amber_sharp,
                color: Colors.redAccent, size: 28),
            const SizedBox(width: 10),
            Text(translate("Warning")),
          ]),
          content: Text(translate("android_stop_service_tip")),
          actions: [
            TextButton(onPressed: close, child: Text(translate("Cancel"))),
            TextButton(onPressed: submit, child: Text(translate("OK"))),
          ],
          onSubmit: submit,
          onCancel: close,
        );
      });
      if (res == true) {
        stopService();
      }
    } else {
      await checkRequestNotificationPermission();
      // R-X6: the floating-window overlay permission request is removed — the native
      // floating window is excised, so service start no longer asks for SYSTEM_ALERT_WINDOW.
      if (!await AndroidPermissionManager.check(kManageExternalStorage)) {
        await AndroidPermissionManager.request(kManageExternalStorage);
      }
      // R-G7 (§19): the user-settable "Start on boot" toggle is removed — the controlled
      // box auto-starts on boot unconditionally (BootReceiver, re-homed on
      // RECEIVE_BOOT_COMPLETED alone, gated only on the battery-optimization exemption).
      // The battery-optimization onboarding the spec requires kept is relocated here, to the
      // service-start moment: granting it both keeps the foreground service alive under Doze
      // and lets the re-homed BootReceiver actually start the service on the next boot
      // (so the kept capability is not "left silently broken", R-G7).
      if (!await AndroidPermissionManager.check(
          kRequestIgnoreBatteryOptimizations)) {
        await AndroidPermissionManager.request(kRequestIgnoreBatteryOptimizations);
      }
      final res = await parent.target?.dialogManager
          .show<bool>((setState, close, context) {
        submit() => close(true);
        return CustomAlertDialog(
          title: Row(children: [
            const Icon(Icons.warning_amber_sharp,
                color: Colors.redAccent, size: 28),
            const SizedBox(width: 10),
            Text(translate("Warning")),
          ]),
          content: Text(translate("android_service_will_start_tip")),
          actions: [
            dialogButton("Cancel", onPressed: close, isOutline: true),
            dialogButton("OK", onPressed: submit),
          ],
          onSubmit: submit,
          onCancel: close,
        );
      });
      if (res == true) {
        startService();
      }
    }
  }

  /// Start the screen sharing service.
  Future<void> startService() async {
    // finding D / R-S9: on mobile the controlled side binds NO listener without a
    // permanent password — the Rust core parks fail-closed and refuses every connection —
    // and, before the crash fix, tapping "Start service" with no password bound nothing
    // yet took down the WHOLE app, because the Android Rust core shares the app process
    // and its startup self-check called std::process::exit(1). Gate here, the single
    // chokepoint before init_service, so every mobile start path (the Start button and
    // the media-permission auto-start) is covered: require a permanent password first and
    // route the user to set one. The fork deliberately has NO auto-generated password —
    // the user must choose one — so we prompt rather than fabricate a credential; the
    // service starts once a non-empty password is set (notEmptyCallback re-invokes this).
    // (`permanent-password-set` is is_permanent_password_set() == !get_permanent_password_prs()
    // .is_empty(), the exact condition the Rust park/bail use, so this gate never diverges
    // from the fail-closed backstop.) Desktop is intentionally untouched (it uses the
    // installed --service, and its launch path runs before the widget tree exists).
    if ((isAndroid || isIOS) &&
        (await bind.mainGetCommon(key: 'permanent-password-set')) != 'true') {
      showToast(translate(
          'Please set a permanent password before starting the service.'));
      setPasswordDialog(notEmptyCallback: () => startService());
      return;
    }
    // Optimistically flip _isStart before the awaited native calls so the media-permission
    // callback (changeStatue("media") -> startService when !_isStart) cannot re-enter here.
    _isStart = true;
    notifyListeners();
    try {
      parent.target?.ffiModel.updateEventListener(parent.target!.sessionId, "");
      // R-D7a: the direct listener is service-owned — MainService.onCreate (bound by init_service)
      // starts it via JNI startServer; there is no separate service-enable config write.
      await parent.target?.invokeMethod("init_service");
      updateClientState();
    } catch (e) {
      // Honest status (§19/R-G7): the "service running / reachable on :21118" surface is driven
      // by _isStart, so a start that did NOT actually complete must not leave it asserting a
      // running server. Reset the flag (and notify) so the UI falls back to "Service is not
      // running" rather than showing a false green check. (A user-declined MediaProjection is a
      // separate path already handled by on_media_projection_canceled -> stopService.)
      debugPrint("startService failed: $e");
      _isStart = false;
      notifyListeners();
      return;
    }
    if (isAndroid) {
      androidUpdatekeepScreenOn();
    }
  }

  /// Stop the screen sharing service.
  Future<void> stopService() async {
    _isStart = false;
    closeAll();
    // R-D7a: the real stop is the OS foreground-service lifecycle — invokeMethod("stop_service")
    // -> MainActivity.stop_service -> MainService.destroy() -> onDestroy -> JNI stopServer, which
    // supersedes the service-owned-listener generation so the accept loop drops the socket. There
    // is no stop-service config write (the listener reads no such option, R-D4).
    await parent.target?.invokeMethod("stop_service");
    notifyListeners();
    // for androidUpdatekeepScreenOn only
    WakelockManager.disable(_wakelockKey);
  }


  changeStatue(String name, bool value) {
    debugPrint("changeStatue value $value");
    switch (name) {
      case "media":
        _mediaOk = value;
        if (value && !_isStart) {
          startService();
        }
        break;
      case "input":
        // M2 / R-S16: no enable-keyboard write — the key is policy-pinned Y (R-S16), so the write was
        // rejected; _inputOk simply mirrors the native AccessibilityService state (InputService.isOpen),
        // the honest single source of truth for whether remote input can actually be injected.
        _inputOk = value;
        break;
      default:
        return;
    }
    notifyListeners();
  }

  // force
  updateClientState([String? json]) async {
    if (isTest) return;
    var res = await bind.cmGetClientsState();
    List<dynamic> clientsJson;
    try {
      clientsJson = jsonDecode(res);
    } catch (e) {
      debugPrint("Failed to decode clientsJson: '$res', error $e");
      return;
    }

    final oldClientLenght = _clients.length;
    _clients.clear();
    tabController.state.value.tabs.clear();

    for (var clientJson in clientsJson) {
      try {
        final client = Client.fromJson(clientJson);
        _clients.add(client);
        _addTab(client);
      } catch (e) {
        debugPrint("Failed to decode clientJson '$clientJson', error $e");
      }
    }
    if (desktopType == DesktopType.cm) {
      if (_clients.isEmpty) {
        hideCmWindow();
      } else if (!hideCm) {
        showCmWindow();
      }
    }
    if (_clients.length != oldClientLenght) {
      notifyListeners();
      if (isAndroid) androidUpdatekeepScreenOn();
    }
  }

  void addConnection(Map<String, dynamic> evt) {
    try {
      final client = Client.fromJson(jsonDecode(evt["client"]));
      // R-A2/R-G7: approve-mode is pinned "password", so every incoming client arrives already
      // authorized (post-PAKE). There is no unauthorized / click-to-accept state to render.
      parent.target?.dialogManager.dismissByTag(getLoginDialogTag(client.id));
      final index = _clients.indexWhere((c) => c.id == client.id);
      if (index < 0) {
        _clients.add(client);
      } else {
        if (_clients[index].authorized) {
          _clients[index].privacyMode = client.privacyMode;
          notifyListeners();
          return;
        }
        _clients[index].authorized = true;
        _clients[index].privacyMode = client.privacyMode;
      }
      _addTab(client);
      // remove disconnected
      final index_disconnected = _clients
          .indexWhere((c) => c.disconnected && c.peerId == client.peerId);
      if (index_disconnected >= 0) {
        _clients.removeAt(index_disconnected);
        tabController.remove(index_disconnected);
      }
      if (desktopType == DesktopType.cm && !hideCm) {
        showCmWindow();
      }
      scrollToBottom();
      notifyListeners();
      if (isAndroid) androidUpdatekeepScreenOn();
    } catch (e) {
      debugPrint("Failed to call loginRequest,error:$e");
    }
  }

  void _addTab(Client client) {
    tabController.add(TabInfo(
        key: client.id.toString(),
        label: client.name,
        closable: false,
        onTap: () {},
        page: desktop.buildConnectionCard(client)));
    Future.delayed(Duration.zero, () async {
      if (!hideCm) windowOnTop(null);
    });
    // Only do the hidden task when on Desktop.
    if (client.authorized && isDesktop) {
      cmHiddenTimer = Timer(const Duration(seconds: 3), () {
        if (!hideCm) windowManager.minimize();
        cmHiddenTimer = null;
      });
    }
    parent.target?.chatModel
        .updateConnIdOfKey(MessageKey(client.peerId, client.id));
  }

  handleVoiceCall(Client client, bool accept) {
    parent.target?.invokeMethod("cancel_notification", client.id);
    bind.cmHandleIncomingVoiceCall(id: client.id, accept: accept);
  }

  showVoiceCallDialog(Client client) {
    showClientDialog(
      client,
      'Voice call',
      'Do you accept?',
      'android_new_voice_call_tip',
      () => handleVoiceCall(client, false),
      () => handleVoiceCall(client, true),
    );
  }

  showClientDialog(Client client, String title, String contentTitle,
      String content, VoidCallback onCancel, VoidCallback? onSubmit) {
    parent.target?.dialogManager.show((setState, close, context) {
      cancel() {
        onCancel();
        close();
      }

      submit() {
        onSubmit?.call();
        close();
      }

      return CustomAlertDialog(
        title:
            Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text(translate(title)),
          IconButton(onPressed: close, icon: const Icon(Icons.close))
        ]),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate(contentTitle)),
            ClientInfo(client),
            Text(
              translate(content),
              style: Theme.of(globalKey.currentContext!).textTheme.bodyMedium,
            ),
          ],
        ),
        actions: [
          dialogButton("Dismiss", onPressed: cancel, isOutline: true),
          // R-G7 / R-S9 (§19): for the incoming-connection login dialog the accept
          // callback is null, so NO "Accept" button is shown — approve-mode is pinned
          // 'password', acceptance is automatic, only "Dismiss" (reject) survives.
          // A non-null onSubmit (the post-auth in-session voice-call request, a kept
          // audio capability) still renders its Accept action.
          if (onSubmit != null) dialogButton("Accept", onPressed: submit),
        ],
        // Enter binds to accept ONLY when there is an accept action — so the
        // reject-only login dialog has no Enter→accept path either (R-G7).
        onSubmit: onSubmit == null ? null : submit,
        onCancel: cancel,
      );
    }, tag: getLoginDialogTag(client.id));
  }

  scrollToBottom() {
    if (isDesktop) return;
    Future.delayed(Duration(milliseconds: 200), () {
      controller.animateTo(controller.position.maxScrollExtent,
          duration: Duration(milliseconds: 200),
          curve: Curves.fastLinearToSlowEaseIn);
    });
  }

  void onClientRemove(Map<String, dynamic> evt) {
    try {
      final id = int.parse(evt['id'] as String);
      final close = (evt['close'] as String) == 'true';
      if (_clients.any((c) => c.id == id)) {
        final index = _clients.indexWhere((client) => client.id == id);
        if (index >= 0) {
          if (close) {
            _clients.removeAt(index);
            tabController.remove(index);
          } else {
            _clients[index].disconnected = true;
          }
        }
        parent.target?.dialogManager.dismissByTag(getLoginDialogTag(id));
        parent.target?.invokeMethod("cancel_notification", id);
      }
      if (desktopType == DesktopType.cm && _clients.isEmpty) {
        hideCmWindow();
      }
      if (isAndroid) androidUpdatekeepScreenOn();
      notifyListeners();
    } catch (e) {
      debugPrint("onClientRemove failed,error:$e");
    }
  }

  Future<void> closeAll() async {
    await Future.wait(
        _clients.map((client) => bind.cmCloseConnection(connId: client.id)));
    _clients.clear();
    tabController.state.value.tabs.clear();
    if (isAndroid) androidUpdatekeepScreenOn();
  }

  void jumpTo(int id) {
    final index = _clients.indexWhere((client) => client.id == id);
    tabController.jumpTo(index);
  }

  void updateVoiceCallState(Map<String, dynamic> evt) {
    try {
      final client = Client.fromJson(jsonDecode(evt["client"]));
      final index = _clients.indexWhere((element) => element.id == client.id);
      if (index != -1) {
        _clients[index].inVoiceCall = client.inVoiceCall;
        _clients[index].incomingVoiceCall = client.incomingVoiceCall;
        if (client.incomingVoiceCall) {
          if (isAndroid) {
            showVoiceCallDialog(client);
          } else {
            // Has incoming phone call, let's set the window on top.
            Future.delayed(Duration.zero, () {
              windowOnTop(null);
            });
          }
        }
        notifyListeners();
      }
    } catch (e) {
      debugPrint("updateVoiceCallState failed: $e");
    }
  }

  void androidUpdatekeepScreenOn() async {
    if (!isAndroid) return;
    // R-D7a: keep-screen-on is hard-pinned to "during controlled" — the never / service-on modes
    // are excised, so the screen stays on exactly while a controlled session is active. (R-X6 had
    // already decoupled this from the excised floating-window gate.)
    // Bugfix: the intended predicate is "any live (non-disconnected) client". The old
    // `_clients.map((e) => !e.disconnected).isNotEmpty` discarded the filter — `.map(...).isNotEmpty`
    // is true whenever `_clients` is non-empty — so the wakelock stayed held while a
    // disconnected-but-not-yet-removed client lingered. `.any(...)` applies the predicate. This
    // matches the same `clients.any((c) => !c.disconnected)` idiom used elsewhere in this model.
    final on = _clients.any((e) => !e.disconnected);
    if (on) {
      WakelockManager.enable(_wakelockKey, isServer: true);
    } else {
      WakelockManager.disable(_wakelockKey);
    }
  }
}

enum ClientType {
  remote,
  file,
  camera,
  portForward,
  terminal,
}

class Client {
  int id = 0; // client connections inner count id
  bool authorized = false;
  bool isFileTransfer = false;
  bool isViewCamera = false;
  bool isTerminal = false;
  String portForward = "";
  String name = "";
  String avatar = "";
  String peerId = ""; // peer user's id,show at app
  bool keyboard = false;
  bool clipboard = false;
  bool audio = false;
  bool file = false;
  bool privacyMode = false;
  bool disconnected = false;
  bool fromSwitch = false;
  bool inVoiceCall = false;
  bool incomingVoiceCall = false;

  RxInt unreadChatMessageCount = 0.obs;

  Client(this.id, this.authorized, this.isFileTransfer, this.isViewCamera,
      this.name, this.peerId, this.keyboard, this.clipboard, this.audio);

  Client.fromJson(Map<String, dynamic> json) {
    id = json['id'];
    authorized = json['authorized'];
    isFileTransfer = json['is_file_transfer'];
    // TODO: no entry then default.
    isViewCamera = json['is_view_camera'];
    isTerminal = json['is_terminal'] ?? false;
    portForward = json['port_forward'];
    name = json['name'];
    avatar = json['avatar'] ?? '';
    peerId = json['peer_id'];
    keyboard = json['keyboard'];
    clipboard = json['clipboard'];
    audio = json['audio'];
    file = json['file'];
    privacyMode = json['privacy_mode'] ?? privacyMode;
    disconnected = json['disconnected'];
    fromSwitch = json['from_switch'];
    inVoiceCall = json['in_voice_call'];
    incomingVoiceCall = json['incoming_voice_call'];
  }

  Map<String, dynamic> toJson() {
    final Map<String, dynamic> data = <String, dynamic>{};
    data['id'] = id;
    data['authorized'] = authorized;
    data['is_file_transfer'] = isFileTransfer;
    data['is_view_camera'] = isViewCamera;
    data['is_terminal'] = isTerminal;
    data['port_forward'] = portForward;
    data['name'] = name;
    data['avatar'] = avatar;
    data['peer_id'] = peerId;
    data['keyboard'] = keyboard;
    data['clipboard'] = clipboard;
    data['audio'] = audio;
    data['file'] = file;
    data['privacy_mode'] = privacyMode;
    data['disconnected'] = disconnected;
    data['from_switch'] = fromSwitch;
    data['in_voice_call'] = inVoiceCall;
    data['incoming_voice_call'] = incomingVoiceCall;
    return data;
  }

  ClientType type_() {
    if (isFileTransfer) {
      return ClientType.file;
    } else if (isViewCamera) {
      return ClientType.camera;
    } else if (isTerminal) {
      return ClientType.terminal;
    } else if (portForward.isNotEmpty) {
      return ClientType.portForward;
    } else {
      return ClientType.remote;
    }
  }
}

String getLoginDialogTag(int id) {
  return kLoginDialogTag + id.toString();
}

showInputWarnAlert(FFI ffi) {
  ffi.dialogManager.show((setState, close, context) {
    submit() {
      AndroidPermissionManager.startAction(kActionAccessibilitySettings);
      close();
    }

    return CustomAlertDialog(
      title: Text(translate("How to get Android input permission?")),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(translate("android_input_permission_tip1")),
          const SizedBox(height: 10),
          Text(translate("android_input_permission_tip2")),
          // Android 13+ (API 33) greys out the Accessibility toggle for sideloaded apps as a
          // "Restricted setting" until the user explicitly unblocks it via App info -> (kebab)
          // menu -> "Allow restricted settings" (which requires a lock-screen credential to
          // authenticate). Without this step the [RustDesk Input] toggle simply cannot be turned
          // on, so spell it out — only on the affected platform versions.
          if (androidVersion >= 33) ...[
            const SizedBox(height: 10),
            Text(translate("android_input_permission_tip3_restricted")),
          ],
        ],
      ),
      actions: [
        dialogButton("Cancel", onPressed: close, isOutline: true),
        dialogButton("Open System Setting", onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

Future<void> showClientsMayNotBeChangedAlert(FFI? ffi) async {
  await ffi?.dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate("Permissions")),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(translate("android_permission_may_not_change_tip")),
        ],
      ),
      actions: [
        dialogButton("OK", onPressed: close),
      ],
      onSubmit: close,
      onCancel: close,
    );
  });
}
