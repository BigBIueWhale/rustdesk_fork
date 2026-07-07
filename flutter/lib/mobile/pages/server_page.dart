import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/desktop/pages/desktop_home_page.dart';
import 'package:flutter_hbb/mobile/widgets/dialog.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';

import '../../common.dart';
import '../../common/widgets/dialog.dart';
import '../../consts.dart';
import '../../models/platform_model.dart';
import '../../models/server_model.dart';
import 'home_page.dart';

// R-D7a / R-S9 / R-G1 (verify-ground-truth): the REAL reachability of the direct listener, read
// synchronously from the Rust `direct-listener-bound` signal (the actual bound-TcpListener state) —
// NOT the optimistic Dart `serverModel.isStart`, which is set before init_service and never synced
// from the native service (so it is false after a boot listener-only start even though the listener
// is UP, and stale otherwise). On Android the listener is FGS-owned (R-D7a): bound iff the service
// runs AND a permanent password is set (R-S9 park), and Stop closes it.
bool _directListenerBound() =>
    bind.mainGetCommonSync(key: 'direct-listener-bound') == 'true';
bool _permanentPasswordSet() =>
    bind.mainGetCommonSync(key: 'permanent-password-set') == 'true';

class ServerPage extends StatefulWidget implements PageShape {
  @override
  final title = translate("Share screen");

  @override
  final icon = const Icon(Icons.mobile_screen_share);

  @override
  final appBarActions = (!bind.isDisableSettings() &&
          bind.mainGetBuildinOption(key: kOptionHideSecuritySetting) != 'Y')
      ? [_DropDownAction()]
      : [];

  ServerPage({Key? key}) : super(key: key);

  @override
  State<StatefulWidget> createState() => _ServerPageState();
}

class _DropDownAction extends StatelessWidget {
  _DropDownAction();

  // should only have one action
  final actions = [
    PopupMenuButton<String>(
        tooltip: "",
        icon: const Icon(Icons.more_vert),
        itemBuilder: (context) {
          // R-G4/R-S9/R-X7: approve-mode (pinned "password"), verification-method (pinned
          // "use-permanent-password") and the one-time-password path (R-X7) are all dead — the
          // accept-mode / OTP / verification-method menu items are removed. Change-ID is removed
          // too (R-G4/R-SV5: the numeric ID is dead under the direct-IP model). Only "Set permanent
          // password" remains (the permanent password is the fork's sole credential).
          return [
            if (!isChangePermanentPasswordDisabled())
              PopupMenuItem(
                value: "setPermanentPassword",
                child: Text(translate("Set permanent password")),
              ),
          ];
        },
        onSelected: (value) async {
          if (value == "setPermanentPassword") {
            setPasswordDialog();
          }
        })
  ];

  @override
  Widget build(BuildContext context) {
    return actions[0];
  }
}

class _ServerPageState extends State<ServerPage> {
  @override
  void initState() {
    super.initState();
    gFFI.serverModel.checkAndroidPermission();
  }

  @override
  Widget build(BuildContext context) {
    checkService();
    return ChangeNotifierProvider.value(
        value: gFFI.serverModel,
        child: Consumer<ServerModel>(
            builder: (context, serverModel, child) => SingleChildScrollView(
                  controller: gFFI.serverModel.controller,
                  child: Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.start,
                      children: [
                        buildPresetPasswordWarningMobile(),
                        gFFI.serverModel.isStart
                            ? ServerInfo()
                            : ServiceNotRunningNotification(),
                        const ConnectionManager(),
                        const PermissionChecker(),
                        SizedBox.fromSize(size: const Size(0, 15.0)),
                      ],
                    ),
                  ),
                )));
  }
}

void checkService() async {
  gFFI.invokeMethod("check_service");
  // for Android 10/11, request MANAGE_EXTERNAL_STORAGE permission from system setting page
  if (AndroidPermissionManager.isWaitingFile() && !gFFI.serverModel.fileOk) {
    AndroidPermissionManager.complete(kManageExternalStorage,
        await AndroidPermissionManager.check(kManageExternalStorage));
    debugPrint("file permission finished");
  }
}

class ServiceNotRunningNotification extends StatelessWidget {
  ServiceNotRunningNotification({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final serverModel = Provider.of<ServerModel>(context);

    // BR-15 (§19): "service" mislabels the CAPTURE toggle as the listener. This card controls
    // SCREEN SHARING (MediaProjection capture), distinct from the direct listener. Report the REAL
    // listener state (from the Rust direct-listener-bound signal), NOT a static "port stays open"
    // claim: on Android the listener is FGS-owned (R-D7a), bound iff the service runs AND a
    // permanent password is set (R-S9), and Stop closes it — so an unconditional "port is open"
    // line was false in the stopped state and contradicted android_stop_service_tip.
    final bound = _directListenerBound();
    final passwordSet = _permanentPasswordSet();
    final String portStatus = bound
        ? translate(
            "The port on :21118 is open for connections (e.g. file transfer). Starting screen sharing also shares this device's screen.")
        : passwordSet
            ? translate(
                "The port on :21118 is closed: the service is not running. It opens while the service runs and a permanent password is set; stopping also closes it.")
            : translate(
                "The port on :21118 is closed: no permanent password is set. It opens while the service runs and a permanent password is set.");
    return PaddingCard(
        title: translate("Screen sharing is off"),
        titleIcon:
            const Icon(Icons.warning_amber_sharp, color: Colors.redAccent),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate("android_start_service_tip"),
                    style:
                        const TextStyle(fontSize: 12, color: MyTheme.darkGray))
                .marginOnly(bottom: 8),
            Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(bound ? Icons.check : Icons.info_outline,
                      color: bound ? Colors.green : MyTheme.darkGray, size: 18)
                  .marginOnly(right: 8),
              Expanded(
                  child: Text(portStatus,
                      style: const TextStyle(
                          fontSize: 12, color: MyTheme.darkGray))),
            ]).marginOnly(bottom: 8),
            ElevatedButton.icon(
                icon: const Icon(Icons.play_arrow),
                // R-X7a/§19: the scam-warning social-engineering dialog is excised (it fired on
                // every start because accounts are excised -> userName is always empty); start
                // screen sharing directly.
                onPressed: () {
                  serverModel.toggleService();
                },
                label: Text(translate("Start screen sharing")))
          ],
        ));
  }
}

class ServerInfo extends StatelessWidget {
  final emptyController = TextEditingController(text: "-");

  ServerInfo({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final serverModel = Provider.of<ServerModel>(context);

    const Color colorPositive = Colors.green;
    const Color colorNegative = Colors.red;
    const double iconMarginRight = 15;
    const double iconSize = 24;
    const TextStyle textStyleValue =
        TextStyle(fontSize: 25.0, fontWeight: FontWeight.bold);

    Widget ConnectionStateNotification() {
      // R-G2/R-G7/R-S9 (BR-4 mobile analog, verify-ground-truth): direct-IP — the controlled side
      // listens on the pinned direct port (config::DIRECT_PORT = 21118); no rendezvous
      // "connecting"/"not ready" state. Report TWO distinct, honest facts instead of one static
      // green check:
      //  1. REACHABLE — driven by the REAL Rust `direct-listener-bound` signal (the actual bound
      //     TcpListener), NOT `serverModel.isStart` (an optimistic Dart flag set before init_service
      //     and never synced from the native service — false after a boot listener-only start even
      //     though the listener is UP). `permanent-password-set` only picks the "why not reachable"
      //     wording (no password vs service stopped).
      //  2. Screen capture only actually flows once MediaProjection consent is in hand (mediaOk,
      //     re-synced from native MainService.isReady by the check_service poll) — so the card
      //     must not imply capture is ready before that consent, or after it is lost.
      final reachable = _directListenerBound();
      final passwordSet = _permanentPasswordSet();
      return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Icon(reachable ? Icons.check : Icons.warning_amber_sharp,
                  color: reachable ? colorPositive : colorNegative,
                  size: iconSize)
              .marginOnly(right: iconMarginRight),
          Expanded(
              child: Text(translate(reachable
                  ? 'Reachable on :21118'
                  : passwordSet
                      ? 'Not reachable — the service is not running'
                      : 'Not reachable — set a permanent password to open the port')))
        ]),
        const SizedBox(height: 8),
        Row(children: [
          Icon(serverModel.mediaOk ? Icons.check : Icons.warning_amber_sharp,
                  color: serverModel.mediaOk ? colorPositive : colorNegative,
                  size: iconSize)
              .marginOnly(right: iconMarginRight),
          Expanded(
              child: Text(translate(serverModel.mediaOk
                  ? 'Screen capture ready'
                  : 'Screen capture not ready — grant screen capture below')))
        ]),
      ]);
    }

    return PaddingCard(
        title: translate('Your Device'),
        child: Column(
          children: [
            // R-G4/R-X7/R-G1: the rotating OTP display/refresh row is removed — that credential is
            // excised (R-X7), so under the pinned use-permanent-password policy (R-S16) this row
            // showed only a dead "-"; the permanent password (the fork's sole credential) is set via
            // the "Set permanent password" menu above, so the card needs no redundant password row.
            ConnectionStateNotification()
          ],
        ));
  }
}

class PermissionChecker extends StatefulWidget {
  const PermissionChecker({Key? key}) : super(key: key);

  @override
  State<PermissionChecker> createState() => _PermissionCheckerState();
}

class _PermissionCheckerState extends State<PermissionChecker> {
  @override
  Widget build(BuildContext context) {
    final serverModel = Provider.of<ServerModel>(context);
    final hasAudioPermission = androidVersion >= 30;
    final hideStopService = isAndroid &&
        bind.mainGetBuildinOption(key: kOptionHideStopService) == 'Y';
    final allowPermChangeInAcceptWindow = option2bool(
        kOptionEnablePermChangeInAcceptWindow,
        bind.mainGetBuildinOption(
          key: kOptionEnablePermChangeInAcceptWindow,
        ));
    final permissionChangeLocked = isAndroid &&
        serverModel.clients.any((c) => !c.disconnected) &&
        !allowPermChangeInAcceptWindow;
    return PaddingCard(
        title: translate("Permissions"),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          serverModel.mediaOk && !hideStopService
              ? ElevatedButton.icon(
                      style: ButtonStyle(
                          backgroundColor:
                              MaterialStateProperty.all(Colors.red)),
                      icon: const Icon(Icons.stop),
                      onPressed: serverModel.toggleService,
                      // BR-15 (§19): relabel the CAPTURE toggle honestly — this stops screen
                      // sharing, not the password-gated listener (which the FGS owns, R-D7a).
                      label: Text(translate("Stop screen sharing")))
                  .marginOnly(bottom: 8)
              : SizedBox.shrink(),
          if (!hideStopService || !serverModel.mediaOk)
            PermissionRow(
                translate("Screen Capture"),
                serverModel.mediaOk,
                // R-X7a/§19: scam-warning dialog excised — toggle screen capture directly.
                serverModel.toggleService),
          PermissionRow(
            translate("Input Control"),
            serverModel.inputOk,
            serverModel.toggleInput,
          ),
          PermissionRow(
            translate("Transfer file"),
            serverModel.fileOk,
            serverModel.toggleFile,
            enabled: !permissionChangeLocked,
          ),
          hasAudioPermission
              ? PermissionRow(translate("Audio Capture"), serverModel.audioOk,
                  serverModel.toggleAudio,
                  enabled: !permissionChangeLocked)
              : Row(children: [
                  Icon(Icons.info_outline).marginOnly(right: 15),
                  Expanded(
                      child: Text(
                    translate("android_version_audio_tip"),
                    style: const TextStyle(color: MyTheme.darkGray),
                  ))
                ]),
          PermissionRow(
            translate("Enable clipboard"),
            serverModel.clipboardOk,
            serverModel.toggleClipboard,
            enabled: !permissionChangeLocked,
          ),
        ]));
  }
}

class PermissionRow extends StatelessWidget {
  const PermissionRow(this.name, this.isOk, this.onPressed,
      {Key? key, this.enabled = true})
      : super(key: key);

  final String name;
  final bool isOk;
  final VoidCallback onPressed;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
        visualDensity: VisualDensity.compact,
        contentPadding: EdgeInsets.all(0),
        title: Text(name),
        value: isOk,
        onChanged: enabled
            ? (bool value) {
                onPressed();
              }
            : null);
  }
}

class ConnectionManager extends StatelessWidget {
  const ConnectionManager({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final serverModel = Provider.of<ServerModel>(context);
    return Column(
        children: serverModel.clients
            .map((client) => PaddingCard(
                title: translate(
                    client.isFileTransfer ? "Transfer file" : "Share screen"),
                titleIcon: client.isFileTransfer
                    ? Icon(Icons.folder_outlined)
                    : Icon(Icons.mobile_screen_share),
                child: Column(children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(child: ClientInfo(client)),
                      Expanded(
                          flex: -1,
                          child: client.isFileTransfer
                              ? const SizedBox.shrink()
                              : IconButton(
                                  onPressed: () {
                                    gFFI.chatModel.changeCurrentKey(
                                        MessageKey(client.peerId, client.id));
                                    final bar = navigationBarKey.currentWidget;
                                    if (bar != null) {
                                      bar as BottomNavigationBar;
                                      bar.onTap!(1);
                                    }
                                  },
                                  icon: unreadTopRightBuilder(
                                      client.unreadChatMessageCount)))
                    ],
                  ),
                  // R-A2/R-G7: clients arrive authorized (approve-mode pinned "password"), so the
                  // "new connection" accept hint is gone — only the disconnect control remains.
                  _buildDisconnectButton(client),
                  if (client.incomingVoiceCall && !client.inVoiceCall)
                    ..._buildNewVoiceCallHint(context, serverModel, client),
                ])))
            .toList());
  }

  Widget _buildDisconnectButton(Client client) {
    final disconnectButton = ElevatedButton.icon(
      style: ButtonStyle(backgroundColor: MaterialStatePropertyAll(Colors.red)),
      icon: const Icon(Icons.close),
      onPressed: () {
        bind.cmCloseConnection(connId: client.id);
        gFFI.invokeMethod("cancel_notification", client.id);
      },
      label: Text(translate("Disconnect")),
    );
    final buttons = [disconnectButton];
    if (client.inVoiceCall) {
      buttons.insert(
        0,
        ElevatedButton.icon(
          style: ButtonStyle(
              backgroundColor: MaterialStatePropertyAll(Colors.red)),
          icon: const Icon(Icons.phone),
          label: Text(translate("Stop")),
          onPressed: () {
            bind.cmCloseVoiceCall(id: client.id);
            gFFI.invokeMethod("cancel_notification", client.id);
          },
        ),
      );
    }

    if (buttons.length == 1) {
      return Container(
        alignment: Alignment.centerRight,
        child: disconnectButton,
      );
    } else {
      return Row(
        children: buttons,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
      );
    }
  }

  List<Widget> _buildNewVoiceCallHint(
      BuildContext context, ServerModel serverModel, Client client) {
    return [
      Text(
        translate("android_new_voice_call_tip"),
        style: Theme.of(context).textTheme.bodyMedium,
      ).marginOnly(bottom: 5),
      // R-G7 / R-S9 (§19): the click-to-accept "Accept" button is removed — approve-mode is
      // pinned 'password', so acceptance is automatic; only "Dismiss" (reject) survives.
      Row(mainAxisAlignment: MainAxisAlignment.end, children: [
        TextButton(
            child: Text(translate("Dismiss")),
            onPressed: () {
              serverModel.handleVoiceCall(client, false);
            }).marginOnly(right: 15),
      ])
    ];
  }
}

class PaddingCard extends StatelessWidget {
  const PaddingCard({Key? key, required this.child, this.title, this.titleIcon})
      : super(key: key);

  final String? title;
  final Icon? titleIcon;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final children = [child];
    if (title != null) {
      children.insert(
          0,
          Padding(
              padding: const EdgeInsets.fromLTRB(0, 5, 0, 8),
              child: Row(
                children: [
                  titleIcon?.marginOnly(right: 10) ?? const SizedBox.shrink(),
                  Expanded(
                    child: Text(title!,
                        style: Theme.of(context)
                            .textTheme
                            .titleLarge
                            ?.merge(TextStyle(fontWeight: FontWeight.bold))),
                  )
                ],
              )));
    }
    return SizedBox(
        width: double.maxFinite,
        child: Card(
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(13),
          ),
          margin: const EdgeInsets.fromLTRB(12.0, 10.0, 12.0, 0),
          child: Padding(
            padding:
                const EdgeInsets.symmetric(vertical: 15.0, horizontal: 20.0),
            child: Column(
              children: children,
            ),
          ),
        ));
  }
}

class ClientInfo extends StatelessWidget {
  final Client client;
  ClientInfo(this.client);

  @override
  Widget build(BuildContext context) {
    return Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(children: [
          Row(
            children: [
              Expanded(
                  flex: -1,
                  child: Padding(
                      padding: const EdgeInsets.only(right: 12),
                      child: _buildAvatar(context))),
              Expanded(
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                    Text(client.name, style: const TextStyle(fontSize: 18)),
                    const SizedBox(width: 8),
                    Text(client.peerId, style: const TextStyle(fontSize: 10))
                  ]))
            ],
          ),
        ]));
  }

  Widget _buildAvatar(BuildContext context) {
    final fallback = CircleAvatar(
      backgroundColor: str2color(client.name,
          Theme.of(context).brightness == Brightness.light ? 255 : 150),
      child: Text(client.name.isNotEmpty ? client.name[0] : '?'),
    );
    return buildAvatarWidget(
          avatar: client.avatar,
          size: 40,
          fallback: fallback,
        ) ??
        fallback;
  }
}

void androidChannelInit() {
  gFFI.setMethodCallHandler((method, arguments) {
    debugPrint("flutter got android msg,$method,$arguments");
    try {
      switch (method) {
        case "on_state_changed":
          {
            var name = arguments["name"] as String;
            var value = arguments["value"] as String == "true";
            debugPrint("from jvm:on_state_changed,$name:$value");
            gFFI.serverModel.changeStatue(name, value);
            break;
          }
        case "on_android_permission_result":
          {
            var type = arguments["type"] as String;
            var result = arguments["result"] as bool;
            AndroidPermissionManager.complete(type, result);
            break;
          }
        case "on_media_projection_canceled":
          {
            gFFI.serverModel.stopService();
            break;
          }
        case "msgbox":
          {
            var type = arguments["type"] as String;
            var title = arguments["title"] as String;
            var text = arguments["text"] as String;
            var link = (arguments["link"] ?? '') as String;
            msgBox(gFFI.sessionId, type, title, text, link, gFFI.dialogManager);
            break;
          }
        case "stop_service":
          {
            print(
                "stop_service by kotlin, isStart:${gFFI.serverModel.isStart}");
            if (gFFI.serverModel.isStart) {
              gFFI.serverModel.stopService();
            }
            break;
          }
      }
    } catch (e) {
      debugPrintStack(label: "MethodCallHandler err:$e");
    }
    return "";
  });
}

