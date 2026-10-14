import 'dart:async';
import 'dart:convert';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/common/widgets/connect_password_dialog.dart';
import 'package:flutter_hbb/common/widgets/password_text_field.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../common.dart';
import '../../models/model.dart';
import '../../models/platform_model.dart';

void clientClose(SessionID sessionId, FFI ffi) async {
  msgBox(sessionId, 'info', 'Close', 'Are you sure to close the connection?', '',
      ffi.dialogManager,
      onSubmit: () => ffi.closeView(sessionId));
}

abstract class ValidationRule {
  String get name;
  bool validate(String value);
}

class LengthRangeValidationRule extends ValidationRule {
  final int _min;
  final int _max;

  LengthRangeValidationRule(this._min, this._max);

  @override
  String get name => translate('length %min% to %max%')
      .replaceAll('%min%', _min.toString())
      .replaceAll('%max%', _max.toString());

  @override
  bool validate(String value) {
    return value.length >= _min && value.length <= _max;
  }
}

class RegexValidationRule extends ValidationRule {
  final String _name;
  final RegExp _regex;

  RegexValidationRule(this._name, this._regex);

  @override
  String get name => translate(_name);

  @override
  bool validate(String value) {
    return value.isNotEmpty ? value.contains(_regex) : false;
  }
}

// R-G4 / R-SV5 (§19): the Change-ID dialog is REMOVED. The numeric RustDesk ID is an
// artifact of the rendezvous-registration model the fork deleted (R-SV4/R-SV5) — a sovereign,
// direct-IP box is reached by its <ip|domain>:port, not by a re-assignable ID — so changing it
// is meaningless. The dialog's only FFI caller (`bind.mainChangeId`) is dropped with it
// (the Rust `main_change_id` flutter export is removed; the Sciter `change_id` path is separate).

Future<String> changeAutoDisconnectTimeout(String old) async {
  final controller = TextEditingController(text: old);
  await gFFI.dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate("Timeout in minutes")),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SizedBox(height: 8.0),
          Row(
            children: [
              Expanded(
                child: TextField(
                        maxLines: null,
                        keyboardType: TextInputType.number,
                        decoration: InputDecoration(
                            hintText: '10',
                            isCollapsed: true,
                            suffix: IconButton(
                                padding: EdgeInsets.zero,
                                icon: const Icon(Icons.clear, size: 16),
                                onPressed: () => controller.clear())),
                        inputFormatters: [
                          FilteringTextInputFormatter.allow(RegExp(
                              r'^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$')),
                        ],
                        controller: controller,
                        autofocus: true),
              ),
            ],
          ),
        ],
      ),
      actions: [
        dialogButton("Cancel", onPressed: close, isOutline: true),
        dialogButton("OK", onPressed: () async {
          await bind.mainSetOption(
              key: kOptionAutoDisconnectTimeout, value: controller.text);
          close();
        }),
      ],
      onCancel: close,
    );
  });
  return controller.text;
}

class DialogTextField extends StatelessWidget {
  final String title;
  final String? hintText;
  final bool isPassword;
  final bool passwordVisible;
  final String? errorText;
  final String? helperText;
  final Widget? prefixIcon;
  final Widget? suffixIcon;
  final TextEditingController controller;
  final FocusNode? focusNode;
  final TextInputType? keyboardType;
  final List<TextInputFormatter>? inputFormatters;
  final int? maxLength;

  static const kUsernameTitle = 'Username';
  static const kUsernameIcon = Icon(Icons.account_circle_outlined);
  static const kPasswordTitle = 'Password';
  static const kPasswordIcon = Icon(Icons.lock_outline);

  DialogTextField(
      {Key? key,
      this.focusNode,
      this.isPassword = false,
      this.passwordVisible = false,
      this.errorText,
      this.helperText,
      this.prefixIcon,
      this.suffixIcon,
      this.hintText,
      this.keyboardType,
      this.inputFormatters,
      this.maxLength,
      required this.title,
      required this.controller})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    final decoration = InputDecoration(
      labelText: title,
      hintText: hintText,
      prefixIcon: prefixIcon,
      suffixIcon: suffixIcon,
      helperText: helperText,
      helperMaxLines: 8,
    );
    return Row(
      children: [
        Expanded(
          child: Column(
            children: [
              Semantics(
                focusable: true,
                child: isPassword
                    ? PasswordTextField(
                        decoration: decoration,
                        controller: controller,
                        focusNode: focusNode,
                        autofocus: true,
                        obscureText: !passwordVisible,
                        inputFormatters: inputFormatters,
                        maxLength: maxLength,
                      )
                    : TextField(
                        decoration: decoration,
                        controller: controller,
                        focusNode: focusNode,
                        autofocus: true,
                        keyboardType: keyboardType,
                        inputFormatters: inputFormatters,
                        maxLength: maxLength,
                      ),
              ),
              if (errorText != null)
                Align(
                  alignment: Alignment.centerLeft,
                  child: SelectableText(
                    errorText!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                      fontSize: 12,
                    ),
                    textAlign: TextAlign.left,
                  ).paddingOnly(top: 8, left: 12),
                ),
            ],
          ),
        ),
      ],
    ).paddingSymmetric(vertical: 4.0);
  }
}

class PasswordWidget extends StatefulWidget {
  PasswordWidget({
    Key? key,
    required this.controller,
    this.autoFocus = true,
    this.reRequestFocus = false,
    this.hintText,
    this.errorText,
    this.title,
    this.maxLength,
    this.translateText,
  }) : super(key: key);

  final TextEditingController controller;
  final bool autoFocus;
  final bool reRequestFocus;
  final String? hintText;
  final String? errorText;
  final String? title;
  final int? maxLength;
  final String Function(String text)? translateText;

  @override
  State<PasswordWidget> createState() => _PasswordWidgetState();
}

class _PasswordWidgetState extends State<PasswordWidget> {
  bool _passwordVisible = false;
  final _focusNode = FocusNode();
  Timer? _timer;
  Timer? _timerReRequestFocus;

  @override
  void initState() {
    super.initState();
    if (widget.autoFocus) {
      _timer =
          Timer(Duration(milliseconds: 50), () => _focusNode.requestFocus());
    }
    // software secure keyboard will take the focus since flutter 3.13
    // request focus again when android account password obtain focus
    if (isAndroid && widget.reRequestFocus) {
      _focusNode.addListener(() {
        if (_focusNode.hasFocus) {
          _timerReRequestFocus?.cancel();
          _timerReRequestFocus = Timer(
              Duration(milliseconds: 100), () => _focusNode.requestFocus());
        }
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _timerReRequestFocus?.cancel();
    _focusNode.unfocus();
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final translateText = widget.translateText ?? translate;
    return DialogTextField(
      title: translateText(widget.title ?? DialogTextField.kPasswordTitle),
      hintText: translateText(widget.hintText ?? 'Enter your password'),
      controller: widget.controller,
      prefixIcon: DialogTextField.kPasswordIcon,
      suffixIcon: IconButton(
        icon: Icon(
            // Based on passwordVisible state choose the icon
            _passwordVisible ? Icons.visibility : Icons.visibility_off,
            color: MyTheme.lightTheme.primaryColor),
        onPressed: () {
          // Update the state i.e. toggle the state of passwordVisible variable
          setState(() {
            _passwordVisible = !_passwordVisible;
          });
        },
      ),
      isPassword: true,
      passwordVisible: _passwordVisible,
      errorText: widget.errorText,
      focusNode: _focusNode,
      maxLength: widget.maxLength,
    );
  }
}

// CPace credential replacement belongs to this exact session and prompt round.
void enterConnectPasswordDialog(
    SessionID sessionId,
    int credentialPromptRound,
    OverlayDialogManager dialogManager,
    [String reason = '']) async {
  dialogManager.dismissAll();
  try {
    await dialogManager.show((setState, close, context) => ConnectPasswordDialog(
          key: ValueKey('$sessionId:$credentialPromptRound'),
          reason: reason,
          readRemember: () => bind.sessionGetRemember(sessionId: sessionId),
          submitPassword: (password, remember) => bind.sessionSetConnectPassword(
            sessionId: sessionId,
            credentialPromptRound: credentialPromptRound,
            password: password,
            remember: remember,
          ),
          close: close,
          onCancel: closeConnection,
          onAccepted: () => dialogManager.showLoading(translate('Connecting...'),
              onCancel: closeConnection),
        ));
  } catch (error) {
    debugPrint('Connect password dialog failed: ${error.runtimeType}');
  }
}

void showRestartRemoteDevice(PeerInfo pi, String id, SessionID sessionId,
    OverlayDialogManager dialogManager) async {
  final res = await dialogManager
      .show<bool>((setState, close, context) => CustomAlertDialog(
            title: Row(children: [
              Icon(Icons.warning_rounded, color: Colors.redAccent, size: 28),
              Flexible(
                  child: Text(translate("Restart remote device"))
                      .paddingOnly(left: 10)),
            ]),
            content: Text(
                "${translate('Are you sure you want to restart')} \n${pi.username}@${pi.hostname}($id) ?"),
            actions: [
              dialogButton(
                "Cancel",
                icon: Icon(Icons.close_rounded),
                onPressed: close,
                isOutline: true,
              ),
              dialogButton(
                "OK",
                icon: Icon(Icons.done_rounded),
                onPressed: () => close(true),
              ),
            ],
            onCancel: close,
            onSubmit: () => close(true),
          ));
  if (res == true) bind.sessionRestartRemoteDevice(sessionId: sessionId);
}







customImageQualityDialog(SessionID sessionId, String id, FFI ffi) async {
  double initQuality = kDefaultQuality;
  double initFps = kDefaultFps;
  bool qualitySet = false;
  bool fpsSet = false;

  // Direct-only capability presentation depends only on the peer version. There is no
  // server-selection or relay/direct state to consult.
  bool hideFps = versionCmp(ffi.ffiModel.pi.version, '1.2.0') < 0;
  bool hideMoreQuality = versionCmp(ffi.ffiModel.pi.version, '1.2.2') < 0;

  setCustomValues({double? quality, double? fps}) async {
    debugPrint("setCustomValues quality:$quality, fps:$fps");
    if (quality != null) {
      qualitySet = true;
      await bind.sessionSetCustomImageQuality(
          sessionId: sessionId, value: quality.toInt());
    }
    if (fps != null) {
      fpsSet = true;
      await bind.sessionSetCustomFps(sessionId: sessionId, fps: fps.toInt());
    }
    if (!qualitySet) {
      qualitySet = true;
      await bind.sessionSetCustomImageQuality(
          sessionId: sessionId, value: initQuality.toInt());
    }
    if (!hideFps && !fpsSet) {
      fpsSet = true;
      await bind.sessionSetCustomFps(
          sessionId: sessionId, fps: initFps.toInt());
    }
  }

  final btnClose = dialogButton('Close', onPressed: () async {
    await setCustomValues();
    ffi.dialogManager.dismissAll();
  });

  // quality
  final quality = await bind.sessionGetCustomImageQuality(sessionId: sessionId);
  initQuality = quality != null && quality.isNotEmpty
      ? quality[0].toDouble()
      : kDefaultQuality;
  if (initQuality < kMinQuality ||
      initQuality > (!hideMoreQuality ? kMaxMoreQuality : kMaxQuality)) {
    initQuality = kDefaultQuality;
  }
  // fps
  final fpsOption =
      await bind.sessionGetOption(sessionId: sessionId, arg: 'custom-fps');
  initFps = fpsOption == null
      ? kDefaultFps
      : double.tryParse(fpsOption) ?? kDefaultFps;
  if (initFps < kMinFps || initFps > kMaxFps) {
    initFps = kDefaultFps;
  }

  final content = customImageQualityWidget(
      initQuality: initQuality,
      initFps: initFps,
      setQuality: (v) => setCustomValues(quality: v),
      setFps: (v) => setCustomValues(fps: v),
      showFps: !hideFps,
      showMoreQuality: !hideMoreQuality);
  msgBoxCommon(ffi.dialogManager, 'Custom Image Quality', content, [btnClose]);
}

trackpadSpeedDialog(SessionID sessionId, FFI ffi) async {
  int initSpeed = ffi.inputModel.trackpadSpeed;
  final curSpeed = SimpleWrapper(initSpeed);
  final btnClose = dialogButton('Close', onPressed: () async {
    if (curSpeed.value <= kMaxTrackpadSpeed &&
        curSpeed.value >= kMinTrackpadSpeed &&
        curSpeed.value != initSpeed) {
      await bind.sessionSetTrackpadSpeed(
          sessionId: sessionId, value: curSpeed.value);
      await ffi.inputModel.updateTrackpadSpeed();
    }
    ffi.dialogManager.dismissAll();
  });
  msgBoxCommon(
      ffi.dialogManager,
      'Trackpad speed',
      TrackpadSpeedWidget(
        value: curSpeed,
      ),
      [btnClose]);
}

void deleteConfirmDialog(Function onSubmit, String title) async {
  gFFI.dialogManager.show(
    (setState, close, context) {
      submit() async {
        await onSubmit();
        close();
      }

      return CustomAlertDialog(
        title: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.delete_rounded,
              color: Colors.red,
            ),
            Expanded(
              child: Text(title, overflow: TextOverflow.ellipsis).paddingOnly(
                left: 10,
              ),
            ),
          ],
        ),
        content: SizedBox.shrink(),
        actions: [
          dialogButton(
            "Cancel",
            icon: Icon(Icons.close_rounded),
            onPressed: close,
            isOutline: true,
          ),
          dialogButton(
            "OK",
            icon: Icon(Icons.done_rounded),
            onPressed: submit,
          ),
        ],
        onSubmit: submit,
        onCancel: close,
      );
    },
  );
}

void renameDialog(
    {required String oldName,
    FormFieldValidator<String>? validator,
    required ValueChanged<String> onSubmit,
    Function? onCancel}) async {
  RxBool isInProgress = false.obs;
  var controller = TextEditingController(text: oldName);
  final formKey = GlobalKey<FormState>();
  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      String text = controller.text.trim();
      if (validator != null && formKey.currentState?.validate() == false) {
        return;
      }
      isInProgress.value = true;
      onSubmit(text);
      close();
      isInProgress.value = false;
    }

    cancel() {
      onCancel?.call();
      close();
    }

    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.edit_rounded, color: MyTheme.accent),
          Text(translate('Rename')).paddingOnly(left: 10),
        ],
      ),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            child: Form(
              key: formKey,
              child: TextFormField(
                controller: controller,
                autofocus: true,
                decoration: InputDecoration(labelText: translate('Name')),
                validator: validator,
              ),
            ),
          ),
          // NOT use Offstage to wrap LinearProgressIndicator
          Obx(() =>
              isInProgress.value ? const LinearProgressIndicator() : Offstage())
        ],
      ),
      actions: [
        dialogButton(
          "Cancel",
          icon: Icon(Icons.close_rounded),
          onPressed: cancel,
          isOutline: true,
        ),
        dialogButton(
          "OK",
          icon: Icon(Icons.done_rounded),
          onPressed: submit,
        ),
      ],
      onSubmit: submit,
      onCancel: cancel,
    );
  });
}

// This dialog should not be dismissed, otherwise it will be black screen, have not reproduced this.
void showWindowsSessionsDialog(
    String type,
    String title,
    String text,
    OverlayDialogManager dialogManager,
    SessionID sessionId,
    String peerId,
    String sessions) {
  List<dynamic> sessionsList = [];
  try {
    sessionsList = json.decode(sessions);
  } catch (e) {
    print(e);
  }
  List<String> sids = [];
  List<String> names = [];
  for (var session in sessionsList) {
    sids.add(session['sid']);
    names.add(session['name']);
  }
  String selectedUserValue = sids.first;
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    submit() {
      bind.sessionSendSelectedSessionId(
          sessionId: sessionId, sid: selectedUserValue);
      close();
    }

    return CustomAlertDialog(
      title: null,
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          msgboxContent(type, title, text).marginOnly(bottom: 12),
          ComboBox(
              keys: sids,
              values: names,
              initialKey: selectedUserValue,
              onChanged: (value) {
                selectedUserValue = value;
              }),
        ],
      ),
      actions: [
        dialogButton('Connect', onPressed: submit, isOutline: false),
      ],
    );
  });
}

void CommonConfirmDialog(OverlayDialogManager dialogManager, String content,
    VoidCallback onConfirm) {
  dialogManager.show((setState, close, context) {
    submit() {
      close();
      onConfirm.call();
    }

    return CustomAlertDialog(
      content: Row(
        children: [
          Expanded(
            child: Text(content,
                style: const TextStyle(fontSize: 15),
                textAlign: TextAlign.start),
          ),
        ],
      ).marginOnly(bottom: 12),
      actions: [
        dialogButton(translate("Cancel"), onPressed: close, isOutline: true),
        dialogButton(translate("OK"), onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

// T2 (excise): the two PIN-based settings-lock dialogs were removed with the elevation lock they
// served — the whole local-PIN settings-gate subsystem is excised (R-G1 / excise-don't-disable).
