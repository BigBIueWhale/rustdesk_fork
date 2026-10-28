import 'dart:convert';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/common/widgets/auto_disconnect_timeout_dialog.dart';
import 'package:flutter_hbb/common/widgets/connect_password_dialog.dart';
import 'package:flutter_hbb/common/widgets/password_text_field.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/common/widgets/trackpad_speed_dialog.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../common.dart';
import '../mobile_connection_navigation.dart';
import '../../models/model.dart';
import '../../models/platform_model.dart';

void clientClose(SessionID sessionId, FFI ffi,
    {MobileConnectionRoute? mobileRoute}) async {
  msgBox(sessionId, 'info', 'Close', 'Are you sure to close the connection?', '',
      ffi.dialogManager,
      onSubmit: ffi.viewCloseCallback(sessionId, mobileRoute: mobileRoute));
}

Future<String> changeAutoDisconnectTimeout(String old,
    {OverlayDialogManager? dialogManager,
    Future<void> Function(String value)? writeTimeout,
    Future<String> Function()? readTimeout,
    String Function(String text)? translateText}) async {
  final write = writeTimeout ??
      (value) => bind.mainSetOption(
          key: kOptionAutoDisconnectTimeout, value: value);
  final read = readTimeout ??
      () => bind.mainGetOption(key: kOptionAutoDisconnectTimeout);
  Future<String>? pendingSave;
  final result = await (dialogManager ?? gFFI.dialogManager).show<String>(
    (_, close, __) => AutoDisconnectTimeoutDialog(
      initialValue: old,
      saveTimeout: (value) {
        final operation = Future<String>.sync(() async {
          await write(value);
          return read();
        });
        pendingSave = operation;
        return operation;
      },
      close: close,
      translateText: translateText ?? translate,
    ),
  );
  if (result != null) return result;
  final admitted = pendingSave;
  if (admitted != null) {
    try {
      return await admitted;
    } catch (error) {
      debugPrint('Failed to save auto-disconnect timeout: $error');
    }
  }
  return old;
}

class DialogTextField extends StatelessWidget {
  final String title;
  final String? hintText;
  final bool isPassword;
  final bool passwordVisible;
  final bool enabled;
  final String? errorText;
  final String? helperText;
  final Widget? prefixIcon;
  final Widget? suffixIcon;
  final TextEditingController controller;
  final FocusNode? focusNode;
  final TextInputType? keyboardType;
  final ValueChanged<String>? onSubmitted;
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
      this.enabled = true,
      this.errorText,
      this.helperText,
      this.prefixIcon,
      this.suffixIcon,
      this.hintText,
      this.keyboardType,
      this.onSubmitted,
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
                focusable: enabled,
                child: isPassword
                    ? PasswordTextField(
                        decoration: decoration,
                        controller: controller,
                        focusNode: focusNode,
                        autofocus: true,
                        obscureText: !passwordVisible,
                        enabled: enabled,
                        onSubmitted: onSubmitted,
                        inputFormatters: inputFormatters,
                        maxLength: maxLength,
                      )
                    : TextField(
                        decoration: decoration,
                        controller: controller,
                        focusNode: focusNode,
                        autofocus: true,
                        keyboardType: keyboardType,
                        enabled: enabled,
                        onSubmitted: onSubmitted,
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
    this.hintText,
    this.errorText,
    this.title,
    this.maxLength,
    this.translateText,
    this.onSubmitted,
  }) : super(key: key);

  final TextEditingController controller;
  final String? hintText;
  final String? errorText;
  final String? title;
  final int? maxLength;
  final String Function(String text)? translateText;
  final ValueChanged<String>? onSubmitted;

  @override
  State<PasswordWidget> createState() => _PasswordWidgetState();
}

class _PasswordWidgetState extends State<PasswordWidget> {
  bool _passwordVisible = false;
  final _focusNode = FocusNode();

  @override
  void dispose() {
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
      onSubmitted: widget.onSubmitted,
    );
  }
}

// CPace credential replacement belongs to this exact session and prompt round.
void enterConnectPasswordDialog(
    SessionID sessionId,
    int credentialPromptRound,
    OverlayDialogManager dialogManager,
    {String reason = '',
    required VoidCallback onCancel}) async {
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
          onCancel: onCancel,
          onAccepted: () => dialogManager.showLoading(translate('Connecting...'),
              onCancel: onCancel),
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
  final owner = ffi.clientOwnerId;
  bool current() => ffi.isCurrentSessionOwner(sessionId, owner);
  if (!current()) return;
  final showFps = versionCmp(ffi.ffiModel.pi.version, '1.2.0') >= 0;
  final showMore = versionCmp(ffi.ffiModel.pi.version, '1.2.2') >= 0;
  late final List<int> initialQuality;
  late final String initialFps;
  try {
    final quality = await bind.sessionGetCustomImageQuality(sessionId: sessionId);
    if (!current()) return;
    final fps = await bind.sessionGetOption(sessionId: sessionId, arg: 'custom-fps');
    if (!current()) return;
    if (quality == null || fps == null) throw StateError('Session is unavailable');
    initialQuality = quality;
    initialFps = fps;
  } catch (error) {
    debugPrint('Failed to load image quality settings: $error');
    if (current()) showToast(translate('Failed'));
    return;
  }

  Future<double?> saveQuality(double value) async {
    if (!current()) return null;
    final effective = await bind.sessionSetCustomImageQuality(
        sessionId: sessionId, value: value.toInt());
    if (!current()) return null;
    return effective.toDouble();
  }

  Future<double?> saveFps(double value) async {
    if (!current()) return null;
    final effective = await bind.sessionSetCustomFps(
        sessionId: sessionId, fps: value.toInt());
    if (!current()) return null;
    return effective.toDouble();
  }

  try {
    await ffi.dialogManager.show((setState, close, context) => CustomAlertDialog(
      title: Text(translate('Custom Image Quality'),
          style: const TextStyle(fontSize: 21)),
      content: CustomImageQualityWidget(
        key: ValueKey((sessionId, owner)),
        initQuality: initialQuality.isEmpty
            ? kDefaultQuality : initialQuality.first.toDouble(),
        initFps: double.tryParse(initialFps) ?? kDefaultFps,
        saveQuality: saveQuality,
        saveFps: saveFps,
        showFps: showFps,
        showMoreQuality: showMore,
        onClose: () => close(),
      ),
      onCancel: () => close(),
    ));
  } catch (error) {
    debugPrint('Failed to show image quality editor: $error');
    if (current()) showToast(translate('Failed'));
  }
}

Future<void> trackpadSpeedDialog(SessionID sessionId, FFI ffi) async {
  final owner = ffi.clientOwnerId;
  bool current() => ffi.isCurrentSessionOwner(sessionId, owner);
  if (!current()) return;
  final initialSpeed = ffi.inputModel.trackpadSpeed;
  await ffi.dialogManager.show<void>((_, close, __) => TrackpadSpeedDialog(
    initialSpeed: initialSpeed,
    saveSpeed: (value) => ffi.inputModel.saveTrackpadSpeed(value,
        writeSpeed: (value) => bind.sessionSetTrackpadSpeed(
            sessionId: sessionId, value: value),
        isCurrent: current),
    close: close,
    translateText: translate,
  ));
}

Future<void> deleteConfirmDialog(
    Future<void> Function(bool Function() isCurrent) onSubmit, String title,
    {OverlayDialogManager? dialogManager,
    String Function(String)? translateText}) async {
  var submitting = false;
  await (dialogManager ?? gFFI.dialogManager).show<void>(
    (setState, close, context) {
      submit() async {
        if (!close.isCurrent || submitting) return;
        submitting = true;
        try {
          await onSubmit(() => close.isCurrent);
          close();
        } finally {
          submitting = false;
        }
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
            translateText: translateText,
          ),
          dialogButton(
            "OK",
            icon: Icon(Icons.done_rounded),
            onPressed: submit,
            translateText: translateText,
          ),
        ],
        onSubmit: submit,
        onCancel: close,
      );
    },
  );
}

Future<void> renameDialog(
    {required String oldName,
    required Future<bool> Function(String name, bool Function() isCurrent) onSubmit,
    OverlayDialogManager? dialogManager,
    String Function(String)? translateText}) async {
  await (dialogManager ?? gFFI.dialogManager).show<void>(
    (_, close, __) => PeerRenameDialog(
      oldName: oldName,
      onSubmit: onSubmit,
      close: close,
      translateText: translateText ?? translate,
    ),
  );
}

class PeerRenameDialog extends StatefulWidget {
  const PeerRenameDialog({
    required this.oldName,
    required this.onSubmit,
    required this.close,
    required this.translateText,
  });

  final String oldName;
  final Future<bool> Function(String name, bool Function() isCurrent) onSubmit;
  final DialogClose close;
  final String Function(String) translateText;

  @override
  State<PeerRenameDialog> createState() => _PeerRenameDialogState();
}

class _PeerRenameDialogState extends State<PeerRenameDialog> {
  late final TextEditingController _controller;
  var _submitting = false;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.oldName);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  bool _isCurrent() => mounted && widget.close.isCurrent;

  Future<void> _submit() async {
    if (!_isCurrent() || _submitting) return;
    final text = _controller.text.trim();
    final save = widget.onSubmit;
    final close = widget.close;
    setState(() => _submitting = true);
    try {
      if (await save(text, _isCurrent)) close();
    } finally {
      if (_isCurrent()) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.edit_rounded, color: MyTheme.accent),
          Text(widget.translateText('Rename')).paddingOnly(left: 10),
        ],
      ),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: _controller,
            enabled: !_submitting,
            autofocus: true,
            decoration: InputDecoration(labelText: widget.translateText('Name')),
          ),
          if (_submitting) const LinearProgressIndicator(),
        ],
      ),
      actions: [
        dialogButton(
          "Cancel",
          icon: Icon(Icons.close_rounded),
          onPressed: widget.close,
          isOutline: true,
          translateText: widget.translateText,
        ),
        dialogButton(
          "OK",
          icon: Icon(Icons.done_rounded),
          onPressed: _submitting ? null : _submit,
          translateText: widget.translateText,
        ),
      ],
      onSubmit: _submit,
      onCancel: widget.close,
    );
  }
}

void showWindowsSessionsDialog(
    String type,
    String title,
    String text,
    OverlayDialogManager dialogManager,
    String sessions,
    {required ValueChanged<String> onSelected,
    String Function(String text)? translateText}) {
  List<dynamic> sessionsList = [];
  try {
    sessionsList = json.decode(sessions);
  } catch (e) {
    print(e);
  }
  final options = <String, String>{};
  for (var session in sessionsList) {
    options[session['sid']] = session['name'];
  }
  String selectedUserValue = options.keys.first;
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    submit() {
      final selected = selectedUserValue;
      if (!close()) return;
      onSelected(selected);
    }

    return CustomAlertDialog(
      title: null,
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          msgboxContent(type, title, text, translateText: translateText)
              .marginOnly(bottom: 12),
          ComboBox(
              options: options,
              selectedKey: selectedUserValue,
              onChanged: (value) {
                if (!close.isCurrent) return;
                setState(() => selectedUserValue = value);
              }),
        ],
      ),
      actions: [
        dialogButton('Connect',
            onPressed: submit,
            isOutline: false,
            translateText: translateText),
      ],
      onSubmit: submit,
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
