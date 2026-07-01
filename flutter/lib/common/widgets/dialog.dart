import 'dart:async';
import 'dart:convert';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/peer_tab_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../common.dart';
import '../../models/model.dart';
import '../../models/platform_model.dart';
import 'address_book.dart';

void clientClose(SessionID sessionId, FFI ffi) async {
  msgBox(sessionId, 'info', 'Close', 'Are you sure to close the connection?', '',
      ffi.dialogManager);
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
                        autofocus: true)
                    .workaroundFreezeLinuxMint(),
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
  final bool obscureText;
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
      this.obscureText = false,
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
    return Row(
      children: [
        Expanded(
          child: Column(
            children: [
              TextField(
                decoration: InputDecoration(
                  labelText: title,
                  hintText: hintText,
                  prefixIcon: prefixIcon,
                  suffixIcon: suffixIcon,
                  helperText: helperText,
                  helperMaxLines: 8,
                ),
                controller: controller,
                focusNode: focusNode,
                autofocus: true,
                obscureText: obscureText,
                keyboardType: keyboardType,
                inputFormatters: inputFormatters,
                maxLength: maxLength,
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
          ).workaroundFreezeLinuxMint(),
        ),
      ],
    ).paddingSymmetric(vertical: 4.0);
  }
}

abstract class ValidationField extends StatelessWidget {
  ValidationField({Key? key}) : super(key: key);

  String? validate();
  bool get isReady;
}

class Dialog2FaField extends ValidationField {
  Dialog2FaField({
    Key? key,
    required this.controller,
    this.autoFocus = true,
    this.reRequestFocus = false,
    this.title,
    this.hintText,
    this.errorText,
    this.readyCallback,
    this.onChanged,
  }) : super(key: key);

  final TextEditingController controller;
  final bool autoFocus;
  final bool reRequestFocus;
  final String? title;
  final String? hintText;
  final String? errorText;
  final VoidCallback? readyCallback;
  final VoidCallback? onChanged;
  final errMsg = translate('2FA code must be 6 digits.');

  @override
  Widget build(BuildContext context) {
    return DialogVerificationCodeField(
      title: title ?? translate('2FA code'),
      controller: controller,
      errorText: errorText,
      autoFocus: autoFocus,
      reRequestFocus: reRequestFocus,
      hintText: hintText,
      readyCallback: readyCallback,
      onChanged: _onChanged,
      keyboardType: TextInputType.number,
      inputFormatters: [
        FilteringTextInputFormatter.allow(RegExp(r'[0-9]')),
      ],
    );
  }

  String get text => controller.text;
  bool get isAllDigits => text.codeUnits.every((e) => e >= 48 && e <= 57);

  @override
  bool get isReady => text.length == 6 && isAllDigits;

  @override
  String? validate() => isReady ? null : errMsg;

  _onChanged(StateSetter setState, SimpleWrapper<String?> errText) {
    onChanged?.call();

    if (text.length > 6) {
      setState(() => errText.value = errMsg);
      return;
    }

    if (!isAllDigits) {
      setState(() => errText.value = errMsg);
      return;
    }

    if (isReady) {
      readyCallback?.call();
      return;
    }

    if (errText.value != null) {
      setState(() => errText.value = null);
    }
  }
}

class DialogEmailCodeField extends ValidationField {
  DialogEmailCodeField({
    Key? key,
    required this.controller,
    this.autoFocus = true,
    this.reRequestFocus = false,
    this.hintText,
    this.errorText,
    this.readyCallback,
    this.onChanged,
  }) : super(key: key);

  final TextEditingController controller;
  final bool autoFocus;
  final bool reRequestFocus;
  final String? hintText;
  final String? errorText;
  final VoidCallback? readyCallback;
  final VoidCallback? onChanged;
  final errMsg = translate('Email verification code must be 6 characters.');

  @override
  Widget build(BuildContext context) {
    return DialogVerificationCodeField(
      title: translate('Verification code'),
      controller: controller,
      errorText: errorText,
      autoFocus: autoFocus,
      reRequestFocus: reRequestFocus,
      hintText: hintText,
      readyCallback: readyCallback,
      helperText: translate('verification_tip'),
      onChanged: _onChanged,
      keyboardType: TextInputType.visiblePassword,
    );
  }

  String get text => controller.text;

  @override
  bool get isReady => text.length == 6;

  @override
  String? validate() => isReady ? null : errMsg;

  _onChanged(StateSetter setState, SimpleWrapper<String?> errText) {
    onChanged?.call();

    if (text.length > 6) {
      setState(() => errText.value = errMsg);
      return;
    }

    if (isReady) {
      readyCallback?.call();
      return;
    }

    if (errText.value != null) {
      setState(() => errText.value = null);
    }
  }
}

class DialogVerificationCodeField extends StatefulWidget {
  DialogVerificationCodeField({
    Key? key,
    required this.controller,
    required this.title,
    this.autoFocus = true,
    this.reRequestFocus = false,
    this.helperText,
    this.hintText,
    this.errorText,
    this.textLength,
    this.readyCallback,
    this.onChanged,
    this.keyboardType,
    this.inputFormatters,
  }) : super(key: key);

  final TextEditingController controller;
  final bool autoFocus;
  final bool reRequestFocus;
  final String title;
  final String? helperText;
  final String? hintText;
  final String? errorText;
  final int? textLength;
  final VoidCallback? readyCallback;
  final Function(StateSetter setState, SimpleWrapper<String?> errText)?
      onChanged;
  final TextInputType? keyboardType;
  final List<TextInputFormatter>? inputFormatters;

  @override
  State<DialogVerificationCodeField> createState() =>
      _DialogVerificationCodeField();
}

class _DialogVerificationCodeField extends State<DialogVerificationCodeField> {
  final _focusNode = FocusNode();
  Timer? _timer;
  Timer? _timerReRequestFocus;
  SimpleWrapper<String?> errorText = SimpleWrapper(null);
  String _preText = '';

  @override
  void initState() {
    super.initState();
    if (widget.autoFocus) {
      _timer =
          Timer(Duration(milliseconds: 50), () => _focusNode.requestFocus());

      if (widget.onChanged != null) {
        widget.controller.addListener(() {
          final text = widget.controller.text.trim();
          if (text == _preText) return;
          widget.onChanged!(setState, errorText);
          _preText = text;
        });
      }
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
    return DialogTextField(
      title: widget.title,
      controller: widget.controller,
      errorText: widget.errorText ?? errorText.value,
      focusNode: _focusNode,
      helperText: widget.helperText,
      keyboardType: widget.keyboardType,
      inputFormatters: widget.inputFormatters,
    );
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
  }) : super(key: key);

  final TextEditingController controller;
  final bool autoFocus;
  final bool reRequestFocus;
  final String? hintText;
  final String? errorText;
  final String? title;
  final int? maxLength;

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
    return DialogTextField(
      title: translate(widget.title ?? DialogTextField.kPasswordTitle),
      hintText: translate(widget.hintText ?? 'Enter your password'),
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
      obscureText: !_passwordVisible,
      errorText: widget.errorText,
      focusNode: _focusNode,
      maxLength: widget.maxLength,
    );
  }
}

void wrongPasswordDialog(SessionID sessionId,
    OverlayDialogManager dialogManager, type, title, text) {
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    cancel() {
      close();
      closeConnection();
    }

    submit() {
      enterPasswordDialog(sessionId, dialogManager);
    }

    return CustomAlertDialog(
        title: null,
        content: msgboxContent(type, title, text),
        onSubmit: submit,
        onCancel: cancel,
        actions: [
          dialogButton(
            'Cancel',
            onPressed: cancel,
            isOutline: true,
          ),
          dialogButton(
            'Retry',
            onPressed: submit,
          ),
        ]);
  });
}

void enterPasswordDialog(
    SessionID sessionId, OverlayDialogManager dialogManager) async {
  await _connectDialog(
    sessionId,
    dialogManager,
    passwordController: TextEditingController(),
  );
}

// R-S13/A3 (prompt-before-keying): the CPace handshake needs the box's password BEFORE
// keying, but a bare-ID first connect has none remembered. The keying then fails closed and
// surfaces `connect-password-prompt`; this dialog takes the password and, via
// `sessionSetConnectPassword`, stores it as the connect-password and RECONNECTS — the
// reconnect keys with it. Distinct from `enterPasswordDialog` (which logs in over an
// already-keyed connection); here there is no keyed connection yet.
void enterConnectPasswordDialog(
    SessionID sessionId, OverlayDialogManager dialogManager) async {
  await _connectDialog(
    sessionId,
    dialogManager,
    passwordController: TextEditingController(),
    preKeying: true,
  );
}

// R-S17/R-G5 (first-connect pin seed): the box keyed (so it DOES hold the host key), but the
// operator has not pinned it yet. Show the fingerprint to confirm OUT-OF-BAND against the box's
// `--get-fingerprint`, then pin THIS key + reconnect on accept (SSH's "type yes to the
// fingerprint", done deliberately). NOT shown for a pin MISMATCH — that stays a loud error with
// no easy bypass (the operator must `--forget-host` to re-pin a legitimately re-keyed box).
void hostNotPinnedDialog(
    SessionID sessionId, OverlayDialogManager dialogManager, String text) async {
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    cancel() {
      close();
      closeConnection();
    }

    submit() {
      // Pin the host key the keying stashed, then reconnect (keys against the new pin).
      bind.sessionPinHost(sessionId: sessionId);
      close();
      dialogManager.showLoading(translate('Connecting...'),
          onCancel: closeConnection);
    }

    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.warning_amber_rounded, color: Colors.orange),
          Text(translate('Unknown host')).paddingOnly(left: 10),
        ],
      ),
      content: Align(
        alignment: Alignment.centerLeft,
        child: SelectableText(text, style: TextStyle(fontSize: 14)),
      ),
      actions: [
        dialogButton(
          'Cancel',
          icon: Icon(Icons.close_rounded),
          onPressed: cancel,
          isOutline: true,
        ),
        dialogButton(
          'Trust',
          icon: Icon(Icons.verified_user_outlined),
          onPressed: submit,
        ),
      ],
      onCancel: cancel,
    );
  });
}

// R-S17/R-G5: the host-key MISMATCH warning dialog — the `known_hosts` "WARNING: REMOTE HOST
// IDENTIFICATION HAS CHANGED" analog. Unlike the seed (a trust-on-first-use accept), re-pinning a
// MISMATCHED host is FRICTION-BEARING (R-S17): the operator must TYPE the new fingerprint exactly
// (after verifying it out-of-band), there is no default-focused OK (the Re-pin button stays
// disabled until the typed fingerprint matches), and the destructive action is styled as a risk.
// `newFingerprint` is the verified new fp (the msgbox `link`) the typed input must match; `text`
// carries the human-readable old-vs-new warning. On cancel the connection is closed (fail-closed);
// the keying already stashed the verified new key, so Re-pin overwrites the old pin and reconnects.
void hostMismatchDialog(SessionID sessionId, OverlayDialogManager dialogManager,
    String text, String newFingerprint) async {
  dialogManager.dismissAll();
  final controller = TextEditingController();
  // hex-only, case-insensitive compare so any fingerprint format the operator types matches.
  String norm(String s) => s.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toLowerCase();
  final wantHex = norm(newFingerprint);
  dialogManager.show((setState, close, context) {
    cancel() {
      close();
      closeConnection();
    }

    final matches = wantHex.isNotEmpty && norm(controller.text) == wantHex;
    submit() {
      if (!matches) return;
      // Overwrites the old pin with the verified new key (set_pinned_pk), then reconnects.
      bind.sessionPinHost(sessionId: sessionId);
      close();
      dialogManager.showLoading(translate('Connecting...'),
          onCancel: closeConnection);
    }

    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.gpp_bad, color: Colors.red),
          Text(translate('Host key changed')).paddingOnly(left: 10),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SelectableText(text, style: TextStyle(fontSize: 14)),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            autofocus: false,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              border: const OutlineInputBorder(),
              labelText: translate(
                  'Type the new fingerprint to re-pin (substitution risk)'),
            ),
          ),
        ],
      ),
      actions: [
        dialogButton(
          'Cancel',
          icon: Icon(Icons.close_rounded),
          onPressed: cancel,
          isOutline: true,
        ),
        dialogButton(
          'Re-pin',
          icon: Icon(Icons.warning_amber_rounded),
          onPressed: matches ? submit : null,
        ),
      ],
      onCancel: cancel,
    );
  });
}

// R-S17/R-G5: the known_hosts MANAGE view — lists the pinned hosts (address + fingerprint) and
// forgets one (the GUI twin of --list-known-hosts / --forget-host). Forget is deliberate (a
// confirmation); the next connection re-seeds via the TOFU prompt (R-S17). Reads ONLY the local
// pin store via the main FFI — never a peer message (R-S15). Shared by the desktop Safety tab and
// the mobile settings, so the manage/forget-host view exists on every viewer front-end (R-G5).
class KnownHostsManager extends StatefulWidget {
  const KnownHostsManager({Key? key}) : super(key: key);

  @override
  State<KnownHostsManager> createState() => _KnownHostsManagerState();
}

class _KnownHostsManagerState extends State<KnownHostsManager> {
  List<dynamic> _hosts = [];

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final raw = await bind.mainListPinnedHosts();
      if (!mounted) return;
      setState(() => _hosts = jsonDecode(raw) as List);
    } catch (_) {
      if (!mounted) return;
      setState(() => _hosts = []);
    }
  }

  Future<void> _forget(String address) async {
    final res = await gFFI.dialogManager.show((setState, close, context) {
      return CustomAlertDialog(
        title: Text(translate('Forget')),
        content: Text(
            '${translate('Forget the pinned host key for')} "$address"?\n\n${translate('The next connection will prompt to pin it again (trust-on-first-use).')}'),
        actions: [
          dialogButton('Cancel', onPressed: () => close(false), isOutline: true),
          dialogButton('Forget', onPressed: () => close(true)),
        ],
        onCancel: () => close(false),
      );
    });
    if (res != true) return;
    await bind.mainForgetPinnedHost(address: address);
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    if (_hosts.isEmpty) {
      return Align(
        alignment: Alignment.centerLeft,
        child: Text(translate('No pinned hosts yet.'),
            style: TextStyle(color: Theme.of(context).hintColor)),
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: _hosts.map((h) {
        final address = (h['address'] ?? '').toString();
        final fp = (h['fingerprint'] ?? '').toString();
        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 4),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(address,
                        style: const TextStyle(fontWeight: FontWeight.w600)),
                    SelectableText(fp, style: const TextStyle(fontSize: 12)),
                  ],
                ),
              ),
              IconButton(
                icon: const Icon(Icons.delete_outline),
                tooltip: translate('Forget'),
                onPressed: () => _forget(address),
              ),
            ],
          ),
        );
      }).toList(),
    );
  }
}

// R-S18/R-X8: the connect-time password dialog (rd-password only). The os-username/os-password
// fields it used to carry — the operator's OS credentials pushed to the host — are removed: the
// viewer never solicits OS creds (the host-triggered os-login prompts are gone, the responder
// strips os_login, and create_login_msg no longer sends it).
_connectDialog(
  SessionID sessionId,
  OverlayDialogManager dialogManager, {
  required TextEditingController passwordController,
  bool preKeying = false,
}) async {
  var rememberPassword =
      await bind.sessionGetRemember(sessionId: sessionId) ?? false;

  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    cancel() {
      close();
      closeConnection();
    }

    submit() {
      final password = passwordController.text.trim();
      if (password.isEmpty) return;
      if (preKeying) {
        // R-S13/A3: store the connect-time password + reconnect so the CPace handshake keys
        // with it (no keyed connection exists yet, so we cannot `login`).
        bind.sessionSetConnectPassword(
            sessionId: sessionId, password: password, remember: rememberPassword);
        close();
        dialogManager.showLoading(translate('Connecting...'),
            onCancel: closeConnection);
        return;
      }
      gFFI.login(sessionId, password, rememberPassword);
      close();
      dialogManager.showLoading(translate('Logging in...'),
          onCancel: closeConnection);
    }

    descWidget(String text) {
      return Column(
        children: [
          Align(
            alignment: Alignment.centerLeft,
            child: Text(
              text,
              maxLines: 3,
              softWrap: true,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontSize: 16),
            ),
          ),
          Container(
            height: 8,
          ),
        ],
      );
    }

    rememberWidget(
      String desc,
      bool remember,
      ValueChanged<bool?>? onChanged,
    ) {
      return CheckboxListTile(
        contentPadding: const EdgeInsets.all(0),
        dense: true,
        controlAffinity: ListTileControlAffinity.leading,
        title: Text(desc),
        value: remember,
        onChanged: onChanged,
      );
    }

    passwdWidget() {
      return Column(
        children: [
          descWidget(translate('verify_rustdesk_password_tip')),
          PasswordWidget(
            controller: passwordController,
            autoFocus: true,
          ),
          rememberWidget(
            translate('Remember password'),
            rememberPassword,
            (v) {
              if (v != null) {
                setState(() => rememberPassword = v);
              }
            },
          ),
        ],
      );
    }

    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.password_rounded, color: MyTheme.accent),
          Text(translate('Password Required')).paddingOnly(left: 10),
        ],
      ),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        passwdWidget(),
      ]),
      actions: [
        dialogButton(
          'Cancel',
          icon: Icon(Icons.close_rounded),
          onPressed: cancel,
          isOutline: true,
        ),
        dialogButton(
          'OK',
          icon: Icon(Icons.done_rounded),
          onPressed: submit,
        ),
      ],
      onSubmit: submit,
      onCancel: cancel,
    );
  });
}

void showWaitAcceptDialog(SessionID sessionId, String type, String title,
    String text, OverlayDialogManager dialogManager) {
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    onCancel() {
      closeConnection();
    }

    return CustomAlertDialog(
      title: null,
      content: msgboxContent(type, title, text),
      actions: [
        dialogButton('Cancel', onPressed: onCancel, isOutline: true),
      ],
      onCancel: onCancel,
    );
  });
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

  // R-G3/R-SV4: the fork is direct-only (relay/rendezvous removed), so a session is ALWAYS direct.
  // The inherited `mainIsUsingPublicServer() && !direct` caveat is therefore provably always false
  // (`!direct` can never hold), so it collapses to the version gate alone — and the removed
  // ConnectionType.direct/strDirect state no longer needs consulting here.
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

void editAbTagDialog(
    List<dynamic> currentTags, Function(List<dynamic>) onSubmit) {
  var isInProgress = false;

  final tags = List.of(gFFI.abModel.currentAbTags);
  var selectedTag = currentTags.obs;

  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      setState(() {
        isInProgress = true;
      });
      await onSubmit(selectedTag);
      close();
    }

    return CustomAlertDialog(
      title: Text(translate("Edit Tag")),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(vertical: 8.0),
            child: Wrap(
              children: tags
                  .map((e) => AddressBookTag(
                      name: e,
                      tags: selectedTag,
                      onTap: () {
                        if (selectedTag.contains(e)) {
                          selectedTag.remove(e);
                        } else {
                          selectedTag.add(e);
                        }
                      },
                      showActionMenu: false))
                  .toList(growable: false),
            ),
          ),
          // NOT use Offstage to wrap LinearProgressIndicator
          if (isInProgress) const LinearProgressIndicator(),
        ],
      ),
      actions: [
        dialogButton("Cancel", onPressed: close, isOutline: true),
        dialogButton("OK", onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

void editAbPeerNoteDialog(String id) {
  var isInProgress = false;
  final currentNote = gFFI.abModel.getPeerNote(id);
  var controller = TextEditingController(text: currentNote);

  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      setState(() {
        isInProgress = true;
      });
      await gFFI.abModel.changeNote(id: id, note: controller.text);
      close();
    }

    return CustomAlertDialog(
      title: Text(translate("Edit note")),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: controller,
            autofocus: true,
            maxLines: 3,
            minLines: 1,
            maxLength: 300,
            decoration: InputDecoration(
              labelText: translate('Note'),
            ),
          ).workaroundFreezeLinuxMint(),
          // NOT use Offstage to wrap LinearProgressIndicator
          if (isInProgress) const LinearProgressIndicator(),
        ],
      ),
      actions: [
        dialogButton("Cancel", onPressed: close, isOutline: true),
        dialogButton("OK", onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
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
              ).workaroundFreezeLinuxMint(),
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

void addPeersToAbDialog(
  List<Peer> peers,
) async {
  Future<bool> addTo(String abname) async {
    final mapList = peers.map((e) {
      var json = e.toJson();
      // remove password when add to another address book to avoid re-share
      json.remove('password');
      json.remove('hash');
      return json;
    }).toList();
    final errMsg = await gFFI.abModel.addPeersTo(mapList, abname);
    if (errMsg == null) {
      showToast(translate('Successful'));
      return true;
    } else {
      BotToast.showText(text: errMsg, contentColor: Colors.red);
      return false;
    }
  }

  // if only one address book and it is personal, add to it directly
  if (gFFI.abModel.addressbooks.length == 1 &&
      gFFI.abModel.current.isPersonal()) {
    await addTo(gFFI.abModel.currentName.value);
    return;
  }

  RxBool isInProgress = false.obs;
  final names = gFFI.abModel.addressBooksCanWrite();
  RxString currentName = gFFI.abModel.currentName.value.obs;
  TextEditingController controller = TextEditingController();
  if (gFFI.peerTabModel.currentTab == PeerTabIndex.ab.index) {
    names.remove(currentName.value);
  }
  if (names.isEmpty) {
    debugPrint('no address book to add peers to, should not happen');
    return;
  }
  if (!names.contains(currentName.value)) {
    currentName.value = names[0];
  }
  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      if (controller.text != gFFI.abModel.translatedName(currentName.value)) {
        BotToast.showText(
            text: 'illegal address book name: ${controller.text}',
            contentColor: Colors.red);
        return;
      }
      isInProgress.value = true;
      if (await addTo(currentName.value)) {
        close();
      }
      isInProgress.value = false;
    }

    cancel() {
      close();
    }

    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(IconFont.addressBook, color: MyTheme.accent),
          Text(translate('Add to address book')).paddingOnly(left: 10),
        ],
      ),
      content: Obx(() => Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // https://github.com/flutter/flutter/issues/145081
              DropdownMenu(
                initialSelection: currentName.value,
                onSelected: (value) {
                  if (value != null) {
                    currentName.value = value;
                  }
                },
                dropdownMenuEntries: names
                    .map((e) => DropdownMenuEntry(
                        value: e, label: gFFI.abModel.translatedName(e)))
                    .toList(),
                inputDecorationTheme: InputDecorationTheme(
                    isDense: true, border: UnderlineInputBorder()),
                enableFilter: true,
                controller: controller,
              ),
              // NOT use Offstage to wrap LinearProgressIndicator
              isInProgress.value ? const LinearProgressIndicator() : Offstage()
            ],
          )),
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

void setSharedAbPasswordDialog(String abName, Peer peer) {
  TextEditingController controller = TextEditingController(text: '');
  RxBool isInProgress = false.obs;
  RxBool isInputEmpty = true.obs;
  bool passwordVisible = false;
  controller.addListener(() {
    isInputEmpty.value = controller.text.isEmpty;
  });
  gFFI.dialogManager.show((setState, close, context) {
    change(String password) async {
      isInProgress.value = true;
      bool res =
          await gFFI.abModel.changeSharedPassword(abName, peer.id, password);
      isInProgress.value = false;
      if (res) {
        showToast(translate('Successful'));
      }
      close();
    }

    cancel() {
      close();
    }

    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.key, color: MyTheme.accent),
          Text(translate(peer.password.isEmpty
                  ? 'Set shared password'
                  : 'Change Password'))
              .paddingOnly(left: 10),
        ],
      ),
      content: Obx(() => Column(children: [
            TextField(
              controller: controller,
              autofocus: true,
              obscureText: !passwordVisible,
              decoration: InputDecoration(
                suffixIcon: IconButton(
                  icon: Icon(
                      passwordVisible ? Icons.visibility : Icons.visibility_off,
                      color: MyTheme.lightTheme.primaryColor),
                  onPressed: () {
                    setState(() {
                      passwordVisible = !passwordVisible;
                    });
                  },
                ),
              ),
            ).workaroundFreezeLinuxMint(),
            if (!gFFI.abModel.current.isPersonal())
              Row(children: [
                Icon(Icons.info, color: Colors.amber).marginOnly(right: 4),
                Text(
                  translate('share_warning_tip'),
                  style: TextStyle(fontSize: 12),
                )
              ]).marginSymmetric(vertical: 10),
            // NOT use Offstage to wrap LinearProgressIndicator
            isInProgress.value ? const LinearProgressIndicator() : Offstage()
          ])),
      actions: [
        dialogButton(
          "Cancel",
          icon: Icon(Icons.close_rounded),
          onPressed: cancel,
          isOutline: true,
        ),
        if (peer.password.isNotEmpty)
          dialogButton(
            "Remove",
            icon: Icon(Icons.delete_outline_rounded),
            onPressed: () => change(''),
            buttonStyle: ButtonStyle(
                backgroundColor: MaterialStatePropertyAll(Colors.red)),
          ),
        Obx(() => dialogButton(
              "OK",
              icon: Icon(Icons.done_rounded),
              onPressed:
                  isInputEmpty.value ? null : () => change(controller.text),
            )),
      ],
      onSubmit: isInputEmpty.value ? null : () => change(controller.text),
      onCancel: cancel,
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

void changeUnlockPinDialog(String oldPin, Function() callback) {
  final pinController = TextEditingController(text: oldPin);
  final confirmController = TextEditingController(text: oldPin);
  String? pinErrorText;
  String? confirmationErrorText;
  final maxLength = bind.mainMaxEncryptLen();
  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      pinErrorText = null;
      confirmationErrorText = null;
      final pin = pinController.text.trim();
      final confirm = confirmController.text.trim();
      if (pin != confirm) {
        setState(() {
          confirmationErrorText =
              translate('The confirmation is not identical.');
        });
        return;
      }
      final errorMsg = bind.mainSetUnlockPin(pin: pin);
      if (errorMsg != '') {
        setState(() {
          pinErrorText = translate(errorMsg);
        });
        return;
      }
      callback.call();
      close();
    }

    return CustomAlertDialog(
      title: Text(translate("Set PIN")),
      content: Column(
        children: [
          DialogTextField(
            title: 'PIN',
            controller: pinController,
            obscureText: true,
            errorText: pinErrorText,
            maxLength: maxLength,
          ),
          DialogTextField(
            title: translate('Confirmation'),
            controller: confirmController,
            obscureText: true,
            errorText: confirmationErrorText,
            maxLength: maxLength,
          )
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

void checkUnlockPinDialog(String correctPin, Function() passCallback) {
  final controller = TextEditingController();
  String? errorText;
  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      final pin = controller.text.trim();
      if (correctPin != pin) {
        setState(() {
          errorText = translate('Wrong PIN');
        });
        return;
      }
      passCallback.call();
      close();
    }

    return CustomAlertDialog(
      content: Row(
        children: [
          Expanded(
              child: PasswordWidget(
            title: 'PIN',
            controller: controller,
            errorText: errorText,
            hintText: '',
          ))
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
