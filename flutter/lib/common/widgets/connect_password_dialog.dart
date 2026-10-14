import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart' show PasswordWidget;
import 'package:get/get.dart';

class ConnectPasswordDialog extends StatefulWidget {
  const ConnectPasswordDialog({
    super.key,
    required this.readRemember,
    required this.submitPassword,
    required this.close,
    required this.onCancel,
    required this.onAccepted,
    this.reason = '',
    this.translateText,
  });

  final Future<bool?> Function() readRemember;
  final bool Function(String password, bool remember) submitPassword;
  final DialogClose close;
  final VoidCallback onCancel;
  final VoidCallback onAccepted;
  final String reason;
  final String Function(String text)? translateText;

  @override
  State<ConnectPasswordDialog> createState() => _ConnectPasswordDialogState();
}

class _ConnectPasswordDialogState extends State<ConnectPasswordDialog> {
  final _password = TextEditingController();
  bool _remember = false;
  bool _rememberReady = false;
  bool _rememberChosen = false;
  bool _rememberError = false;
  bool _submissionError = false;
  bool _submitted = false;
  bool _retired = false;

  String _translate(String text) =>
      widget.translateText?.call(text) ?? translate(text);

  bool get _canSubmit =>
      _rememberReady && !_submitted && !_retired && widget.close.isCurrent;

  @override
  void initState() {
    super.initState();
    unawaited(_loadRemember());
  }

  @override
  void dispose() {
    _retired = true;
    _password.dispose();
    super.dispose();
  }

  Future<void> _loadRemember() async {
    try {
      final remember = await widget.readRemember();
      if (!mounted || _retired || _rememberChosen) return;
      if (remember == null) {
        setState(() => _rememberError = true);
        return;
      }
      setState(() {
        _remember = remember;
        _rememberReady = true;
      });
    } catch (error) {
      debugPrint('Remember password preference failed: ${error.runtimeType}');
      if (!mounted || _retired || _rememberChosen) return;
      setState(() => _rememberError = true);
    }
  }

  void _chooseRemember(bool? remember) {
    if (remember == null || _retired || _submitted) return;
    setState(() {
      _rememberChosen = true;
      _rememberReady = true;
      _rememberError = false;
      _remember = remember;
    });
  }

  void _cancel() {
    if (!mounted || _retired || _submitted) return;
    _retired = true;
    if (!widget.close()) return;
    widget.onCancel();
  }

  void _submit() {
    if (!mounted || !_canSubmit) return;
    final password = _password.text.trim();
    if (password.isEmpty) return;
    _submitted = true;
    var accepted = false;
    try {
      accepted = widget.submitPassword(password, _remember);
    } catch (error) {
      debugPrint('Connect password submission failed: ${error.runtimeType}');
    }
    if (!mounted || _retired) return;
    if (!accepted) {
      setState(() {
        _submitted = false;
        _submissionError = true;
      });
      return;
    }
    _retired = true;
    if (!widget.close()) return;
    widget.onAccepted();
  }

  @override
  Widget build(BuildContext context) {
    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.password_rounded, color: MyTheme.accent),
          Text(_translate('Password Required')).paddingOnly(left: 10),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          PasswordWidget(
            controller: _password,
            autoFocus: true,
            translateText: widget.translateText,
          ),
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            controlAffinity: ListTileControlAffinity.leading,
            title: Text(_translate('Remember password')),
            value: _remember,
            onChanged: _submitted || _retired ? null : _chooseRemember,
          ),
          if (!_rememberReady && !_rememberError)
            const LinearProgressIndicator(),
          if (_rememberError || _submissionError)
            Text('${_translate('Prompt')}: ${_translate('Failed')}'),
          if (widget.reason.isNotEmpty) ...[
            const SizedBox(height: 10),
            SelectableText(widget.reason, style: const TextStyle(fontSize: 14)),
          ] else ...[
            Text(
              _translate('verify_rustdesk_password_tip'),
              maxLines: 3,
              softWrap: true,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 16),
            ),
            const SizedBox(height: 8),
          ],
        ],
      ),
      actions: [
        dialogButton(
          'Cancel',
          icon: const Icon(Icons.close_rounded),
          onPressed: _submitted || _retired ? null : _cancel,
          isOutline: true,
          translateText: _translate,
        ),
        dialogButton(
          'OK',
          icon: const Icon(Icons.done_rounded),
          onPressed: _canSubmit ? _submit : null,
          translateText: _translate,
        ),
      ],
      onSubmit: _canSubmit ? _submit : null,
      onCancel: _submitted || _retired ? null : _cancel,
    );
  }
}
