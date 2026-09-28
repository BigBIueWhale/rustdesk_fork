import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/custom_password.dart';
import 'package:get/get.dart';

typedef PermanentPasswordWriter = Future<bool> Function(String password);

class PermanentPasswordMutation {
  PermanentPasswordMutation._({
    required this.result,
  });

  final Future<bool> result;
  Object? _dialogOwner;

  void _claim(Object dialogOwner) {
    _dialogOwner = dialogOwner;
  }

  void _release(Object dialogOwner) {
    if (identical(_dialogOwner, dialogOwner)) {
      _dialogOwner = null;
    }
  }

  bool _isOwnedBy(Object dialogOwner) => identical(_dialogOwner, dialogOwner);
}

/// Retains the one native password write across dialog/Activity replacement.
/// A replacement dialog observes that exact write instead of starting another
/// one; the coordinator retains only the operation future, never the password
/// itself.
class PermanentPasswordMutationCoordinator {
  PermanentPasswordMutation? _active;

  PermanentPasswordMutation? claimActive(Object dialogOwner) {
    final active = _active;
    active?._claim(dialogOwner);
    return active;
  }

  PermanentPasswordMutation begin({
    required Object dialogOwner,
    required String password,
    required PermanentPasswordWriter writePassword,
  }) {
    final active = _active;
    if (active != null) {
      active._claim(dialogOwner);
      return active;
    }

    final mutation = PermanentPasswordMutation._(
      result: Future<bool>.sync(() => writePassword(password)),
    );
    mutation._claim(dialogOwner);
    _active = mutation;
    return mutation;
  }

  void release(
    PermanentPasswordMutation mutation,
    Object dialogOwner,
  ) {
    mutation._release(dialogOwner);
  }

  bool consume(
    PermanentPasswordMutation mutation,
    Object dialogOwner,
  ) {
    if (!identical(_active, mutation) || !mutation._isOwnedBy(dialogOwner)) {
      return false;
    }
    mutation._release(dialogOwner);
    _active = null;
    return true;
  }

  bool isOwnedBy(
    PermanentPasswordMutation mutation,
    Object dialogOwner,
  ) =>
      mutation._isOwnedBy(dialogOwner);
}

class _PasswordRule {
  const _PasswordRule(this.validate, this.label);

  final bool Function(String value) validate;
  final String label;
}

/// Owns one permanent-password mutation from validated input through durable
/// completion. While that mutation is in flight every competing dialog action
/// is closed, and a completion from a retired dialog cannot start a service or
/// mutate disposed UI state.
class PermanentPasswordDialog extends StatefulWidget {
  const PermanentPasswordDialog({
    super.key,
    required this.passwordSet,
    required this.maxLength,
    required this.writePassword,
    required this.mutationCoordinator,
    required this.close,
    this.statusTip = '',
    this.compactSpacing = false,
    this.compactActions = false,
    this.translateText,
  });

  final bool passwordSet;
  final int maxLength;
  final PermanentPasswordWriter writePassword;
  final PermanentPasswordMutationCoordinator mutationCoordinator;
  final VoidCallback close;
  final String statusTip;
  final bool compactSpacing;
  final bool compactActions;
  final String Function(String text)? translateText;

  @override
  State<PermanentPasswordDialog> createState() =>
      _PermanentPasswordDialogState();
}

class _PermanentPasswordDialogState extends State<PermanentPasswordDialog> {
  final Object _dialogOwner = Object();
  final _password = TextEditingController();
  final _confirmation = TextEditingController();
  final RxString _passwordStrength = ''.obs;
  late final List<_PasswordRule> _rules;

  String _passwordError = '';
  String _confirmationError = '';
  bool _canSubmit = false;
  bool _submitting = false;
  PermanentPasswordMutation? _mutation;

  String _translate(String text) =>
      widget.translateText?.call(text) ?? translate(text);

  @override
  void initState() {
    super.initState();
    _rules = [
      _PasswordRule(
        DigitValidationRule().validate,
        _translate('digit'),
      ),
      _PasswordRule(
        UppercaseValidationRule().validate,
        _translate('uppercase'),
      ),
      _PasswordRule(
        LowercaseValidationRule().validate,
        _translate('lowercase'),
      ),
      _PasswordRule(
        MinCharactersValidationRule(8).validate,
        _translate('length>=8'),
      ),
    ];
    final active = widget.mutationCoordinator.claimActive(_dialogOwner);
    if (active != null) {
      _mutation = active;
      _submitting = true;
      unawaited(_finishMutation(active));
    }
  }

  @override
  void dispose() {
    final mutation = _mutation;
    if (mutation != null) {
      widget.mutationCoordinator.release(mutation, _dialogOwner);
    }
    _password.dispose();
    _confirmation.dispose();
    _passwordStrength.close();
    super.dispose();
  }

  void _passwordChanged(String value) {
    _passwordStrength.value = value.trim();
    setState(() {
      _passwordError = '';
      _updateCanSubmit();
    });
  }

  void _confirmationChanged(String value) {
    setState(() {
      _confirmationError = '';
      _updateCanSubmit();
    });
  }

  void _updateCanSubmit() {
    _canSubmit = _password.text.trim().isNotEmpty ||
        _confirmation.text.trim().isNotEmpty;
  }

  Future<void> _submit() async {
    if (!_canSubmit || _submitting) {
      return;
    }
    final password = _password.text.trim();
    if (password.isNotEmpty) {
      final violations =
          _rules.where((rule) => !rule.validate(password)).toList();
      if (violations.isNotEmpty) {
        setState(() {
          _passwordError =
              '${_translate('Prompt')}: ${violations.map((rule) => rule.label).join(', ')}';
          _confirmationError = '';
        });
        return;
      }
    }
    if (_confirmation.text.trim() != password) {
      setState(() {
        _passwordError = '';
        _confirmationError =
            '${_translate('Prompt')}: ${_translate("The confirmation is not identical.")}';
      });
      return;
    }
    await _write(password);
  }

  Future<void> _remove() => _write('');

  Future<void> _write(String password) async {
    if (_submitting) {
      return;
    }
    setState(() {
      _submitting = true;
      _passwordError = '';
      _confirmationError = '';
    });

    final mutation = widget.mutationCoordinator.begin(
      dialogOwner: _dialogOwner,
      password: password,
      writePassword: widget.writePassword,
    );
    _mutation = mutation;
    await _finishMutation(mutation);
  }

  Future<void> _finishMutation(PermanentPasswordMutation mutation) async {
    var persisted = false;
    try {
      persisted = await mutation.result;
    } catch (error) {
      debugPrint(
        'Permanent password mutation failed: ${error.runtimeType}',
      );
    }
    if (!mounted ||
        !widget.mutationCoordinator.isOwnedBy(mutation, _dialogOwner)) {
      return;
    }
    if (!widget.mutationCoordinator.consume(mutation, _dialogOwner)) {
      return;
    }
    if (identical(_mutation, mutation)) {
      _mutation = null;
    }
    if (!persisted) {
      setState(() {
        _submitting = false;
        _passwordError = '${_translate('Prompt')}: ${_translate("Failed")}';
      });
      return;
    }

    widget.close();
  }

  @override
  Widget build(BuildContext context) {
    return CustomAlertDialog(
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.key, color: MyTheme.accent),
          Text(_translate('Set Password')).paddingOnly(left: 10),
        ],
      ),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 500),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(height: widget.compactSpacing ? 0 : 6),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    obscureText: true,
                    enabled: !_submitting,
                    decoration: InputDecoration(
                      labelText: _translate('Password'),
                      errorText:
                          _passwordError.isNotEmpty ? _passwordError : null,
                    ),
                    controller: _password,
                    autofocus: true,
                    onChanged: _passwordChanged,
                    maxLength: widget.maxLength,
                  ),
                ),
              ],
            ),
            Row(
              children: [
                Expanded(
                  child: PasswordStrengthIndicator(
                    password: _passwordStrength,
                    translateText: widget.translateText,
                  ),
                ),
              ],
            ).marginOnly(
              top: 2,
              bottom: widget.compactSpacing ? 2 : 8,
            ),
            SizedBox(height: widget.compactSpacing ? 0 : 8),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    obscureText: true,
                    enabled: !_submitting,
                    decoration: InputDecoration(
                      labelText: _translate('Confirmation'),
                      errorText: _confirmationError.isNotEmpty
                          ? _confirmationError
                          : null,
                    ),
                    controller: _confirmation,
                    onChanged: _confirmationChanged,
                    maxLength: widget.maxLength,
                  ),
                ),
              ],
            ),
            if (widget.statusTip.isNotEmpty)
              Row(
                children: [
                  Icon(Icons.info, color: Colors.amber, size: 18)
                      .marginOnly(right: 6),
                  Expanded(
                    child: Text(
                      widget.statusTip,
                      style: const TextStyle(fontSize: 13, height: 1.1),
                    ),
                  ),
                ],
              ).marginOnly(top: 6, bottom: 2),
            SizedBox(height: widget.compactSpacing ? 0 : 8),
            Obx(
              () => Wrap(
                runSpacing: widget.compactSpacing ? 2 : 8,
                spacing: 4,
                children: _rules.map((rule) {
                  final checked = rule.validate(_passwordStrength.value.trim());
                  return Chip(
                    label: Text(
                      rule.label,
                      style: TextStyle(
                        color: checked
                            ? const Color(0xFF0A9471)
                            : const Color.fromARGB(255, 198, 86, 157),
                      ),
                    ),
                    backgroundColor: checked
                        ? const Color(0xFFD0F7ED)
                        : const Color.fromARGB(255, 247, 205, 232),
                  );
                }).toList(),
              ),
            ),
            if (_submitting)
              Semantics(
                label: _translate('Waiting'),
                liveRegion: true,
                child: const LinearProgressIndicator(
                  key: ValueKey('permanent-password-progress'),
                ),
              ).marginOnly(top: widget.compactSpacing ? 2 : 8),
          ],
        ),
      ),
      actions: _buildActions(),
      onSubmit: _canSubmit && !_submitting ? _submit : null,
      onCancel: _submitting ? null : widget.close,
    );
  }

  List<Widget> _buildActions() {
    final cancelButton = dialogButton(
      'Cancel',
      icon: const Icon(Icons.close_rounded),
      onPressed: _submitting ? null : widget.close,
      isOutline: true,
      translateText: _translate,
    );
    final removeButton = dialogButton(
      'Remove',
      icon: const Icon(Icons.delete_outline_rounded),
      onPressed: _submitting ? null : _remove,
      buttonStyle: const ButtonStyle(
        backgroundColor: MaterialStatePropertyAll(Colors.red),
      ),
      translateText: _translate,
    );
    final okButton = dialogButton(
      'OK',
      icon: const Icon(Icons.done_rounded),
      onPressed: _canSubmit && !_submitting ? _submit : null,
      translateText: _translate,
    );
    if (widget.compactActions && widget.passwordSet) {
      return [
        Align(
          alignment: Alignment.centerRight,
          child: FittedBox(
            fit: BoxFit.scaleDown,
            alignment: Alignment.centerRight,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                cancelButton,
                const SizedBox(width: 4),
                removeButton,
                const SizedBox(width: 4),
                okButton,
              ],
            ),
          ),
        ),
      ];
    }
    return [
      cancelButton,
      if (widget.passwordSet) removeButton,
      okButton,
    ];
  }
}
