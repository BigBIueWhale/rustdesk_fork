import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/reverse_mouse_wheel.dart';

class ReverseMouseWheelControl extends StatefulWidget {
  const ReverseMouseWheelControl({super.key, required this.ffi,
      this.enabled = true, this.translateText});

  final FFI ffi;
  final bool enabled;
  final String Function(String)? translateText;

  @override
  State<ReverseMouseWheelControl> createState() => _ReverseMouseWheelControlState();
}

class _ReverseMouseWheelControlState extends State<ReverseMouseWheelControl> {
  late FFI _ffi;
  late SessionID _sessionId;
  late SessionID _clientOwnerId;
  late ReverseMouseWheelPreferences _preferences;
  Object? _readToken;
  bool _failed = false;
  bool _deferredRead = false;
  bool? _retryValue;
  int _epoch = 0;
  int _actionRevision = 0;
  int _callbackRevision = 0;

  bool _current(int epoch) => mounted && epoch == _epoch &&
      identical(widget.ffi, _ffi) &&
      _ffi.isCurrentSessionOwner(_sessionId, _clientOwnerId);

  void _attach() {
    _ffi = widget.ffi;
    _sessionId = _ffi.sessionId;
    _clientOwnerId = _ffi.clientOwnerId;
    _preferences = _ffi.inputModel.reverseMouseWheel;
    _preferences.addListener(_changed);
  }

  void _scheduleRead() {
    final epoch = _epoch;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_current(epoch)) _read();
    });
  }

  void _changed() {
    if (!_current(_epoch)) return;
    setState(() {});
    if (_deferredRead && !_preferences.reading && !_preferences.saving) {
      _deferredRead = false;
      _read();
    }
  }

  @override
  void initState() {
    super.initState();
    _attach();
    _scheduleRead();
  }

  @override
  void didUpdateWidget(covariant ReverseMouseWheelControl oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(widget.ffi, _ffi) || widget.ffi.sessionId != _sessionId ||
        widget.ffi.clientOwnerId != _clientOwnerId) {
      _epoch++;
      _actionRevision++;
      _preferences.removeListener(_changed);
      _deferredRead = false;
      _readToken = null;
      _failed = false;
      _retryValue = null;
      _attach();
      _scheduleRead();
    }
    if (oldWidget.enabled != widget.enabled) {
      _callbackRevision++;
      _failed = false;
      _retryValue = null;
    }
  }

  Future<void> _read() async {
    if (_readToken != null || !_current(_epoch)) return;
    if (_preferences.reading || _preferences.saving) {
      _deferredRead = true;
      return;
    }
    final epoch = _epoch;
    final preferences = _preferences;
    final token = Object();
    _actionRevision++;
    setState(() { _readToken = token; _failed = false; _retryValue = null; });
    try {
      await preferences.read();
    } catch (error, stack) {
      debugPrint('Failed to read reverse mouse wheel: $error');
      debugPrintStack(stackTrace: stack);
      if (_current(epoch)) setState(() => _failed = true);
    } finally {
      if (mounted && identical(_readToken, token)) setState(() => _readToken = null);
    }
  }

  Future<void> _save(bool? value, int epoch, int action, int callback) async {
    if (value == null || !_current(epoch) || !widget.enabled || _preferences.saving ||
        action != _actionRevision || callback != _callbackRevision) return;
    final preferences = _preferences;
    _actionRevision++;
    setState(() { _failed = false; _retryValue = null; });
    try {
      final effective = await preferences.save(value);
      if (_current(epoch) && callback == _callbackRevision && effective == value) {
        setState(() { _failed = false; _retryValue = null; });
      }
    } catch (error, stack) {
      debugPrint('Failed to save reverse mouse wheel: $error');
      debugPrintStack(stackTrace: stack);
      if (_current(epoch) && callback == _callbackRevision) {
        setState(() { _failed = true; _retryValue = value; });
      }
    }
  }

  @override
  void dispose() {
    _epoch++;
    _deferredRead = false;
    _preferences.removeListener(_changed);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText ?? translate;
    final epoch = _epoch;
    final action = _actionRevision;
    final callback = _callbackRevision;
    final value = _preferences.value;
    final retryValue = _retryValue;
    final enabled = widget.enabled && _current(epoch) &&
        !_preferences.saving && _readToken == null;
    void choose(bool? value) => _save(value, epoch, action, callback);
    return Column(mainAxisSize: MainAxisSize.min, children: [
      if (value != null && isMobile) CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          visualDensity: VisualDensity.compact,
          value: value, onChanged: enabled ? choose : null,
          title: Text(text('Reverse mouse wheel')))
      else if (value != null) CheckboxMenuButton(
          value: value,
          onChanged: enabled ? choose : null,
          child: Text(text('Reverse mouse wheel')))
      else if (!_failed) Text(text('Loading...')),
      if (_failed) Row(mainAxisSize: MainAxisSize.min, children: [
        Text(text('Failed')),
        TextButton(key: const ValueKey('reverse-mouse-wheel-retry'),
            onPressed: !_current(epoch) || _preferences.saving ||
                (retryValue != null ? !widget.enabled : _readToken != null || _preferences.reading)
                ? null : () {
                  if (!_current(epoch) || action != _actionRevision || callback != _callbackRevision) return;
                  if (retryValue == null) {
                    _read();
                  } else {
                    _save(retryValue, epoch, action, callback);
                  }
                },
            child: Text(text('Retry'))),
      ]),
    ]);
  }
}
