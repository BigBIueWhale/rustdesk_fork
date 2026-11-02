import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/session_view_mode.dart';

class ViewModeControl extends StatefulWidget {
  const ViewModeControl({super.key, required this.ffi,
      this.setting = ViewModeSetting.viewOnly, this.enabled = true,
      this.onSelected, this.translateText, this.showFailure});

  final FFI ffi;
  final ViewModeSetting setting;
  final bool enabled;
  final VoidCallback? onSelected;
  final String Function(String)? translateText;
  final VoidCallback? showFailure;

  @override
  State<ViewModeControl> createState() => _ViewModeControlState();
}

class _ViewModeControlState extends State<ViewModeControl> {
  late FFI _ffi;
  late SessionID _session;
  late SessionID _owner;
  late SessionViewMode _preferences;
  int _epoch = 0;

  bool _current(int epoch) => mounted && epoch == _epoch &&
      identical(widget.ffi, _ffi) && _ffi.isCurrentSessionOwner(_session, _owner);

  void _attach() {
    _ffi = widget.ffi;
    _session = _ffi.sessionId;
    _owner = _ffi.clientOwnerId;
    _preferences = _ffi.viewMode;
    _preferences.addListener(_changed);
    final epoch = _epoch;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!_current(epoch)) return;
      try {
        await _preferences.refresh();
      } catch (error) {
        debugPrint('Failed to read View mode: $error');
      }
    });
  }

  void _changed() {
    if (_current(_epoch)) setState(() {});
  }

  @override
  void initState() {
    super.initState();
    _attach();
  }

  @override
  void didUpdateWidget(covariant ViewModeControl oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(widget.ffi, _ffi) || widget.ffi.sessionId != _session ||
        widget.ffi.clientOwnerId != _owner) {
      _epoch++;
      _preferences.removeListener(_changed);
      _attach();
    }
  }

  @override
  void dispose() {
    _epoch++;
    _preferences.removeListener(_changed);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText ?? translate;
    final ffi = _ffi;
    final session = _session;
    final owner = _owner;
    final preferences = _preferences;
    final revision = preferences.revision;
    final setting = widget.setting;
    final state = preferences.value;
    final value = state == null ? null : setting == ViewModeSetting.viewOnly
        ? state.viewOnly : state.showMyCursor;
    final enabled = widget.enabled && _current(_epoch) && !preferences.busy;
    final retry = preferences.retryValue;
    final failed = preferences.failed && (retry == null || retry.$1 == setting);
    final label = text(setting == ViewModeSetting.viewOnly ? 'View Mode' : 'Show my cursor');
    final onSelected = widget.onSelected;
    final showFailure = widget.showFailure ?? () => showToast(translate('Failed'));
    // The menu can dispose this widget before invoking its selection callback.
    Future<void> choose(bool? requested) async {
      if (!ffi.isCurrentSessionOwner(session, owner) || preferences.busy ||
          revision != preferences.revision) return;
      onSelected?.call();
      try {
        if (requested == null) {
          await preferences.refresh();
        } else {
          await preferences.save(setting, requested);
        }
      } catch (error) {
        debugPrint('Failed to apply View mode: $error');
        if (ffi.isCurrentSessionOwner(session, owner)) showFailure();
      }
    }
    return Column(mainAxisSize: MainAxisSize.min, children: [
      if (value != null && isMobile) CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          visualDensity: VisualDensity.compact,
          value: value, onChanged: enabled ? choose : null,
          title: Text(label))
      else if (value != null) CheckboxMenuButton(
          value: value, onChanged: enabled ? choose : null,
          child: Text(label))
      else if (!failed) Text(text('Loading...')),
      if (failed) Row(mainAxisSize: MainAxisSize.min, children: [
        Text(text('Failed')),
        TextButton(onPressed: enabled ? () => choose(retry?.$2) : null,
            child: Text(text('Retry'))),
      ]),
    ]);
  }
}
