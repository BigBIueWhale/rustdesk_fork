import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/consts.dart';

class TrackpadSpeedDialog extends StatefulWidget {
  const TrackpadSpeedDialog({
    super.key,
    required this.initialSpeed,
    required this.saveSpeed,
    required this.close,
    required this.translateText,
  });

  final int initialSpeed;
  final Future<int?> Function(int) saveSpeed;
  final DialogClose close;
  final String Function(String) translateText;

  @override
  State<TrackpadSpeedDialog> createState() => _TrackpadSpeedDialogState();
}

class _TrackpadSpeedDialogState extends State<TrackpadSpeedDialog> {
  late final _speed = SimpleWrapper(widget.initialSpeed);
  late int? _draft = widget.initialSpeed;
  bool _saving = false;
  bool _failed = false;

  bool get _current => mounted && widget.close.isCurrent;

  void _changed(int? value) {
    if (!_current || _saving) return;
    _draft = value;
    if (value != null) {
      _speed.value = value.clamp(kMinTrackpadSpeed, kMaxTrackpadSpeed);
    }
  }

  void _cancel() {
    if (_current && !_saving) widget.close();
  }

  Future<void> _save() async {
    if (!_current || _saving) return;
    final draft = _draft;
    if (draft == null) {
      setState(() => _failed = true);
      return;
    }
    final requested = draft.clamp(kMinTrackpadSpeed, kMaxTrackpadSpeed);
    _speed.value = requested;
    if (requested == widget.initialSpeed) {
      widget.close();
      return;
    }
    setState(() {
      _saving = true;
      _failed = false;
    });
    try {
      final effective = await widget.saveSpeed(requested);
      if (!_current) return;
      if (effective == requested) {
        widget.close();
        return;
      }
    } catch (error) {
      debugPrint('Failed to save trackpad speed: $error');
    }
    if (!_current) return;
    setState(() {
      _saving = false;
      _failed = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText;
    return CustomAlertDialog(
      title: Text(text('Trackpad speed')),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        TrackpadSpeedWidget(
          value: _speed,
          onChanged: _changed,
          enabled: !_saving,
          translateText: text,
        ),
        if (_saving) const LinearProgressIndicator(),
        if (_failed) Text(text('Failed')),
      ]),
      actions: [
        dialogButton(_failed ? 'Retry' : 'Close',
            onPressed: _saving ? null : _save, translateText: text),
      ],
      onSubmit: _save,
      onCancel: _cancel,
    );
  }
}
