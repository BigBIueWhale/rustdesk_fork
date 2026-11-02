import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/session_audio_mute.dart';

class AudioMuteControl extends StatefulWidget {
  const AudioMuteControl({super.key, required this.ffi,
      this.translateText, this.showFailure});

  final FFI ffi;
  final String Function(String)? translateText;
  final VoidCallback? showFailure;

  @override
  State<AudioMuteControl> createState() => _AudioMuteControlState();
}

class _AudioMuteControlState extends State<AudioMuteControl> {
  late FFI _ffi;
  late SessionID _session;
  late SessionID _owner;
  late SessionAudioMute _preferences;
  int _epoch = 0;

  bool _current(int epoch) => mounted && epoch == _epoch &&
      identical(widget.ffi, _ffi) && _ffi.isCurrentSessionOwner(_session, _owner);

  void _attach() {
    _ffi = widget.ffi;
    _session = _ffi.sessionId;
    _owner = _ffi.clientOwnerId;
    _preferences = _ffi.audioMute;
    _preferences.addListener(_changed);
    final epoch = _epoch;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!_current(epoch)) return;
      try {
        await _preferences.refresh();
      } catch (error) {
        debugPrint('Failed to read Mute preference: $error');
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
  void didUpdateWidget(covariant AudioMuteControl oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(widget.ffi, _ffi) || widget.ffi.sessionId != _session ||
        widget.ffi.clientOwnerId != _owner) {
      _epoch++;
      _preferences.removeListener(_changed);
      _attach();
    }
  }

  Future<void> _choose(bool? muted, int epoch, int revision) async {
    if (!_current(epoch) || _preferences.busy || revision != _preferences.revision) return;
    final preferences = _preferences;
    final ffi = _ffi;
    final session = _session;
    final owner = _owner;
    final showFailure = widget.showFailure ?? () => showToast(translate('Failed'));
    try {
      if (muted == null) {
        await preferences.refresh();
      } else {
        await preferences.save(muted);
      }
    } catch (error) {
      debugPrint('Failed to apply Mute preference: $error');
      // The menu may have closed, but this exact session still owns the result.
      if (ffi.isCurrentSessionOwner(session, owner)) showFailure();
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
    final epoch = _epoch;
    final revision = _preferences.revision;
    final value = _preferences.value;
    final enabled = _current(epoch) && !_preferences.busy;
    final retry = _preferences.retryValue;
    void choose(bool? value) => _choose(value, epoch, revision);
    return Column(mainAxisSize: MainAxisSize.min, children: [
      if (value != null && isMobile) CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          visualDensity: VisualDensity.compact,
          value: value, onChanged: enabled ? choose : null,
          title: Text(text('Mute')))
      else if (value != null) CheckboxMenuButton(
          value: value, onChanged: enabled ? choose : null,
          child: Text(text('Mute')))
      else if (!_preferences.failed) Text(text('Loading...')),
      if (_preferences.failed) Row(mainAxisSize: MainAxisSize.min, children: [
        Text(text('Failed')),
        TextButton(onPressed: enabled ? () => choose(retry) : null,
            child: Text(text('Retry'))),
      ]),
    ]);
  }
}
