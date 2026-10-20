import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/setting_checkbox.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';

class DefaultOptionCheckbox extends StatelessWidget {
  const DefaultOptionCheckbox({
    super.key,
    required this.optionKey,
    required this.label,
    required this.value,
    required this.falseValue,
    required this.enabled,
    required this.saveOption,
    required this.failureText,
  });

  final String optionKey;
  final String label;
  final String value;
  final String falseValue;
  final bool enabled;
  final Future<String?> Function(String, String) saveOption;
  final String failureText;

  @override
  Widget build(BuildContext context) {
    return SettingCheckbox(
      key: ValueKey(('user-default', optionKey)),
      label: label,
      value: value == 'Y',
      enabled: enabled,
      failureText: failureText,
      saveValue: (next) async {
        final effective = await saveOption(optionKey, next ? 'Y' : falseValue);
        return effective == null ? null : effective == 'Y';
      },
    );
  }
}

class CustomImageQualityWidget extends StatefulWidget {
  const CustomImageQualityWidget({
    super.key,
    required this.initQuality,
    required this.initFps,
    required this.saveQuality,
    required this.saveFps,
    required this.showFps,
    required this.showMoreQuality,
    this.translateText,
    this.mobileLayout,
    this.onClose,
  });

  final double initQuality;
  final double initFps;
  final Future<double?> Function(double)? saveQuality;
  final Future<double?> Function(double)? saveFps;
  final bool showFps;
  final bool showMoreQuality;
  final String Function(String)? translateText;
  final bool? mobileLayout;
  final VoidCallback? onClose;

  @override
  State<CustomImageQualityWidget> createState() => _CustomImageQualityWidgetState();
}

class _QualityField {
  _QualityField(this.minimum, this.maximum, this.fallback, double input,
      this.writer, this.enabled, this.changed) {
    value = confirmed = _input = _normalize(input);
  }

  final double minimum;
  double maximum;
  final double fallback;
  Future<double?> Function(double)? writer;
  bool enabled;
  final VoidCallback changed;
  late double value;
  late double confirmed;
  late double _input;
  Timer? _timer;
  Future<bool>? _pending;
  bool _alive = true;
  bool _dirty = false;
  bool _ready = false;
  bool _committed = false;
  bool _flushing = false;
  bool failed = false;
  int _epoch = 0;

  bool get active => _alive && enabled && writer != null;
  bool get saving => _pending != null;
  double _normalize(double input) =>
      input.isFinite && input >= minimum && input <= maximum ? input : fallback;

  void configure(double input, Future<double?> Function(double)? write,
      bool canEdit, double maxValue) {
    final replaced = enabled != canEdit || (writer == null) != (write == null) ||
        maximum != maxValue;
    writer = write;
    enabled = canEdit;
    maximum = maxValue;
    final next = _normalize(input);
    if (replaced) {
      _epoch++;
      _timer?.cancel();
      _timer = null;
      _dirty = _ready = failed = _committed = false;
      value = confirmed = _input = next;
    } else if (next != _input) {
      _input = confirmed = next;
      if (!_dirty && !saving) value = next;
    }
  }

  void edit(double next) {
    if (!active || !next.isFinite) return;
    _timer?.cancel();
    _timer = null;
    value = next.clamp(minimum, maximum).toDouble();
    failed = _ready = false;
    _dirty = saving || value != confirmed;
    changed();
    if (_dirty) _schedule();
  }

  void initialize() {
    if (!active || _committed || saving || _dirty) return;
    _dirty = true;
    changed();
    _schedule();
  }

  void _schedule() {
    _timer?.cancel();
    _timer = Timer(const Duration(seconds: 1), () {
      _timer = null;
      _ready = true;
      unawaited(save());
    });
  }

  void retry() {
    if (!active || saving || !failed) return;
    _timer?.cancel();
    _timer = null;
    _dirty = _ready = true;
    unawaited(save());
  }

  Future<bool> save() {
    final write = writer;
    if (!active || write == null || saving || !_ready || !_dirty) {
      return Future.value(false);
    }
    final done = Completer<bool>();
    final requested = value;
    final epoch = _epoch;
    _pending = done.future;
    _ready = failed = false;
    changed();
    unawaited(_complete(write, requested, epoch, done));
    return done.future;
  }

  Future<void> _complete(Future<double?> Function(double) write,
      double requested, int epoch, Completer<bool> done) async {
    double? effective;
    try {
      effective = await write(requested);
    } catch (error) {
      debugPrint('Failed to save image quality setting: $error');
    }
    _pending = null;
    var success = false;
    if (_alive && epoch == _epoch) {
      if (effective != null && effective.isFinite &&
          effective >= minimum && effective <= maximum) {
        confirmed = effective;
        _committed = true;
        if (value == requested) value = effective;
        _dirty = value != confirmed;
        success = true;
      } else {
        failed = value == requested;
        _dirty = failed || value != confirmed;
      }
    }
    if (_alive) changed();
    done.complete(success);
    if (_alive && !_flushing && _ready && _dirty) unawaited(save());
  }

  Future<bool> flush() async {
    _timer?.cancel();
    _timer = null;
    _ready = false;
    _flushing = true;
    try {
      while (_pending != null) {
        await _pending;
        if (!_alive) return false;
        if (active && failed) return false;
      }
      if (!_alive) return false;
      if (!active) return true;
      if (_dirty || !_committed) {
        _dirty = _ready = true;
        return await save();
      }
      return !failed;
    } finally {
      _flushing = false;
    }
  }

  void dispose() {
    _alive = false;
    _timer?.cancel();
    _timer = null;
  }
}

class _CustomImageQualityWidgetState extends State<CustomImageQualityWidget> {
  late final _QualityField _quality;
  late final _QualityField _fps;
  bool _moreSelected = false;
  bool _closing = false;
  bool _closeFailed = false;
  double get _qualityMaximum =>
      widget.showMoreQuality ? kMaxMoreQuality : kMaxQuality;
  bool get _more => widget.showMoreQuality &&
      (_moreSelected || _quality.value > kMaxQuality);

  void _refresh() {
    if (mounted) setState(() {});
  }

  @override
  void initState() {
    super.initState();
    _quality = _QualityField(kMinQuality, _qualityMaximum, kDefaultQuality,
        widget.initQuality, widget.saveQuality, true, _refresh);
    _fps = _QualityField(kMinFps, kMaxFps, kDefaultFps, widget.initFps,
        widget.saveFps, widget.showFps, _refresh);
    _moreSelected = _quality.value > kMaxQuality;
  }

  @override
  void didUpdateWidget(covariant CustomImageQualityWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    _quality.configure(widget.initQuality, widget.saveQuality, true, _qualityMaximum);
    _fps.configure(widget.initFps, widget.saveFps, widget.showFps, kMaxFps);
    if (!widget.showMoreQuality) _moreSelected = false;
  }

  @override
  void dispose() {
    _quality.dispose();
    _fps.dispose();
    super.dispose();
  }

  void _edit(_QualityField field, double value) {
    if (!mounted || _closing || !field.active) return;
    field.edit(value);
    if (widget.onClose != null) {
      _quality.initialize();
      _fps.initialize();
    }
  }

  void _changeMore(bool? value) {
    if (!mounted || _closing || !_quality.active || value == null) return;
    setState(() { _moreSelected = value; });
    if (!value && _quality.value > kMaxQuality) _edit(_quality, kMaxQuality);
  }

  Future<void> _close() async {
    final close = widget.onClose;
    if (!mounted || _closing || close == null) return;
    setState(() { _closing = true; _closeFailed = false; });
    try {
      final results = await Future.wait([_quality.flush(), _fps.flush()]);
      if (mounted && results.every((value) => value)) close();
    } catch (error) {
      debugPrint('Failed to close image quality editor: $error');
      if (mounted) setState(() { _closeFailed = true; });
    } finally {
      if (mounted) setState(() { _closing = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText ?? translate;
    final mobile = widget.mobileLayout ?? isMobile;
    final moreControl = Row(children: [
      Checkbox(value: _more,
        onChanged: _quality.active && !_closing ? _changeMore : null),
      Expanded(child: Text(text('More'))),
    ]);
    Widget status(_QualityField field) => Column(mainAxisSize: MainAxisSize.min,
      children: [
        if (field.saving) const LinearProgressIndicator(),
        if (field.failed) ...[
          Text(text('Failed')),
          TextButton(onPressed: field.active && !_closing && !field.saving
            ? () { if (mounted && !_closing) field.retry(); } : null,
            child: Text(text('Retry'))),
        ],
      ]);
    return Column(mainAxisSize: MainAxisSize.min, children: [
      Row(children: [
        Expanded(flex: 3, child: Slider(
          value: _quality.value, min: kMinQuality,
          max: _more ? kMaxMoreQuality : kMaxQuality,
          divisions: _more ? ((kMaxMoreQuality - kMinQuality) / 10).round()
              : ((kMaxQuality - kMinQuality) / 5).round(),
          onChanged: _quality.active && !_closing
              ? (v) => _edit(_quality, v) : null)),
        Expanded(child: Text(_quality.value.round().toString() + '%',
          style: const TextStyle(fontSize: 15))),
        Expanded(flex: mobile ? 2 : 1, child: Text(text('Bitrate'),
          style: const TextStyle(fontSize: 15))),
        if (widget.showMoreQuality && !mobile) Expanded(child: moreControl),
      ]),
      if (widget.showMoreQuality && mobile)
        Row(children: [const Spacer(), Expanded(child: moreControl)]),
      status(_quality),
      if (widget.showFps) ...[
        Row(children: [
          Expanded(flex: 3, child: Slider(
            value: _fps.value, min: kMinFps, max: kMaxFps,
            divisions: ((kMaxFps - kMinFps) / 5).round(),
            onChanged: _fps.active && !_closing
                ? (v) => _edit(_fps, v) : null)),
          Expanded(child: Text(_fps.value.round().toString(),
            style: const TextStyle(fontSize: 15))),
          Expanded(flex: 2, child: Text(text('FPS'),
            style: const TextStyle(fontSize: 15))),
        ]),
        status(_fps),
      ],
      if (_closeFailed) Text(text('Failed')),
      if (widget.onClose != null)
        Align(alignment: Alignment.centerRight, child: TextButton(
          onPressed: _closing ? null : _close, child: Text(text('Close')))),
    ]);
  }
}

Widget customImageQualitySetting(
    {required Future<String?> Function(String key, String value) saveOption}) {
  const qualityKey = 'custom_image_quality';
  const fpsKey = 'custom-fps';
  Future<double?> save(String key, double value) async {
    final effective = await saveOption(key, value.toString());
    return effective == null ? null : double.tryParse(effective);
  }
  return CustomImageQualityWidget(
    initQuality: double.tryParse(bind.mainGetUserDefaultOption(key: qualityKey)) ??
        kDefaultQuality,
    initFps: double.tryParse(bind.mainGetUserDefaultOption(key: fpsKey)) ?? kDefaultFps,
    saveQuality: isOptionFixed(qualityKey) ? null : (v) => save(qualityKey, v),
    saveFps: isOptionFixed(fpsKey) ? null : (v) => save(fpsKey, v),
    showFps: true,
    showMoreQuality: true,
  );
}

// R-G4 / R-X4 (§19): ServerConfigImportExportWidgets (the clipboard import/export of a full
// id/relay/api/key server config) is removed with the mobile "ID/Relay Server" editor it lived in
// — the trust-anchor-injection surface. Its importConfig/setServerConfig/ServerConfig backers go
// with it (common.dart), all now unreachable.

List<(String, String)> otherDefaultSettings() {
  List<(String, String)> v = [
    ('View Mode', kOptionViewOnly),
    if ((isDesktop || isWebDesktop))
      ('show_monitors_tip', kKeyShowMonitorsToolbar),
    if ((isDesktop || isWebDesktop))
      ('Collapse toolbar', kOptionCollapseToolbar),
    ('Show remote cursor', kOptionShowRemoteCursor),
    ('Follow remote cursor', kOptionFollowRemoteCursor),
    ('Follow remote window focus', kOptionFollowRemoteWindow),
    if ((isDesktop || isWebDesktop)) ('Zoom cursor', kOptionZoomCursor),
    ('Show quality monitor', kOptionShowQualityMonitor),
    ('Mute', kOptionDisableAudio),
    if (isDesktop) ('Enable file copy and paste', kOptionEnableFileCopyPaste),
    ('Disable clipboard', kOptionDisableClipboard),
    ('Lock after session end', kOptionLockAfterSessionEnd),
    ('Privacy mode', kOptionPrivacyMode),
    ('True color (4:4:4)', kOptionI444),
    ('Reverse mouse wheel', kKeyReverseMouseWheel),
    ('swap-left-right-mouse', kOptionSwapLeftRightMouse),
    if (isDesktop)
      (
        'Show displays as individual windows',
        kKeyShowDisplaysAsIndividualWindows
      ),
    if (isDesktop)
      (
        'Use all my displays for the remote session',
        kKeyUseAllMyDisplaysForTheRemoteSession
      ),
    ('Keep terminal sessions on disconnect', kOptionTerminalPersistent),
  ];

  return v;
}

class TrackpadSpeedWidget extends StatefulWidget {
  final SimpleWrapper<int> value;
  final ValueChanged<int?>? onChanged;
  final Future<int?> Function(int)? saveSpeed;
  final bool enabled;
  final String Function(String)? translateText;

  const TrackpadSpeedWidget({
    super.key,
    required this.value,
    this.onChanged,
    this.saveSpeed,
    this.enabled = true,
    this.translateText,
  });

  @override
  State<TrackpadSpeedWidget> createState() => _TrackpadSpeedWidgetState();
}

class _TrackpadSpeedWidgetState extends State<TrackpadSpeedWidget> {
  late final TextEditingController _controller;
  late int _value;
  late int _confirmed;
  late int _inputValue;
  Timer? _debounce;
  bool _dirty = false;
  bool _saving = false;
  bool _ready = false;
  bool _failed = false;
  int _epoch = 0;

  int _bounded(int value) => value.clamp(kMinTrackpadSpeed, kMaxTrackpadSpeed);

  @override
  void initState() {
    super.initState();
    _value = _confirmed = _inputValue = _bounded(widget.value.value);
    _controller = TextEditingController(text: _value.toString());
  }

  @override
  void didUpdateWidget(covariant TrackpadSpeedWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    final incoming = _bounded(widget.value.value);
    final changedMode = (oldWidget.saveSpeed == null) !=
        (widget.saveSpeed == null);
    if (oldWidget.enabled != widget.enabled || changedMode) {
      _epoch++;
      _debounce?.cancel();
      _debounce = null;
      _ready = _dirty = _failed = false;
      _value = _confirmed = _inputValue = incoming;
      _controller.text = incoming.toString();
    } else if (incoming != _inputValue) {
      final replaceDraft = !_dirty && !_saving &&
          _controller.text == _value.toString();
      _inputValue = _confirmed = incoming;
      if (replaceDraft) {
        _value = incoming;
        _controller.text = incoming.toString();
      }
    }
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _controller.dispose();
    super.dispose();
  }

  void _updateValue(int newValue) {
    if (!mounted || !widget.enabled) return;
    _debounce?.cancel();
    _debounce = null;
    setState(() {
      _value = _bounded(newValue);
      _inputValue = widget.value.value = _value;
      _controller.text = _value.toString();
      _failed = _ready = false;
      _dirty = widget.saveSpeed != null &&
          (_saving || _value != _confirmed);
      if (widget.saveSpeed == null) _confirmed = _value;
    });
    widget.onChanged?.call(_value);
    if (_dirty) {
      _debounce = Timer(const Duration(seconds: 1), () {
        _debounce = null;
        _ready = true;
        unawaited(_save());
      });
    }
  }

  void _submit(String text) {
    if (!mounted || !widget.enabled) return;
    final value = int.tryParse(text);
    if (value != null) {
      _updateValue(value);
    } else {
      _controller.text = _value.toString();
      widget.onChanged?.call(_value);
    }
  }

  void _retry() {
    if (!mounted || !widget.enabled || _saving || !_failed) return;
    _submit(_controller.text);
    _debounce?.cancel();
    _debounce = null;
    _ready = true;
    unawaited(_save());
  }

  Future<void> _save() async {
    if (!mounted) return;
    final write = widget.saveSpeed;
    if (!widget.enabled || write == null ||
        _saving || !_ready || !_dirty) return;
    final requested = _value;
    final epoch = _epoch;
    _ready = false;
    setState(() {
      _saving = true;
      _failed = false;
    });
    int? effective;
    try {
      effective = await write(requested);
    } catch (error) {
      debugPrint('Failed to save trackpad speed: $error');
    }
    if (!mounted) return;
    final confirmed = effective;
    setState(() {
      _saving = false;
      if (epoch != _epoch) return;
      if (confirmed != null &&
          confirmed >= kMinTrackpadSpeed &&
          confirmed <= kMaxTrackpadSpeed) {
        _confirmed = confirmed;
        if (_value == requested) {
          if (_controller.text == requested.toString()) {
            _controller.text = confirmed.toString();
          }
          _value = _inputValue = widget.value.value = confirmed;
        }
        _dirty = _value != _confirmed;
      } else {
        _failed = _value == requested;
        _dirty = _failed || _value != _confirmed;
      }
    });
    if (_ready) unawaited(_save());
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText ?? translate;
    return Column(mainAxisSize: MainAxisSize.min, children: [
      Row(
        children: [
          Expanded(
            flex: 3,
            child: Slider(
              value: _value.toDouble(),
              min: kMinTrackpadSpeed.toDouble(),
              max: kMaxTrackpadSpeed.toDouble(),
              divisions: ((kMaxTrackpadSpeed - kMinTrackpadSpeed) / 10).round(),
              onChanged: widget.enabled ? (v) => _updateValue(v.round()) : null,
            ),
          ),
          SizedBox(
              width: 88,
              child: Row(
                children: [
                  SizedBox(
                    width: 56,
                    child: TextField(
                      controller: _controller,
                      enabled: widget.enabled,
                      keyboardType: TextInputType.number,
                      textAlign: TextAlign.center,
                      onSubmitted: _submit,
                      onChanged: (value) => widget.onChanged?.call(int.tryParse(value)),
                      inputFormatters: [
                        TextInputFormatter.withFunction((oldValue, newValue) {
                          return RegExp(r'^[0-9]{0,4}$').hasMatch(newValue.text)
                              ? newValue : oldValue;
                        }),
                      ],
                      style: const TextStyle(fontSize: 13),
                      decoration: InputDecoration(
                        errorText: _failed ? text('Failed') : null,
                        contentPadding: const EdgeInsets.symmetric(
                            vertical: 8.0, horizontal: 12.0),
                      ),
                    ),
                  ).marginOnly(right: 8.0),
                  const Text('%', style: TextStyle(fontSize: 15)),
                ],
              )),
        ],
      ),
      if (_saving) const LinearProgressIndicator(),
      if (_failed)
        TextButton(
          onPressed: widget.enabled && !_saving ? _retry : null,
          child: Text(text('Retry')),
        ),
    ]);
  }
}
