import 'dart:async';

import 'package:debounce_throttle/debounce_throttle.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';

customImageQualityWidget(
    {required double initQuality,
    required double initFps,
    required Function(double)? setQuality,
    required Function(double)? setFps,
    required bool showFps,
    required bool showMoreQuality,
    String Function(String)? translateText,
    bool? mobileLayout}) {
  final text = translateText ?? translate;
  final mobile = mobileLayout ?? isMobile;
  if (initQuality < kMinQuality ||
      initQuality > (showMoreQuality ? kMaxMoreQuality : kMaxQuality)) {
    initQuality = kDefaultQuality;
  }
  if (initFps < kMinFps || initFps > kMaxFps) {
    initFps = kDefaultFps;
  }
  final qualityValue = initQuality.obs;
  final fpsValue = initFps.obs;

  final RxBool moreQualityChecked = RxBool(qualityValue.value > kMaxQuality);
  final debouncerQuality = Debouncer<double>(
    Duration(milliseconds: 1000),
    onChanged: setQuality,
    initialValue: qualityValue.value,
  );
  final debouncerFps = Debouncer<double>(
    Duration(milliseconds: 1000),
    onChanged: setFps,
    initialValue: fpsValue.value,
  );

  onMoreChanged(bool? value) {
    if (value == null) return;
    moreQualityChecked.value = value;
    if (!value && qualityValue.value > 100) {
      qualityValue.value = 100;
    }
    debouncerQuality.value = qualityValue.value;
  }

  return Column(
    children: [
      Obx(() => Row(
            children: [
              Expanded(
                flex: 3,
                child: Slider(
                  value: qualityValue.value,
                  min: kMinQuality,
                  max: moreQualityChecked.value ? kMaxMoreQuality : kMaxQuality,
                  divisions: moreQualityChecked.value
                      ? ((kMaxMoreQuality - kMinQuality) / 10).round()
                      : ((kMaxQuality - kMinQuality) / 5).round(),
                  onChanged: setQuality == null
                      ? null
                      : (double value) async {
                          qualityValue.value = value;
                          debouncerQuality.value = value;
                        },
                ),
              ),
              Expanded(
                  flex: 1,
                  child: Text(
                    '${qualityValue.value.round()}%',
                    style: const TextStyle(fontSize: 15),
                  )),
              Expanded(
                  flex: mobile ? 2 : 1,
                  child: Text(
                    text('Bitrate'),
                    style: const TextStyle(fontSize: 15),
                  )),
              // mobile doesn't have enough space
              if (showMoreQuality && !mobile)
                Expanded(
                    flex: 1,
                    child: Row(
                      children: [
                        Checkbox(
                          value: moreQualityChecked.value,
                          onChanged: onMoreChanged,
                        ),
                        Expanded(
                          child: Text(text('More')),
                        )
                      ],
                    ))
            ],
          )),
      if (showMoreQuality && mobile)
        Obx(() => Row(
              children: [
                Expanded(
                  child: Align(
                    alignment: Alignment.centerRight,
                    child: Checkbox(
                      value: moreQualityChecked.value,
                      onChanged: onMoreChanged,
                    ),
                  ),
                ),
                Expanded(
                  child: Text(text('More')),
                )
              ],
            )),
      if (showFps)
        Obx(() => Row(
              children: [
                Expanded(
                  flex: 3,
                  child: Slider(
                    value: fpsValue.value,
                    min: kMinFps,
                    max: kMaxFps,
                    divisions: ((kMaxFps - kMinFps) / 5).round(),
                    onChanged: setFps == null
                        ? null
                        : (double value) async {
                            fpsValue.value = value;
                            debouncerFps.value = value;
                          },
                  ),
                ),
                Expanded(
                    flex: 1,
                    child: Text(
                      '${fpsValue.value.round()}',
                      style: const TextStyle(fontSize: 15),
                    )),
                Expanded(
                    flex: 2,
                    child: Text(
                      text('FPS'),
                      style: const TextStyle(fontSize: 15),
                    ))
              ],
            )),
    ],
  );
}

customImageQualitySetting(
    {required Future<String?> Function(String key, String value) saveOption}) {
  final qualityKey = 'custom_image_quality';
  final fpsKey = 'custom-fps';

  final initQuality =
      (double.tryParse(bind.mainGetUserDefaultOption(key: qualityKey)) ??
          kDefaultQuality);
  final isQuanlityFixed = isOptionFixed(qualityKey);
  final initFps =
      (double.tryParse(bind.mainGetUserDefaultOption(key: fpsKey)) ??
          kDefaultFps);
  final isFpsFixed = isOptionFixed(fpsKey);

  return customImageQualityWidget(
      initQuality: initQuality,
      initFps: initFps,
      setQuality: isQuanlityFixed
          ? null
          : (v) {
              return saveOption(qualityKey, v.toString());
            },
      setFps: isFpsFixed
          ? null
          : (v) {
              return saveOption(fpsKey, v.toString());
            },
      showFps: true,
      showMoreQuality: true);
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
  final Future<int?> Function(int)? saveSpeed;
  final bool enabled;
  final String Function(String)? translateText;

  const TrackpadSpeedWidget({
    super.key,
    required this.value,
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
          Expanded(
              flex: 1,
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
