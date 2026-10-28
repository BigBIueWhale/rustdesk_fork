import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/generated_bridge.dart'
    if (dart.library.html) 'package:flutter_hbb/web/bridge.dart' show SoundInput;
import 'package:flutter_hbb/models/platform_model.dart';

const _kSystemSound = 'System Sound';

typedef AudioINputSetDevice = Future<void> Function(String device);
typedef AudioInputBuilder = Widget Function(
    Map<String, String> devices, String currentDevice, AudioINputSetDevice setDevice);
typedef AudioInputDeviceLoader = Future<AudioInputDevices> Function(
    bool isCm, bool isVoiceCall);
typedef AudioInputDeviceWriter = Future<void> Function(
    String device, bool isCm, bool isVoiceCall);

class AudioInputDevices {
  final Map<String, String> devices;
  final String current;

  AudioInputDevices(Map<String, String> devices, this.current)
      : devices = Map.unmodifiable(devices);

  factory AudioInputDevices.fromInputs(
      Iterable<SoundInput> inputs, String current, {String? systemSoundLabel}) {
    final devices = <String, String>{
      if (systemSoundLabel != null) '': systemSoundLabel,
      for (final input in inputs)
        input.id: input.label.isEmpty ? input.id : input.label,
    };
    final counts = <String, int>{};
    for (final label in devices.values) {
      counts.update(label, (count) => count + 1, ifAbsent: () => 1);
    }
    return AudioInputDevices({
      for (final device in devices.entries)
        device.key: device.key.isNotEmpty && counts[device.value]! > 1
            ? '${device.value} (${device.key})'
            : device.value,
    }, current);
  }
}

class AudioInput extends StatefulWidget {
  final AudioInputBuilder builder;
  final bool isCm;
  final bool isVoiceCall;
  final AudioInputDeviceLoader? loadDevicesInfo;
  final AudioInputDeviceWriter? writeDevice;
  final String? failureText;
  final String? retryText;

  const AudioInput(
      {Key? key,
      required this.builder,
      required this.isCm,
      required this.isVoiceCall,
      this.loadDevicesInfo,
      this.writeDevice,
      this.failureText,
      this.retryText})
      : super(key: key);

  static Future<String> getAudioInput(bool isCm, bool isVoiceCall) {
    if (isVoiceCall) {
      return bind.getVoiceCallInputDevice(isCm: isCm);
    } else {
      return bind.mainGetOption(key: 'audio-input');
    }
  }

  static Future<void> setDevice(
      String device, bool isCm, bool isVoiceCall) async {
    if (isVoiceCall) {
      await bind.setVoiceCallInputDevice(isCm: isCm, device: device);
    } else {
      await bind.mainSetOption(key: 'audio-input', value: device);
    }
  }

  static Future<AudioInputDevices> getDevicesInfo(
      bool isCm, bool isVoiceCall) async {
    final devices = await bind.mainGetSoundInputs();
    final current = await getAudioInput(isCm, isVoiceCall);
    return AudioInputDevices.fromInputs(devices, current,
        systemSoundLabel: bind.mainAudioSupportLoopback()
            ? translate(_kSystemSound) : null);
  }

  @override
  State<AudioInput> createState() => _AudioInputState();
}

class _AudioInputState extends State<AudioInput> {
  late Future<AudioInputDevices> _devices;
  Object _owner = Object();
  Object? _readToken;
  bool _readPending = false;
  bool _writePending = false;
  bool _writeFailed = false;

  Future<AudioInputDevices> _readDevices() {
    final token = Object();
    _readToken = token;
    _readPending = true;
    final load = widget.loadDevicesInfo ?? AudioInput.getDevicesInfo;
    final isCm = widget.isCm;
    final isVoiceCall = widget.isVoiceCall;
    return Future<AudioInputDevices>.sync(() => load(isCm, isVoiceCall))
        .whenComplete(() {
      if (identical(_readToken, token)) _readPending = false;
    });
  }

  @override
  void initState() {
    super.initState();
    _devices = _readDevices();
  }

  @override
  void didUpdateWidget(covariant AudioInput oldWidget) {
    super.didUpdateWidget(oldWidget);
    final ownerChanged = oldWidget.isCm != widget.isCm ||
        oldWidget.isVoiceCall != widget.isVoiceCall ||
        oldWidget.loadDevicesInfo != widget.loadDevicesInfo ||
        oldWidget.writeDevice != widget.writeDevice;
    if (ownerChanged) {
      _owner = Object();
      _writeFailed = false;
    }
    if (ownerChanged || (!_readPending && !_writePending)) {
      _devices = _readDevices();
    }
  }

  @override
  void dispose() {
    _owner = Object();
    _readToken = null;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final read = _devices;
    final owner = _owner;
    final write = widget.writeDevice ?? AudioInput.setDevice;
    final isCm = widget.isCm;
    final isVoiceCall = widget.isVoiceCall;
    final controls = FutureBuilder<AudioInputDevices>(
      future: read,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const SizedBox(height: 2, child: LinearProgressIndicator());
        }
        if (snapshot.hasError) {
          debugPrint('Failed to load audio inputs: ${snapshot.error}');
          return Wrap(
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 8,
            children: [
              if (!_writeFailed)
                Text(widget.failureText ?? translate('Failed')),
              TextButton(
                onPressed: () {
                  if (!mounted ||
                      _writePending ||
                      !identical(owner, _owner) ||
                      !identical(read, _devices)) return;
                  setState(() {
                    _devices = _readDevices();
                  });
                },
                child: Text(widget.retryText ?? translate('Retry')),
              ),
            ],
          );
        }
        final data = snapshot.data!;
        final currentDevice = data.current;
        final devices = data.devices;
        if (devices.isEmpty) return const Offstage();
        return widget.builder(devices, currentDevice, (device) async {
          if (!mounted ||
              _writePending ||
              !identical(owner, _owner) ||
              !identical(read, _devices)) return;
          setState(() {
            _writePending = true;
            _writeFailed = false;
          });
          var failed = false;
          try {
            await write(device, isCm, isVoiceCall);
          } catch (error) {
            debugPrint('Failed to set audio input: $error');
            failed = true;
          } finally {
            if (mounted) {
              setState(() {
                _writePending = false;
                if (identical(owner, _owner)) {
                  _writeFailed = failed;
                  _devices = _readDevices();
                }
              });
            }
          }
        });
      },
    );
    return Column(mainAxisSize: MainAxisSize.min, children: [
      if (_writeFailed)
        Text(widget.failureText ?? translate('Failed')),
      if (_writePending)
        const SizedBox(height: 2, child: LinearProgressIndicator()),
      AbsorbPointer(absorbing: _writePending, child: controls),
    ]);
  }
}
