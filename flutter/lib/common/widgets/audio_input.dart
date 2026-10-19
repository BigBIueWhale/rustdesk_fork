import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';

const _kSystemSound = 'System Sound';

typedef AudioINputSetDevice = Future<void> Function(String device);
typedef AudioInputBuilder = Widget Function(
    List<String> devices, String currentDevice, AudioINputSetDevice setDevice);
typedef AudioInputDeviceLoader = Future<Map<String, Object>> Function(
    bool isCm, bool isVoiceCall);
typedef AudioInputDeviceWriter = Future<void> Function(
    String device, bool isCm, bool isVoiceCall);

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

  static String getDefault() {
    if (bind.mainAudioSupportLoopback()) return translate(_kSystemSound);
    return '';
  }

  static Future<String> getAudioInput(bool isCm, bool isVoiceCall) {
    if (isVoiceCall) {
      return bind.getVoiceCallInputDevice(isCm: isCm);
    } else {
      return bind.mainGetOption(key: 'audio-input');
    }
  }

  static Future<String> getValue(bool isCm, bool isVoiceCall) async {
    String device = await getAudioInput(isCm, isVoiceCall);
    if (device.isNotEmpty) {
      return device;
    } else {
      return getDefault();
    }
  }

  static Future<void> setDevice(
      String device, bool isCm, bool isVoiceCall) async {
    if (device == getDefault()) device = '';
    try {
      if (isVoiceCall) {
        await bind.setVoiceCallInputDevice(isCm: isCm, device: device);
      } else {
        await mainSetOption('audio-input', device);
      }
    } catch (error) {
      debugPrint('Failed to set audio input: $error');
      showToast(translate('Failed'));
    }
  }

  static Future<Map<String, Object>> getDevicesInfo(
      bool isCm, bool isVoiceCall) async {
    List<String> devices = (await bind.mainGetSoundInputs()).toList();
    if (bind.mainAudioSupportLoopback()) {
      devices.insert(0, translate(_kSystemSound));
    }
    String current = await getValue(isCm, isVoiceCall);
    return {'devices': devices, 'current': current};
  }

  @override
  State<AudioInput> createState() => _AudioInputState();
}

class _AudioInputState extends State<AudioInput> {
  late Future<Map<String, Object>> _devices;
  Object _owner = Object();
  Object? _readToken;
  bool _readPending = false;

  Future<Map<String, Object>> _readDevices() {
    final token = Object();
    _readToken = token;
    _readPending = true;
    final load = widget.loadDevicesInfo ?? AudioInput.getDevicesInfo;
    final isCm = widget.isCm;
    final isVoiceCall = widget.isVoiceCall;
    return Future<Map<String, Object>>.sync(() => load(isCm, isVoiceCall))
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
    if (ownerChanged) _owner = Object();
    if (ownerChanged || !_readPending) _devices = _readDevices();
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
    return FutureBuilder<Map<String, Object>>(
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
              Text(widget.failureText ?? translate('Failed')),
              TextButton(
                onPressed: () {
                  if (!mounted ||
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
        final currentDevice = data['current'] as String;
        final devices = data['devices'] as List<String>;
        if (devices.isEmpty) return const Offstage();
        return widget.builder(devices, currentDevice, (device) async {
          if (!mounted ||
              !identical(owner, _owner) ||
              !identical(read, _devices)) return;
          try {
            await write(device, isCm, isVoiceCall);
          } finally {
            if (mounted && identical(owner, _owner)) {
              setState(() {
                _devices = _readDevices();
              });
            }
          }
        });
      },
    );
  }
}
