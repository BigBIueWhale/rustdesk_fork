import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:texture_rgba_renderer/texture_rgba_renderer.dart';

typedef _TryOnRgbaNative = Int32 Function(
  Pointer<Void>,
  Pointer<Uint8>,
  Int32,
  Int32,
  Int32,
  Int32,
);
typedef _TryOnRgba = int Function(
  Pointer<Void>,
  Pointer<Uint8>,
  int,
  int,
  int,
  int,
);
typedef _TryNotifyNative = Int32 Function(Pointer<Void>);
typedef _TryNotify = int Function(Pointer<Void>);
typedef _MallocNative = Pointer<Void> Function(UintPtr);
typedef _Malloc = Pointer<Void> Function(int);
typedef _FreeNative = Void Function(Pointer<Void>);
typedef _Free = void Function(Pointer<Void>);

const _textureKey = 0x52535052;
const _width = 320;
const _height = 240;
const _frameBytes = _width * _height * 4;
const _hiddenFrameCount = 128;

Future<void> _waitForMarker(
  String directory,
  String name,
  String expected,
) async {
  final file = File('$directory/$name');
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  while (DateTime.now().isBefore(deadline)) {
    if (await file.exists()) {
      final value = await file.readAsString();
      if (value != expected) {
        throw StateError(
            '$name has unexpected contents: ${value.length} bytes');
      }
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  throw TimeoutException('timed out waiting for $name');
}

Future<void> _publishMarker(
  String directory,
  String name,
  String value,
) async {
  final destination = File('$directory/$name');
  if (await destination.exists()) {
    throw StateError('$name already exists');
  }
  final temporary = File('$directory/.${name}.${pid}.tmp');
  await temporary.writeAsString(value, flush: true);
  await temporary.rename(destination.path);
}

void _fillRgba(Uint8List bytes, int red, int green, int blue) {
  for (var offset = 0; offset < bytes.length; offset += 4) {
    bytes[offset] = red;
    bytes[offset + 1] = green;
    bytes[offset + 2] = blue;
    bytes[offset + 3] = 255;
  }
}

Future<void> _frameWorker(List<Object> arguments) async {
  final stateDirectory = arguments[0] as String;
  final libraryPath = arguments[1] as String;
  final textureAddress = arguments[2] as int;
  final sendPort = arguments[3] as SendPort;
  Pointer<Void>? allocation;
  try {
    final library = DynamicLibrary.open(libraryPath);
    final tryOnRgba = library.lookupFunction<_TryOnRgbaNative, _TryOnRgba>(
      'FlutterRgbaRendererPluginTryOnRgba',
    );
    final tryNotify = library.lookupFunction<_TryNotifyNative, _TryNotify>(
      'FlutterRgbaRendererPluginTryNotifyPending',
    );
    final process = DynamicLibrary.process();
    final malloc = process.lookupFunction<_MallocNative, _Malloc>('malloc');
    final free = process.lookupFunction<_FreeNative, _Free>('free');
    allocation = malloc(_frameBytes);
    if (allocation.address == 0) {
      throw StateError('malloc returned null');
    }
    final frame = allocation.cast<Uint8>().asTypedList(_frameBytes);
    final texture = Pointer<Void>.fromAddress(textureAddress);

    _fillRgba(frame, 255, 0, 0);
    if (tryOnRgba(
            texture, allocation.cast(), _frameBytes, _width, _height, 1) !=
        1) {
      throw StateError('initial direct-ABI frame was rejected');
    }
    await _publishMarker(
      stateDirectory,
      'initial-submitted',
      'red direct-abi\n',
    );
    await _waitForMarker(stateDirectory, 'switch', 'hidden\n');

    for (var frameNumber = 0; frameNumber < _hiddenFrameCount; frameNumber++) {
      final isLast = frameNumber == _hiddenFrameCount - 1;
      _fillRgba(
        frame,
        isLast ? 0 : (frameNumber * 17) & 0xff,
        isLast ? 255 : (frameNumber * 29) & 0xff,
        isLast ? 0 : (frameNumber * 43) & 0xff,
      );
      if (tryOnRgba(
            texture,
            allocation.cast(),
            _frameBytes,
            _width,
            _height,
            1,
          ) !=
          1) {
        throw StateError('hidden direct-ABI frame $frameNumber was rejected');
      }
    }
    await _publishMarker(
      stateDirectory,
      'updated',
      'green frames=$_hiddenFrameCount\n',
    );
    await _waitForMarker(stateDirectory, 'remapped', 'visible\n');
    if (tryNotify(texture) != 1) {
      throw StateError('pending-frame notification was rejected');
    }
    await _publishMarker(stateDirectory, 'renotified', 'accepted\n');
    await _waitForMarker(stateDirectory, 'finish', 'green-visible\n');
    sendPort.send('finish');
    free(allocation);
    allocation = null;
  } catch (error, stackTrace) {
    sendPort.send('failure:$error\n$stackTrace');
  } finally {
    if (allocation != null) {
      final free =
          DynamicLibrary.process().lookupFunction<_FreeNative, _Free>('free');
      free(allocation);
    }
  }
}

class _LifecycleObserver with WidgetsBindingObserver {
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    stdout.writeln('FLUTTER_LIFECYCLE_STATE=${state.name}');
  }
}

Future<void> main(List<String> arguments) async {
  stdout.writeln('FLUTTER_PROBE_STEP=dart-main begin');
  await stdout.flush();
  WidgetsFlutterBinding.ensureInitialized();
  if (arguments.length != 1) {
    stderr.writeln('expected one private state-directory argument');
    exit(64);
  }
  final stateDirectory = Directory(arguments.single);
  if (!stateDirectory.isAbsolute || !await stateDirectory.exists()) {
    stderr.writeln('state directory is absent or not absolute');
    exit(64);
  }
  stdout.writeln('FLUTTER_PROBE_STEP=texture-create begin');
  await stdout.flush();
  final renderer = TextureRgbaRenderer();
  final textureId = await renderer.createTexture(_textureKey);
  final textureAddress = await renderer.getTexturePtr(_textureKey);
  if (textureId <= 0 || textureAddress == 0) {
    stderr.writeln(
      'texture creation failed: id=$textureId pointer=$textureAddress',
    );
    exit(1);
  }
  stdout.writeln(
    'FLUTTER_PROBE_STEP=texture-create ok id=$textureId pointer=$textureAddress',
  );
  await stdout.flush();

  final observer = _LifecycleObserver();
  WidgetsBinding.instance.addObserver(observer);
  runApp(
    MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        backgroundColor: Colors.black,
        body: SizedBox.expand(child: Texture(textureId: textureId)),
      ),
    ),
  );
  stdout.writeln('FLUTTER_PROBE_STEP=run-app ok');
  await stdout.flush();

  final libraryPath =
      '${Directory.current.path}/lib/libtexture_rgba_renderer_plugin.so';
  final receivePort = ReceivePort();
  await Isolate.spawn<List<Object>>(
    _frameWorker,
    <Object>[
      stateDirectory.path,
      libraryPath,
      textureAddress,
      receivePort.sendPort,
    ],
  );
  await for (final message in receivePort) {
    if (message == 'finish') {
      final closed = await renderer.closeTexture(_textureKey);
      WidgetsBinding.instance.removeObserver(observer);
      stdout.writeln(
        'FLUTTER_PROBE_APP_OK texture_id=$textureId '
        'direct_abi=true hidden_frames=$_hiddenFrameCount closed=$closed',
      );
      await stdout.flush();
      receivePort.close();
      exit(closed ? 0 : 1);
    }
    stderr.writeln(message);
    await stderr.flush();
    receivePort.close();
    exit(1);
  }
}
