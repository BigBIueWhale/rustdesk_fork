import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/material.dart';
import 'package:texture_rgba_renderer/texture_rgba_renderer.dart';

import 'presentation_recovery.dart';

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
typedef _MoveFileNative = Int32 Function(
  Pointer<Uint16>,
  Pointer<Uint16>,
);
typedef _MoveFile = int Function(Pointer<Uint16>, Pointer<Uint16>);
typedef _GetLastErrorNative = Uint32 Function();
typedef _GetLastError = int Function();

const _textureKey = 0x52535750;
const _width = 400;
const _height = 300;
const _frameBytes = _width * _height * 4;
const _queuedFrameCount = 128;

class _Markers {
  _Markers(this.directory);

  static final _runtime = DynamicLibrary.open('ucrtbase.dll');
  static final _malloc =
      _runtime.lookupFunction<_MallocNative, _Malloc>('malloc');
  static final _free = _runtime.lookupFunction<_FreeNative, _Free>('free');
  static final _kernel32 = DynamicLibrary.open('kernel32.dll');
  static final _moveFile =
      _kernel32.lookupFunction<_MoveFileNative, _MoveFile>('MoveFileW');
  static final _getLastError = _kernel32
      .lookupFunction<_GetLastErrorNative, _GetLastError>('GetLastError');

  final Directory directory;

  File _file(String name) => File('${directory.path}/$name');

  static Pointer<Uint16> _widePath(String value) {
    final units = value.codeUnits;
    final pointer =
        _malloc((units.length + 1) * sizeOf<Uint16>()).cast<Uint16>();
    if (pointer.address == 0) {
      throw StateError('ucrtbase malloc returned null for marker path');
    }
    final buffer = pointer.asTypedList(units.length + 1);
    buffer.setRange(0, units.length, units);
    buffer[units.length] = 0;
    return pointer;
  }

  static void _moveFileNoReplace(String sourcePath, String destinationPath) {
    final source = _widePath(sourcePath);
    try {
      final destination = _widePath(destinationPath);
      try {
        if (_moveFile(source, destination) == 0) {
          final error = _getLastError();
          throw FileSystemException(
            'MoveFileW failed without replacement',
            sourcePath,
            OSError('Win32 error', error),
          );
        }
      } finally {
        _free(destination.cast<Void>());
      }
    } finally {
      _free(source.cast<Void>());
    }
  }

  Future<void> waitFor(String name, String expected) async {
    final file = _file(name);
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (DateTime.now().isBefore(deadline)) {
      if (await file.exists()) {
        final value = await file.readAsString();
        if (value != expected) {
          throw StateError('$name has unexpected contents');
        }
        return;
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    throw TimeoutException('timed out waiting for $name');
  }

  Future<void> publish(String name, String value) async {
    final destination = _file(name);
    if (await destination.exists()) {
      throw StateError('$name already exists');
    }
    final temporary = _file('.$name.$pid.tmp');
    var published = false;
    try {
      await temporary.create(exclusive: true);
      await temporary.writeAsString(value, flush: true);
      _moveFileNoReplace(temporary.path, destination.path);
      published = true;
    } finally {
      if (!published && await temporary.exists()) {
        await temporary.delete();
      }
    }
  }

  void event(String value) {
    _file('events.log').writeAsStringSync(
      '${DateTime.now().toUtc().toIso8601String()} $value\n',
      mode: FileMode.append,
      flush: true,
    );
  }
}

class _NativeTexture {
  _NativeTexture._(
    this.renderer,
    this.textureId,
    this.texturePointer,
    this._buffer,
    this._tryOnRgba,
    this._tryNotify,
    this._free,
  );

  final TextureRgbaRenderer renderer;
  final int textureId;
  final Pointer<Void> texturePointer;
  final Pointer<Uint8> _buffer;
  final _TryOnRgba _tryOnRgba;
  final _TryNotify _tryNotify;
  final _Free _free;
  bool _closed = false;

  static Future<_NativeTexture> create() async {
    final renderer = TextureRgbaRenderer();
    final textureId = await renderer.createTexture(_textureKey);
    final textureAddress = await renderer.getTexturePtr(_textureKey);
    if (textureId <= 0 || textureAddress == 0) {
      throw StateError(
        'texture creation failed: id=$textureId pointer=$textureAddress',
      );
    }
    final library = DynamicLibrary.open('texture_rgba_renderer_plugin.dll');
    final tryOnRgba = library.lookupFunction<_TryOnRgbaNative, _TryOnRgba>(
      'FlutterRgbaRendererPluginTryOnRgba',
    );
    final tryNotify = library.lookupFunction<_TryNotifyNative, _TryNotify>(
      'FlutterRgbaRendererPluginTryNotifyPending',
    );
    final runtime = DynamicLibrary.open('ucrtbase.dll');
    final malloc = runtime.lookupFunction<_MallocNative, _Malloc>('malloc');
    final free = runtime.lookupFunction<_FreeNative, _Free>('free');
    final buffer = malloc(_frameBytes).cast<Uint8>();
    if (buffer.address == 0) {
      throw StateError('ucrtbase malloc returned null');
    }
    return _NativeTexture._(
      renderer,
      textureId,
      Pointer<Void>.fromAddress(textureAddress),
      buffer,
      tryOnRgba,
      tryNotify,
      free,
    );
  }

  void submit(int red, int green, int blue) {
    if (_closed) {
      throw StateError('cannot submit to a closed texture');
    }
    final bytes = _buffer.asTypedList(_frameBytes);
    for (var offset = 0; offset < bytes.length; offset += 4) {
      bytes[offset] = red;
      bytes[offset + 1] = green;
      bytes[offset + 2] = blue;
      bytes[offset + 3] = 255;
    }
    if (_tryOnRgba(
          texturePointer,
          _buffer,
          _frameBytes,
          _width,
          _height,
          1,
        ) !=
        1) {
      throw StateError('direct texture frame was rejected');
    }
  }

  void queueFinalColor(int red, int green, int blue) {
    for (var frame = 0; frame < _queuedFrameCount; frame++) {
      final finalFrame = frame == _queuedFrameCount - 1;
      submit(
        finalFrame ? red : (frame * 17) & 0xff,
        finalFrame ? green : (frame * 29) & 0xff,
        finalFrame ? blue : (frame * 43) & 0xff,
      );
    }
  }

  void notifyPending() {
    if (_closed || _tryNotify(texturePointer) != 1) {
      throw StateError('pending texture notification was rejected');
    }
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final unregistered = await renderer.closeTexture(_textureKey);
    if (!unregistered) {
      throw StateError('texture unregister was rejected');
    }
    _free(_buffer.cast());
  }
}

class _ProbeApp extends StatefulWidget {
  const _ProbeApp({
    required this.markers,
    required this.texture,
    required this.windowId,
  });

  final _Markers markers;
  final _NativeTexture texture;
  final int windowId;

  @override
  State<_ProbeApp> createState() => _ProbeAppState();
}

class _ProbeAppState extends State<_ProbeApp>
    with MultiWindowListener, WidgetsBindingObserver {
  final PresentationRecovery _recovery = PresentationRecovery();
  int _activeCycle = 0;
  bool _windowBlurred = false;
  bool _finished = false;
  bool _bindingsRetired = false;
  Future<void>? _destroyFuture;

  @override
  void initState() {
    super.initState();
    DesktopMultiWindow.addListener(this);
    WidgetsBinding.instance.addObserver(this);
    DesktopMultiWindow.setMethodHandler((call, fromWindowId) async {
      if (call.method == 'onDestroy') {
        await _beginResponseBoundDestroy();
      }
      return null;
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(_run().catchError(_fatal));
    });
  }

  Future<void> _fatal(Object error, StackTrace stackTrace) async {
    stderr.writeln('WINDOWS_PRESENTATION_PROBE_FAILURE=$error');
    stderr.writeln(stackTrace);
    stderr.flush();
    try {
      widget.markers.event('fatal ${error.runtimeType}');
      File('${widget.markers.directory.path}/app-failure.txt')
          .writeAsStringSync('${error.runtimeType}\n', flush: true);
    } catch (_) {
      // The original failure remains the authoritative result.
    }
    await WindowController.main().close();
  }

  Future<void> _runCycle(
    int cycle,
    int red,
    int green,
    int blue,
  ) async {
    await widget.markers.waitFor('arm-$cycle', 'arm\n');
    _activeCycle = cycle;
    await widget.markers.publish('armed-$cycle', 'armed\n');
    await widget.markers.waitFor('hidden-$cycle', 'hidden\n');
    widget.texture.queueFinalColor(red, green, blue);
    await widget.markers.publish(
      'updated-$cycle',
      'frames=$_queuedFrameCount\n',
    );
    await widget.markers.waitFor('displayed-$cycle', 'displayed\n');
  }

  Future<void> _run() async {
    widget.texture.submit(255, 255, 255);
    await widget.markers.publish('initial-submitted', 'white\n');
    await _runCycle(1, 0, 255, 0);
    await _runCycle(2, 255, 0, 255);
    _activeCycle = 0;
    await widget.markers.publish('close-requested', 'requested\n');
    await WindowController.fromWindowId(widget.windowId).close();
  }

  Future<void> _beginResponseBoundDestroy() {
    return _destroyFuture ??= _completeResponseBoundDestroy();
  }

  Future<void> _completeResponseBoundDestroy() async {
    await widget.markers.publish('destroy-started', 'started\n');
    widget.texture.submit(0, 0, 255);
    await widget.markers.publish('destroy-frame-submitted', 'blue\n');
    await widget.markers.waitFor('allow-destroy-completion', 'allow\n');
    _finished = true;
    _recovery.retire();
    await widget.texture.close();
    _retireBindings();
    await widget.markers.publish('destroy-cleanup-complete', 'complete\n');
  }

  void _retireBindings() {
    if (_bindingsRetired) return;
    _bindingsRetired = true;
    DesktopMultiWindow.removeListener(this);
    WidgetsBinding.instance.removeObserver(this);
    DesktopMultiWindow.setMethodHandler(null);
  }

  void _suspend(String reason) {
    if (_finished) return;
    widget.markers.event('suspend cycle=$_activeCycle reason=$reason');
    _recovery.suspend();
  }

  void _resume(String reason) {
    if (_finished) return;
    widget.markers.event('resume cycle=$_activeCycle reason=$reason');
    unawaited(_recovery
        .resume(
          selected: true,
          refresh: () async {
            final cycle = _activeCycle;
            if (cycle != 1 && cycle != 2) {
              throw StateError('refresh has no active cycle');
            }
            await widget.markers.publish(
              'rearm-requested-$cycle',
              'requested\n',
            );
            await widget.markers.waitFor(
              'allow-rearm-$cycle',
              'allow\n',
            );
            widget.texture.notifyPending();
            await widget.markers.publish(
              'renotified-$cycle',
              'accepted\n',
            );
          },
          onError: (error, stackTrace) {
            _fatal(error, stackTrace);
          },
        )
        .catchError(_fatal));
  }

  @override
  void onWindowBlur() {
    _windowBlurred = true;
    _suspend('window-blur');
  }

  @override
  void onWindowFocus() {
    _windowBlurred = false;
    _resume('window-focus');
  }

  @override
  void onWindowMinimize() {
    _suspend('window-minimize');
  }

  @override
  void onWindowRestore() {
    _windowBlurred = false;
    _resume('window-restore');
  }

  @override
  void onWindowMaximize() {
    _windowBlurred = false;
    _resume('window-maximize');
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    widget.markers.event('flutter-lifecycle state=${state.name}');
  }

  void _pointerDown(PointerDownEvent event) {
    final cycle = _activeCycle;
    widget.markers.event('pointer-down cycle=$cycle');
    unawaited(widget.markers
        .publish('pointer-down-$cycle', 'delivered\n')
        .catchError(_fatal));
    if (_windowBlurred) {
      _windowBlurred = false;
      _resume('pointer-down-fallback');
    }
  }

  @override
  void dispose() {
    _finished = true;
    _recovery.retire();
    _retireBindings();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        backgroundColor: Colors.black,
        body: Listener(
          behavior: HitTestBehavior.opaque,
          onPointerDown: _pointerDown,
          child: SizedBox.expand(
            child: Texture(textureId: widget.texture.textureId),
          ),
        ),
      ),
    );
  }
}

Future<Directory> _stateDirectory(String path) async {
  final directory = Directory(path);
  if (!directory.isAbsolute || !await directory.exists()) {
    throw ArgumentError('state directory is absent or not absolute');
  }
  return directory;
}

Future<void> _launchPresentationWindow(Directory directory) async {
  DesktopMultiWindow.setMethodHandler((call, fromWindowId) async => null);
  final presentationWindow =
      await DesktopMultiWindow.createWindow(directory.path);
  if (presentationWindow.windowId <= 0) {
    throw StateError('presentation window did not receive a subwindow id');
  }
  await presentationWindow.setFrame(
    const Rect.fromLTWH(80, 80, 800, 600),
  );
  await presentationWindow.setTitle('RustDesk Windows Presentation Probe');

  final parentWindow = WindowController.main();
  await parentWindow.hide();
  if (!await parentWindow.isHidden()) {
    throw StateError('primary bootstrap window remained visible');
  }
  await presentationWindow.show();
  await _Markers(directory).publish(
    'window-admitted',
    'secondary-visible\n',
  );
  final markers = _Markers(directory);
  final initialIds = await DesktopMultiWindow.getAllSubWindowIds();
  if (initialIds.length != 1 ||
      initialIds.single != presentationWindow.windowId) {
    throw StateError('initial subwindow ownership differs');
  }
  await markers.waitFor('destroy-cleanup-complete', 'complete\n');
  final deadline = DateTime.now().add(const Duration(seconds: 15));
  while (DateTime.now().isBefore(deadline)) {
    final ids = await DesktopMultiWindow.getAllSubWindowIds();
    if (ids.isEmpty) {
      await markers.publish('subwindow-retired', 'retired\n');
      await markers.publish('app-finished', 'ok\n');
      await WindowController.main().close();
      return;
    }
    if (ids.length != 1 || ids.single != presentationWindow.windowId) {
      throw StateError('subwindow ownership changed before retirement');
    }
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  throw TimeoutException('subwindow owner did not retire after Dart cleanup');
}

Future<void> _runPresentationWindow(
  Directory directory,
  int windowId,
) async {
  if (windowId <= 0) {
    throw ArgumentError('presentation window id is not positive');
  }
  DesktopMultiWindow.setMethodHandler((call, fromWindowId) async => null);
  final markers = _Markers(directory);
  await markers.publish('window-role', 'desktop-multi-window-subwindow\n');
  final texture = await _NativeTexture.create();
  runApp(_ProbeApp(
    markers: markers,
    texture: texture,
    windowId: windowId,
  ));
}

Future<void> main(List<String> arguments) async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    if (arguments.length == 1) {
      await _launchPresentationWindow(
        await _stateDirectory(arguments.single),
      );
      return;
    }
    if (arguments.length == 3 && arguments.first == 'multi_window') {
      final windowId = int.tryParse(arguments[1]);
      if (windowId == null) {
        throw ArgumentError('presentation window id is malformed');
      }
      await _runPresentationWindow(
        await _stateDirectory(arguments[2]),
        windowId,
      );
      return;
    }
    throw ArgumentError('unexpected presentation probe arguments');
  } catch (error, stackTrace) {
    stderr.writeln('WINDOWS_PRESENTATION_PROBE_START_FAILURE=$error');
    stderr.writeln(stackTrace);
    await WindowController.main().close();
  }
}
