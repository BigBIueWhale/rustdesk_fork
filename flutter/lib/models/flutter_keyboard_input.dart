import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/platform_model.dart';

const maxFlutterInputSequence = 9007199254740991;

int? flutterModifierSlot(LogicalKeyboardKey key) {
  const keys = [
    LogicalKeyboardKey.shiftLeft, LogicalKeyboardKey.shiftRight,
    LogicalKeyboardKey.controlLeft, LogicalKeyboardKey.controlRight,
    LogicalKeyboardKey.altLeft, LogicalKeyboardKey.altRight,
    LogicalKeyboardKey.metaLeft, LogicalKeyboardKey.metaRight,
    LogicalKeyboardKey.superKey,
  ];
  final slot = keys.indexOf(key);
  return slot < 0 ? null : slot;
}

class FlutterKeyboardTarget {
  const FlutterKeyboardTarget(this.sessionId, this.clientOwnerId, this.round, this.epoch);
  final SessionID sessionId;
  final SessionID clientOwnerId;
  final String round;
  final int epoch;
}

class FlutterKeyStroke {
  const FlutterKeyStroke.key(this.name, this.usbHid, this.lockModes, this.down)
      : kind = 'key', platformCode = 0, positionCode = 0,
        press = false, alt = false, ctrl = false, shift = false, command = false;
  const FlutterKeyStroke.raw(this.name, this.platformCode, this.positionCode, this.lockModes, this.down)
      : kind = 'raw', usbHid = 0,
        press = false, alt = false, ctrl = false, shift = false, command = false;
  const FlutterKeyStroke.legacy(this.name, this.down, this.press, this.alt, this.ctrl, this.shift, this.command)
      : kind = 'legacy', usbHid = 0, platformCode = 0, positionCode = 0, lockModes = 0;
  final String kind;
  final String name;
  final int usbHid, platformCode, positionCode, lockModes;
  final bool down, press, alt, ctrl, shift, command;
}

abstract class FlutterKeyboardInputBackend {
  bool get useFlutterInput;
  Future<String> readRound(SessionID sessionId, SessionID clientOwnerId);
  Future<void> send(FlutterKeyboardTarget target, int sequence, int? slot, FlutterKeyStroke stroke);
  Future<void> release(FlutterKeyboardTarget target, int sequence, int? slot);
  void enterOrLeave(SessionID sessionId, bool enter);
}

class NativeFlutterKeyboardInputBackend implements FlutterKeyboardInputBackend {
  const NativeFlutterKeyboardInputBackend();
  @override
  bool get useFlutterInput => isInputSourceFlutter;
  @override
  Future<String> readRound(SessionID sessionId, SessionID clientOwnerId) =>
      bind.sessionKeyboardInputRound(sessionId: sessionId, clientOwnerId: clientOwnerId);
  @override
  Future<void> send(FlutterKeyboardTarget target, int sequence, int? slot, FlutterKeyStroke stroke) {
    switch (stroke.kind) {
      case 'key':
        return bind.sessionHandleFlutterKeyEvent(
            sessionId: target.sessionId, clientOwnerId: target.clientOwnerId,
            inputEpoch: target.epoch, inputRound: target.round,
            inputSequence: sequence, modifierSlot: slot,
            character: stroke.name, usbHid: stroke.usbHid,
            lockModes: stroke.lockModes, downOrUp: stroke.down);
      case 'raw':
        return bind.sessionHandleFlutterRawKeyEvent(
            sessionId: target.sessionId, clientOwnerId: target.clientOwnerId,
            inputEpoch: target.epoch, inputRound: target.round,
            inputSequence: sequence, modifierSlot: slot,
            name: stroke.name, platformCode: stroke.platformCode,
            positionCode: stroke.positionCode, lockModes: stroke.lockModes,
            downOrUp: stroke.down);
      case 'legacy':
        return bind.sessionInputKey(
            sessionId: target.sessionId, clientOwnerId: target.clientOwnerId,
            inputEpoch: target.epoch, inputRound: target.round,
            inputSequence: sequence, modifierSlot: slot,
            name: stroke.name, down: stroke.down, press: stroke.press,
            alt: stroke.alt, ctrl: stroke.ctrl, shift: stroke.shift, command: stroke.command);
      default:
        throw StateError('Unknown Flutter key representation');
    }
  }
  @override
  Future<void> release(FlutterKeyboardTarget target, int sequence, int? slot) =>
      bind.sessionReleaseFlutterModifiers(
          sessionId: target.sessionId, clientOwnerId: target.clientOwnerId,
          inputEpoch: target.epoch, inputSequence: sequence, modifierSlot: slot);
  @override
  void enterOrLeave(SessionID sessionId, bool enter) {
    if (!useFlutterInput) bind.sessionEnterOrLeave(sessionId: sessionId, enter: enter);
    if (!isWeb && enter) bind.setCurSessionId(sessionId: sessionId);
  }
}

/// Retains the UI and connection identity at admission, including before a bridge worker runs.
class FlutterKeyboardInput {
  FlutterKeyboardInput(this.parent, this.backend);
  final WeakReference<FFI> parent;
  final FlutterKeyboardInputBackend backend;
  FlutterKeyboardTarget? _target;
  FFI? _owner;
  int _epoch = 1;
  int _sequence = 0;
  int _readGeneration = 0;
  final List<int?> _held = List.filled(9, null);

  bool get ready => _target != null && identical(parent.target, _owner) &&
      _owner!.isCurrentSessionOwner(_target!.sessionId, _target!.clientOwnerId);

  Future<void> resume() async {
    final owner = parent.target;
    if (owner == null) return;
    final session = owner.sessionId;
    final client = owner.clientOwnerId;
    final generation = ++_readGeneration;
    final String round;
    try {
      round = await backend.readRound(session, client);
    } catch (error) {
      if (generation == _readGeneration) suspend();
      debugPrint('Flutter keyboard connection is unavailable: $error');
      return;
    }
    if (generation != _readGeneration || !identical(parent.target, owner) ||
        !owner.isCurrentSessionOwner(session, client)) return;
    if (ready && _target!.round == round) return;
    releaseAll();
    _owner = owner;
    _target = FlutterKeyboardTarget(session, client, round, _epoch);
  }

  void _observe(Future<void> operation) {
    operation.catchError((Object error) {
      debugPrint('Flutter keyboard operation failed: $error');
    });
  }

  bool releaseSlot(int slot) {
    final sequence = _held[slot];
    final target = _target;
    if (sequence == null || target == null) return false;
    _held[slot] = null;
    _observe(backend.release(target, sequence, slot));
    return true;
  }

  void releaseAll() {
    final target = _target;
    _held.fillRange(0, _held.length, null);
    if (_epoch == maxFlutterInputSequence) {
      _target = null;
      _owner = null;
      throw StateError('Flutter keyboard input epoch exhausted');
    }
    _epoch++;
    if (target != null) {
      _target = FlutterKeyboardTarget(target.sessionId, target.clientOwnerId, target.round, _epoch);
      _observe(backend.release(target, 0, null));
    }
  }

  void suspend() {
    ++_readGeneration;
    releaseAll();
    _target = null;
    _owner = null;
  }

  void send(FlutterKeyStroke stroke, {int? slot, SessionID? expectedSessionId}) {
    if (!ready || (expectedSessionId != null && expectedSessionId != _target!.sessionId)) return;
    if (slot != null && !stroke.down && !stroke.press) {
      releaseSlot(slot);
      return;
    }
    if (_sequence == maxFlutterInputSequence) {
      suspend();
      throw StateError('Flutter key press sequence exhausted');
    }
    final sequence = slot != null && stroke.down && !stroke.press
        ? (_held[slot] ??= ++_sequence) : ++_sequence;
    _observe(backend.send(_target!, sequence, slot, stroke));
  }
}
