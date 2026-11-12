import 'dart:convert';
import 'package:flutter/foundation.dart';

class IncomingRecordingSetting {
  const IncomingRecordingSetting(this.enabled, this.pending);
  final bool? enabled;
  final bool pending;

  static IncomingRecordingSetting decode(String encoded) {
    final value = jsonDecode(encoded);
    if (value is! Map<String, dynamic> || value.length != 2 ||
        !value.containsKey('enabled') ||
        (value['enabled'] != null && value['enabled'] is! bool) ||
        value['pending'] is! bool) {
      throw const FormatException('Invalid incoming recording setting');
    }
    return IncomingRecordingSetting(value['enabled'], value['pending']);
  }
}

enum IncomingRecordingChangeOutcome { applied, denied, failed, uncertain }

class IncomingRecordingChange {
  const IncomingRecordingChange(this.outcome, this.enabled);
  final IncomingRecordingChangeOutcome outcome;
  final bool? enabled;
}

class IncomingRecordingSettingModel extends ChangeNotifier {
  IncomingRecordingSettingModel(this.save);
  final Future<IncomingRecordingChange> Function(bool) save;
  IncomingRecordingSetting _setting = const IncomingRecordingSetting(null, false);
  bool _submitting = false;
  IncomingRecordingChangeOutcome? outcome;

  bool? get enabled => _setting.enabled;
  bool get pending => _submitting || _setting.pending;

  void update(IncomingRecordingSetting setting) {
    if (setting.enabled == _setting.enabled && setting.pending == _setting.pending) return;
    _setting = setting;
    notifyListeners();
  }

  Future<void> change(bool enabled) async {
    if (pending || this.enabled == null) return;
    _submitting = true;
    outcome = null;
    notifyListeners();
    try {
      final result = await save(enabled);
      outcome = result.outcome;
      if (result.outcome == IncomingRecordingChangeOutcome.applied) {
        if (result.enabled == null) {
          outcome = IncomingRecordingChangeOutcome.uncertain;
        } else {
          _setting = IncomingRecordingSetting(result.enabled, false);
        }
      }
    } catch (error) {
      // An FFI failure cannot establish that the receiver did not commit.
      debugPrint('Incoming recording change is unconfirmed: $error');
      outcome = IncomingRecordingChangeOutcome.uncertain;
    } finally {
      _submitting = false;
      notifyListeners();
    }
  }
}
