import 'dart:convert';

class IncomingRecordingFailure {
  const IncomingRecordingFailure(this.display, this.camera, this.stage);

  final int display;
  final bool camera;
  final String stage;
}

class IncomingRecordingStatus {
  const IncomingRecordingStatus(
      this.starting, this.active, this.finishing, this.lastFailure);

  final int starting;
  final int active;
  final int finishing;
  final IncomingRecordingFailure? lastFailure;

  static IncomingRecordingStatus? decode(String encoded) {
    final value = jsonDecode(encoded);
    if (value == null) return null;
    if (value is! Map<String, dynamic> ||
        value.length != 4 ||
        !value.containsKey('last_failure')) {
      throw const FormatException('Invalid incoming recording status');
    }
    int count(String key) {
      final count = value[key];
      if (count is! int || count < 0 || count > 64) {
        throw const FormatException('Invalid incoming recording count');
      }
      return count;
    }

    final starting = count('starting');
    final active = count('active');
    final finishing = count('finishing');
    if (starting + active + finishing > 64) {
      throw const FormatException('Incoming recording count exceeds limit');
    }
    IncomingRecordingFailure? failure;
    final rawFailure = value['last_failure'];
    if (rawFailure != null) {
      if (rawFailure is! Map<String, dynamic> ||
          rawFailure.length != 3 ||
          rawFailure['display'] is! int ||
          rawFailure['display'] < 0 ||
          rawFailure['camera'] is! bool ||
          !const ['start', 'write', 'finish'].contains(rawFailure['stage'])) {
        throw const FormatException('Invalid incoming recording failure');
      }
      failure = IncomingRecordingFailure(
          rawFailure['display'], rawFailure['camera'], rawFailure['stage']);
    }
    return IncomingRecordingStatus(starting, active, finishing, failure);
  }
}
