import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:uuid/uuid.dart';

/// Clamp custom scale percent to supported bounds.
/// Keep this in sync with the slider's minimum in the desktop toolbar UI.
///
/// This function exists to ensure consistent clamping behavior across the app
/// and to provide a single point of reference for the valid scale range.
int clampCustomScalePercent(int percent) {
  return percent.clamp(kScaleCustomMinPercent, kScaleCustomMaxPercent);
}

/// Read the effective percentage; invalid state and missing sessions report errors.
Future<int> getSessionCustomScalePercent(UuidValue sessionId) =>
    bind.sessionGetCustomScalePercent(sessionId: sessionId);

/// Fetch and compute the custom scale factor for a session.
Future<double> getSessionCustomScale(UuidValue sessionId) async {
  final p = await getSessionCustomScalePercent(sessionId);
  return p / 100.0;
}
