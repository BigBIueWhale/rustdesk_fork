String formatFileModifiedTime(int seconds) {
  // Check seconds before multiplication: native Dart integer overflow wraps.
  const maxDateTimeSeconds = 8640000000000;
  if (seconds < -maxDateTimeSeconds || seconds > maxDateTimeSeconds) {
    return '—';
  }
  return DateTime.fromMillisecondsSinceEpoch(seconds * 1000)
      .toString()
      .replaceAll('.000', '');
}
