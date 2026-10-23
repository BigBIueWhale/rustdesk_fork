String formatFileModifiedTime(int seconds) {
  return DateTime.fromMillisecondsSinceEpoch(seconds * 1000)
      .toString()
      .replaceAll('.000', '');
}
