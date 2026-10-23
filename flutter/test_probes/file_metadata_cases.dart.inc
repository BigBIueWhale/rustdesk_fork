Entry metadataEntry(int seconds, {String name = 'file', int kind = 4}) {
  return Entry.fromJson(jsonDecode(jsonEncode({
    'entry_type': kind,
    'modified_time': seconds,
    'name': name,
    'size': 17,
  })) as Map<String, dynamic>);
}

void main() {
  const limit = 8640000000000;
  const wrap = 0x2000000000000000;
  const ordinary = {
    0: '1970-01-01 00:00:00',
    1: '1970-01-01 00:00:01',
    -1: '1969-12-31 23:59:59',
    1700000000: '2023-11-14 22:13:20',
    -2147483648: '1901-12-13 20:45:52',
    2147483647: '2038-01-19 03:14:07',
    limit: '275760-09-13 00:00:00',
    -limit: '-271821-04-20 00:00:00',
  };
  for (final entry in ordinary.entries) {
    test('ordinary timestamp ${entry.key} keeps its date', () {
      expect(DateTime.now().timeZoneOffset, Duration.zero);
      final value = metadataEntry(entry.key);
      expect(value.lastModifiedText(), entry.value);
      expect(value.modifiedTime, entry.key);
      expect(fileMetadataRowText(value), '${entry.value}   ');
    });
  }
  for (final seconds in [limit + 1, -limit - 1, wrap, -wrap]) {
    test('unsupported timestamp $seconds is unavailable without data loss', () {
      final value = metadataEntry(seconds);
      expect(value.lastModifiedText(), '—');
      expect(value.modifiedTime, seconds);
      expect(fileMetadataRowText(value), '—   ');
    });
  }
  test('drive row retains its blank timestamp', () {
    final drive = metadataEntry(wrap, kind: 3);
    expect(fileMetadataRowText(drive), ' ');
    expect(drive.modifiedTime, wrap);
  });
  test('timestamp rendering preserves the remaining entry fields', () {
    for (final seconds in [0, limit, limit + 1, wrap]) {
      final entry = metadataEntry(seconds, name: '目录-é');
      expect(entry.entryType, 4);
      expect(entry.name, '目录-é');
      expect(entry.size, 17);
      expect(entry.modifiedTime, seconds);
      expect(entry.isFile, isTrue);
    }
  });
  for (final ascending in [false, true]) {
    test('modified ordering uses raw seconds ascending=$ascending', () {
      List<Entry> values(List<int> seconds) => [
            for (var i = 0; i < seconds.length; i++)
              metadataEntry(seconds[i], name: 'entry-$i')
          ];
      final ordinary = values([0, -1, 1]);
      final normal = _sortList(ordinary, SortBy.modified, ascending);
      expect(normal.map((entry) => entry.modifiedTime).toList(),
          ascending ? [1, 0, -1] : [-1, 0, 1]);
      final input = values([0, wrap, -wrap, limit + 1, 1700000000]);
      final expected = [wrap, limit + 1, 1700000000, 0, -wrap];
      final result = _sortList(input, SortBy.modified, ascending);
      expect(result.map((entry) => entry.modifiedTime).toList(),
          ascending ? expected : expected.reversed.toList());
      expect(result.map((entry) => entry.name).toSet(),
          {'entry-0', 'entry-1', 'entry-2', 'entry-3', 'entry-4'});
    });
  }
}
