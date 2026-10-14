import 'dart:convert';

import 'package:flutter_hbb/models/terminal_output_decoder.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('terminal UTF-8 survives every two-packet split', () {
    const text = 'hello שלום café 中文 😀\r\n\x1b[32mgreen\x1b[0m';
    final bytes = utf8.encode(text);
    for (var split = 1; split < bytes.length; split++) {
      final decoder = TerminalOutputDecoder();
      final output = decoder.add(bytes.sublist(0, split)) +
          decoder.add(bytes.sublist(split)) +
          decoder.finish();
      expect(output, text, reason: 'split at byte $split');
    }
  });

  test('terminal UTF-8 emits complete text while retaining only a partial tail',
      () {
    final decoder = TerminalOutputDecoder();
    expect(decoder.add([0x41, 0xf0]), 'A');
    expect(decoder.add([0x9f]), '');
    expect(decoder.add([]), '');
    expect(decoder.add([0x98]), '');
    expect(decoder.add([0x80, 0x42]), '😀B');
    expect(decoder.finish(), '');
  });

  test('terminal invalid UTF-8 has the same replacement policy across packets',
      () {
    const bytes = [0xff, 0xc3, 0x28, 0x80, 0xe2, 0x82, 0xac, 0xf0, 0x9f];
    final expected = utf8.decode(bytes, allowMalformed: true);
    for (var split = 1; split < bytes.length; split++) {
      final decoder = TerminalOutputDecoder();
      expect(
        decoder.add(bytes.sublist(0, split)) +
            decoder.add(bytes.sublist(split)) +
            decoder.finish(),
        expected,
        reason: 'split at byte $split',
      );
    }
  });

  test('terminal end of stream flushes an incomplete character exactly once', () {
    final decoder = TerminalOutputDecoder();
    expect(decoder.add([0xe2, 0x82]), '');
    expect(decoder.finish(), '\uFFFD');
    expect(decoder.finish(), '');
    expect(() => decoder.add([0xac]), throwsStateError);
  });

  test('terminal decoders keep concurrent terminal byte streams separate', () {
    final first = TerminalOutputDecoder();
    final second = TerminalOutputDecoder();
    expect(first.add([0xd7]), '');
    expect(second.add([0xc3]), '');
    expect(first.add([0xa9]), 'ש');
    expect(second.add([0xa9]), 'é');
    expect(first.finish(), '');
    expect(second.finish(), '');
  });

  test('replacement terminal stream cannot complete its predecessor tail', () {
    final predecessor = TerminalOutputDecoder();
    expect(predecessor.add([0xe2, 0x82]), '');
    expect(predecessor.finish(), '\uFFFD');
    final successor = TerminalOutputDecoder();
    expect(successor.add([0xac, 0x41]), '\uFFFDA');
    expect(successor.finish(), '');
  });
}
