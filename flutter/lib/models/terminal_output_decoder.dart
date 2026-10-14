import 'dart:convert';

/// Decodes one terminal byte stream, retaining incomplete UTF-8 between packets.
class TerminalOutputDecoder {
  final _text = StringBuffer();
  late final ByteConversionSink _sink =
      const Utf8Decoder(allowMalformed: true)
          .startChunkedConversion(_TerminalTextSink(_text));
  bool _finished = false;

  String add(List<int> bytes) {
    if (_finished) throw StateError('Terminal output stream is finished');
    _sink.add(bytes);
    return _takeText();
  }

  String finish() {
    if (_finished) return '';
    _finished = true;
    _sink.close();
    return _takeText();
  }

  String _takeText() {
    final result = _text.toString();
    _text.clear();
    return result;
  }
}

class _TerminalTextSink extends StringConversionSink {
  final StringBuffer text;

  _TerminalTextSink(this.text);

  @override
  void add(String str) => text.write(str);

  @override
  void addSlice(String str, int start, int end, bool isLast) =>
      text.write(str.substring(start, end));

  @override
  void close() {}
}
