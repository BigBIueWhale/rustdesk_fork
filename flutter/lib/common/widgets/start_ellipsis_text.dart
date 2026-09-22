import 'package:characters/characters.dart';
import 'package:flutter/material.dart';

/// A single-line label that retains the end of [text] when space is limited.
///
/// File names and paths usually carry their distinguishing information at the
/// end. Flutter's built-in ellipsis retains the start instead, so this widget
/// measures complete grapheme clusters and prefixes the longest fitting suffix
/// with an ellipsis. Assistive technology still receives the complete text.
class StartEllipsisText extends StatelessWidget {
  const StartEllipsisText(
    this.text, {
    super.key,
    this.style,
  });

  final String text;
  final TextStyle? style;

  @override
  Widget build(BuildContext context) {
    final defaultStyle = DefaultTextStyle.of(context).style;
    final effectiveStyle = style == null || style!.inherit
        ? defaultStyle.merge(style)
        : style!;
    final textDirection = Directionality.of(context);
    final textScaler = MediaQuery.textScalerOf(context);
    final locale = Localizations.maybeLocaleOf(context);

    return LayoutBuilder(
      builder: (context, constraints) {
        final visibleText = constraints.hasBoundedWidth
            ? _fitSuffix(
                text,
                constraints.maxWidth,
                effectiveStyle,
                textDirection,
                textScaler,
                locale,
              )
            : text;
        return Text(
          visibleText,
          style: style,
          maxLines: 1,
          softWrap: false,
          overflow: TextOverflow.clip,
          semanticsLabel: text,
        );
      },
    );
  }
}

String _fitSuffix(
  String text,
  double maxWidth,
  TextStyle style,
  TextDirection textDirection,
  TextScaler textScaler,
  Locale? locale,
) {
  if (text.isEmpty || maxWidth <= 0) {
    return text.isEmpty ? text : '';
  }

  final painter = TextPainter(
    textDirection: textDirection,
    textScaler: textScaler,
    locale: locale,
    maxLines: 1,
  );
  try {
    bool fits(String candidate) {
      painter.text = TextSpan(text: candidate, style: style);
      painter.layout();
      return painter.width <= maxWidth;
    }

    if (fits(text)) {
      return text;
    }

    const ellipsis = '…';
    if (!fits(ellipsis)) {
      return '';
    }

    final clusters = text.characters.toList(growable: false);
    var low = 0;
    var high = clusters.length;
    while (low < high) {
      final count = (low + high + 1) ~/ 2;
      final candidate =
          ellipsis + clusters.sublist(clusters.length - count).join();
      if (fits(candidate)) {
        low = count;
      } else {
        high = count - 1;
      }
    }
    return ellipsis + clusters.sublist(clusters.length - low).join();
  } finally {
    painter.dispose();
  }
}
