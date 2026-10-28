import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class DraggableDivider extends StatefulWidget {
  final Axis axis;
  final double thickness;
  final Color color;
  /// Change in the preceding pane's extent, following the layout direction.
  final Function(double)? onPointerMove;
  final VoidCallback? onHover;
  final EdgeInsets padding;
  const DraggableDivider({
    super.key,
    this.axis = Axis.horizontal,
    this.thickness = 1.0,
    this.color = const Color.fromARGB(200, 177, 175, 175),
    this.onPointerMove,
    this.padding = const EdgeInsets.symmetric(horizontal: 1.0),
    this.onHover,
  });

  @override
  State<DraggableDivider> createState() => _DraggableDividerState();
}

class _DraggableDividerState extends State<DraggableDivider> {
  bool _showFocus = false;

  @override
  Widget build(BuildContext context) {
    final direction = widget.axis == Axis.vertical
        ? Directionality.of(context) : TextDirection.ltr;
    final enabled = widget.onPointerMove != null;
    final forward = direction == TextDirection.rtl ? -8.0 : 8.0;
    final divider = GestureDetector(
      key: ValueKey(direction),
      behavior: HitTestBehavior.opaque,
      dragStartBehavior: DragStartBehavior.down,
      excludeFromSemantics: true,
      supportedDevices: const {
        PointerDeviceKind.mouse,
        PointerDeviceKind.touch,
        PointerDeviceKind.stylus,
        PointerDeviceKind.invertedStylus,
      },
      onHorizontalDragUpdate:
          widget.axis == Axis.vertical && widget.onPointerMove != null
              ? (event) => widget.onPointerMove?.call(
                  direction == TextDirection.rtl ? -event.delta.dx : event.delta.dx)
              : null,
      onVerticalDragUpdate:
          widget.axis == Axis.horizontal && widget.onPointerMove != null
              ? (event) => widget.onPointerMove?.call(event.delta.dy)
              : null,
      child: MouseRegion(
        onHover: (event) => widget.onHover?.call(),
        cursor: widget.onPointerMove == null
            ? SystemMouseCursors.basic
            : widget.axis == Axis.vertical
                ? SystemMouseCursors.resizeLeftRight
                : SystemMouseCursors.resizeUpDown,
        child: Padding(
          padding: widget.padding,
          child: Container(
            decoration: BoxDecoration(
                color: enabled && _showFocus
                    ? Theme.of(context).focusColor : widget.color),
            width: widget.axis == Axis.horizontal
                ? double.infinity
                : widget.thickness,
            height: widget.axis == Axis.horizontal
                ? widget.thickness
                : double.infinity,
          ),
        ),
      ),
    );
    return CallbackShortcuts(
      bindings: {
        if (enabled && widget.axis == Axis.vertical) ...{
          const SingleActivator(LogicalKeyboardKey.arrowRight):
              () => widget.onPointerMove?.call(forward),
          const SingleActivator(LogicalKeyboardKey.arrowLeft):
              () => widget.onPointerMove?.call(-forward),
        },
        if (enabled && widget.axis == Axis.horizontal) ...{
          const SingleActivator(LogicalKeyboardKey.arrowDown):
              () => widget.onPointerMove?.call(8),
          const SingleActivator(LogicalKeyboardKey.arrowUp):
              () => widget.onPointerMove?.call(-8),
        },
      },
      child: FocusableActionDetector(
        enabled: enabled,
        onShowFocusHighlight: (show) {
          if (mounted && _showFocus != show) {
            setState(() => _showFocus = show);
          }
        },
        child: divider,
      ),
    );
  }
}
