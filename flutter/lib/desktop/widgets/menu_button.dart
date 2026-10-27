import 'package:flutter/material.dart';

class MenuButton extends StatelessWidget {
  final GestureTapCallback? onPressed;
  final Color color;
  final Color hoverColor;
  final Color? splashColor;
  final Widget child;
  final String? tooltip;
  final EdgeInsetsGeometry padding;
  final bool enableFeedback;
  const MenuButton({
    super.key,
    required this.onPressed,
    required this.color,
    required this.hoverColor,
    required this.child,
    this.splashColor,
    this.tooltip = "",
    this.padding = const EdgeInsets.symmetric(horizontal: 3, vertical: 6),
    this.enableFeedback = true,
  });

  @override
  Widget build(BuildContext context) {
    final borderRadius = BorderRadius.circular(8);
    return Padding(
      padding: padding,
      child: Tooltip(
        waitDuration: Duration(milliseconds: 300),
        message: tooltip,
        child: Material(
          type: MaterialType.transparency,
          child: Ink(
            decoration: BoxDecoration(
              borderRadius: borderRadius,
              color: color,
            ),
            child: InkWell(
              hoverColor: hoverColor,
              borderRadius: borderRadius,
              splashColor: splashColor,
              enableFeedback: enableFeedback,
              onTap: onPressed,
              child: Semantics(
                button: true,
                enabled: onPressed != null,
                child: child,
              ),
            ),
          ),
        ),
      ),
    );
  }
}
