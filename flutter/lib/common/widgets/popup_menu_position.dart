import 'package:flutter/material.dart';

RelativeRect popupMenuPosition(BuildContext context, Offset globalPosition) {
  final overlay =
      Navigator.of(context).overlay!.context.findRenderObject() as RenderBox;
  final localPosition = overlay.globalToLocal(globalPosition);
  return RelativeRect.fromSize(localPosition & Size.zero, overlay.size);
}
