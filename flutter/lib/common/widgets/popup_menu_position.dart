import 'package:flutter/material.dart';

RelativeRect popupMenuPosition(BuildContext context, Offset globalPosition) {
  return RelativeRect.fromLTRB(globalPosition.dx, globalPosition.dy,
      globalPosition.dx, globalPosition.dy);
}
