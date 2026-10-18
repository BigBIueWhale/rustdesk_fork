import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_hbb/models/platform_model.dart';

import '../../common.dart';

/// Saves the type and publishes confirmed readback to the shared choice model.
typedef KBChosenCallback = Future<bool> Function(String);

const double _kImageMarginVertical = 6.0;
const double _kImageMarginHorizontal = 10.0;
const double _kImageBoarderWidth = 4.0;
const double _kImagePaddingWidth = 4.0;
const Color _kImageBorderColor = Color.fromARGB(125, 202, 247, 2);
const double _kBorderRadius = 6.0;
const String _kKBLayoutTypeISO = 'ISO';
const String _kKBLayoutTypeNotISO = 'Not ISO';

const _kKBLayoutImageMap = {
  _kKBLayoutTypeISO: 'kb_layout_iso',
  _kKBLayoutTypeNotISO: 'kb_layout_not_iso',
};

class _KBImage extends StatelessWidget {
  final String kbLayoutType;
  final double imageWidth;
  final RxString chosenType;
  const _KBImage({
    Key? key,
    required this.kbLayoutType,
    required this.imageWidth,
    required this.chosenType,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Obx(() {
      return Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(_kBorderRadius),
          border: Border.all(
            color: chosenType.value == kbLayoutType
                ? _kImageBorderColor
                : Colors.transparent,
            width: _kImageBoarderWidth,
          ),
        ),
        margin: EdgeInsets.symmetric(
          horizontal: _kImageMarginHorizontal,
          vertical: _kImageMarginVertical,
        ),
        padding: EdgeInsets.all(_kImagePaddingWidth),
        child: SvgPicture.asset(
          'assets/${_kKBLayoutImageMap[kbLayoutType] ?? ""}.svg',
          width: imageWidth -
              _kImageMarginHorizontal * 2 -
              _kImagePaddingWidth * 2 -
              _kImageBoarderWidth * 2,
        ),
      );
    });
  }
}

class _KBChooser extends StatelessWidget {
  final String kbLayoutType;
  final double imageWidth;
  final RxString chosenType;
  final ValueChanged<String> cb;
  final bool enabled;
  const _KBChooser({
    Key? key,
    required this.kbLayoutType,
    required this.imageWidth,
    required this.chosenType,
    required this.cb,
    required this.enabled,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    onChanged(String? v) {
      if (v != null) {
        cb(v);
      }
    }

    return Column(
      children: [
        TextButton(
          onPressed: enabled ? () => onChanged(kbLayoutType) : null,
          child: _KBImage(
            kbLayoutType: kbLayoutType,
            imageWidth: imageWidth,
            chosenType: chosenType,
          ),
          style: TextButton.styleFrom(padding: EdgeInsets.zero),
        ),
        TextButton(
          child: Row(
            children: [
              Obx(() => Radio(
                    splashRadius: 0,
                    value: kbLayoutType,
                    groupValue: chosenType.value,
                    onChanged: enabled ? onChanged : null,
                  )),
              Text(kbLayoutType),
            ],
          ),
          onPressed: enabled ? () => onChanged(kbLayoutType) : null,
        ),
      ],
    );
  }
}

class KBLayoutTypeChooser extends StatefulWidget {
  final RxString chosenType;
  final double width;
  final double height;
  final double dividerWidth;
  final KBChosenCallback cb;
  final String? failureText;
  KBLayoutTypeChooser({
    Key? key,
    required this.chosenType,
    required this.width,
    required this.height,
    required this.dividerWidth,
    required this.cb,
    this.failureText,
  }) : super(key: key);

  @override
  State<KBLayoutTypeChooser> createState() => _KBLayoutTypeChooserState();
}

class _KBLayoutTypeChooserState extends State<KBLayoutTypeChooser> {
  bool _pending = false;
  bool _failed = false;

  Future<void> _choose(String value) async {
    if (!mounted || _pending) return;
    setState(() {
      _pending = true;
      _failed = false;
    });
    var saved = false;
    try {
      saved = await widget.cb(value);
    } catch (error) {
      debugPrint('Failed to save local keyboard type: $error');
    }
    if (!mounted) return;
    setState(() {
      _pending = false;
      _failed = !saved;
    });
  }

  @override
  Widget build(BuildContext context) {
    final imageWidth = widget.width / 2 - widget.dividerWidth;
    return SizedBox(
      width: widget.width,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          SizedBox(
            height: widget.height,
            child: Center(
              child: Row(
                children: [
                  _KBChooser(
                    kbLayoutType: _kKBLayoutTypeISO,
                    imageWidth: imageWidth,
                    chosenType: widget.chosenType,
                    cb: _choose,
                    enabled: !_pending,
                  ),
                  VerticalDivider(width: widget.dividerWidth * 2),
                  _KBChooser(
                    kbLayoutType: _kKBLayoutTypeNotISO,
                    imageWidth: imageWidth,
                    chosenType: widget.chosenType,
                    cb: _choose,
                    enabled: !_pending,
                  ),
                ],
              ),
            ),
          ),
          if (_pending) const LinearProgressIndicator(),
          if (_failed)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(widget.failureText ?? translate('Failed')),
            ),
        ],
      ),
    );
  }
}

RxString KBLayoutType = ''.obs;

Future<bool> saveLocalKeyboardLayoutType(String value,
    {Future<void> Function(String)? writeType,
    String Function()? readType}) async {
  final write = writeType ??
      (value) => bind.setLocalKbLayoutType(kbLayoutType: value);
  final read = readType ?? (() => bind.getLocalKbLayoutType());
  await write(value);
  final effective = read();
  KBLayoutType.value = effective;
  return effective == value;
}

String getLocalPlatformForKBLayoutType(String peerPlatform) {
  String localPlatform = '';
  if (peerPlatform != kPeerPlatformMacOS) {
    return localPlatform;
  }

  if (isWindows) {
    localPlatform = kPeerPlatformWindows;
  } else if (isLinux) {
    localPlatform = kPeerPlatformLinux;
  } else if (isWebOnWindows || isWebOnLinux) {
    localPlatform = kPeerPlatformWebDesktop;
  }
  return localPlatform;
}

showKBLayoutTypeChooserIfNeeded(
  String peerPlatform,
  OverlayDialogManager dialogManager,
) async {
  final localPlatform = getLocalPlatformForKBLayoutType(peerPlatform);
  if (localPlatform == '') {
    return;
  }
  KBLayoutType.value = bind.getLocalKbLayoutType();
  if (KBLayoutType.value == _kKBLayoutTypeISO ||
      KBLayoutType.value == _kKBLayoutTypeNotISO) {
    return;
  }
  showKBLayoutTypeChooser(localPlatform, dialogManager);
}

showKBLayoutTypeChooser(
  String localPlatform,
  OverlayDialogManager dialogManager,
) {
  dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title:
          Text('${translate('Select local keyboard type')} ($localPlatform)'),
      content: KBLayoutTypeChooser(
          chosenType: KBLayoutType,
          width: 360,
          height: 200,
          dividerWidth: 4.0,
          cb: saveLocalKeyboardLayoutType),
      actions: [dialogButton('Close', onPressed: close)],
      onCancel: close,
    );
  });
}
