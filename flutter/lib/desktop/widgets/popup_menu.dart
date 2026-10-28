import 'dart:core';

import 'package:flutter/material.dart';
import 'package:get/get.dart';

import '../../common.dart';
import './material_mod_popup_menu.dart' as mod_menu;

class MenuConfig {
  // adapt to the screen height
  static const fontSize = 14.0;
  static const iconScale = 0.8;

  final double height;
  final double dividerHeight;
  final double? boxWidth;
  final Color commonColor;

  const MenuConfig(
      {required this.commonColor,
      this.height = kMinInteractiveDimension,
      this.dividerHeight = 16.0,
      this.boxWidth});
}

typedef DismissCallback = Function();

abstract class MenuEntryBase<T> {
  bool dismissOnClicked;
  DismissCallback? dismissCallback;
  RxBool? enabled;

  MenuEntryBase({
    this.dismissOnClicked = false,
    this.enabled,
    this.dismissCallback,
  });
  List<mod_menu.PopupMenuEntry<T>> build(BuildContext context, MenuConfig conf);

  enabledStyle(BuildContext context) => TextStyle(
      color: Theme.of(context).textTheme.titleLarge?.color,
      fontSize: MenuConfig.fontSize,
      fontWeight: FontWeight.normal);
  disabledStyle() => TextStyle(
      color: Colors.grey,
      fontSize: MenuConfig.fontSize,
      fontWeight: FontWeight.normal);
}

class MenuEntryDivider<T> extends MenuEntryBase<T> {
  @override
  List<mod_menu.PopupMenuEntry<T>> build(
      BuildContext context, MenuConfig conf) {
    return [
      mod_menu.PopupMenuDivider(
        height: conf.dividerHeight,
      )
    ];
  }
}

enum SwitchType {
  sswitch,
  scheckbox,
}

typedef SwitchGetter = Future<bool> Function();
typedef SwitchSetter = Future<void> Function(bool);

abstract class MenuEntrySwitchBase<T> extends MenuEntryBase<T> {
  final SwitchType switchType;
  final String text;
  final EdgeInsets? padding;
  Rx<TextStyle>? textStyle;

  MenuEntrySwitchBase({
    required this.switchType,
    required this.text,
    required dismissOnClicked,
    this.textStyle,
    this.padding,
    RxBool? enabled,
    dismissCallback,
  }) : super(
          dismissOnClicked: dismissOnClicked,
          enabled: enabled,
          dismissCallback: dismissCallback,
        );

  bool get isEnabled => enabled?.value ?? true;

  RxBool get curOption;
  Future<void> setOption(bool? option);

  tryPop(BuildContext context) {
    if (dismissOnClicked && Navigator.canPop(context)) {
      Navigator.pop(context);
      super.dismissCallback?.call();
    }
  }

  @override
  List<mod_menu.PopupMenuEntry<T>> build(
      BuildContext context, MenuConfig conf) {
    textStyle ??= TextStyle(
            color: Theme.of(context).textTheme.titleLarge?.color,
            fontSize: MenuConfig.fontSize,
            fontWeight: FontWeight.normal)
        .obs;
    return [
      mod_menu.PopupMenuItem(
        padding: EdgeInsets.zero,
        height: conf.height,
        child: Container(
            width: conf.boxWidth,
            child: TextButton(
              child: Container(
                  padding: padding,
                  alignment: AlignmentDirectional.centerStart,
                  height: conf.height,
                  child: Row(children: [
                    Obx(() => Text(
                          text,
                          style: textStyle!.value,
                        )),
                    Expanded(
                        child: Align(
                      alignment: Alignment.centerRight,
                      child: Transform.scale(
                          scale: MenuConfig.iconScale,
                          child: Obx(() {
                            if (switchType == SwitchType.sswitch) {
                              return Switch(
                                value: curOption.value,
                                onChanged: isEnabled
                                    ? (v) {
                                        tryPop(context);
                                        setOption(v);
                                      }
                                    : null,
                              );
                            } else {
                              return Checkbox(
                                value: curOption.value,
                                onChanged: isEnabled
                                    ? (v) {
                                        tryPop(context);
                                        setOption(v);
                                      }
                                    : null,
                              );
                            }
                          })),
                    ))
                  ])),
              onPressed: isEnabled
                  ? () {
                      tryPop(context);
                      setOption(!curOption.value);
                    }
                  : null,
            )),
      )
    ];
  }
}

class MenuEntrySwitch<T> extends MenuEntrySwitchBase<T> {
  final SwitchGetter getter;
  final SwitchSetter setter;
  final RxBool _curOption = false.obs;

  MenuEntrySwitch({
    required SwitchType switchType,
    required String text,
    required this.getter,
    required this.setter,
    Rx<TextStyle>? textStyle,
    EdgeInsets? padding,
    dismissOnClicked = false,
    RxBool? enabled,
    dismissCallback,
  }) : super(
          switchType: switchType,
          text: text,
          textStyle: textStyle,
          padding: padding,
          dismissOnClicked: dismissOnClicked,
          enabled: enabled,
          dismissCallback: dismissCallback,
        ) {
    () async {
      _curOption.value = await getter();
    }();
  }

  @override
  RxBool get curOption => _curOption;
  @override
  setOption(bool? option) async {
    if (option != null) {
      await setter(option);
      final opt = await getter();
      if (_curOption.value != opt) {
        _curOption.value = opt;
      }
    }
  }
}

// Compatible with MenuEntrySwitch, it uses value instead of getter
class MenuEntrySwitchSync<T> extends MenuEntrySwitchBase<T> {
  final SwitchSetter setter;
  final RxBool _curOption = false.obs;

  MenuEntrySwitchSync({
    required SwitchType switchType,
    required String text,
    required bool currentValue,
    required this.setter,
    Rx<TextStyle>? textStyle,
    EdgeInsets? padding,
    dismissOnClicked = false,
    RxBool? enabled,
    dismissCallback,
  }) : super(
          switchType: switchType,
          text: text,
          textStyle: textStyle,
          padding: padding,
          dismissOnClicked: dismissOnClicked,
          enabled: enabled,
          dismissCallback: dismissCallback,
        ) {
    _curOption.value = currentValue;
  }

  @override
  RxBool get curOption => _curOption;
  @override
  setOption(bool? option) async {
    if (option != null) {
      await setter(option);
      // Notice: no ensure with getter, best used on menus that are destroyed on click
      if (_curOption.value != option) {
        _curOption.value = option;
      }
    }
  }
}

class MenuEntryButton<T> extends MenuEntryBase<T> {
  final Widget Function(TextStyle? style) childBuilder;
  Function() proc;
  final EdgeInsets? padding;

  MenuEntryButton({
    required this.childBuilder,
    required this.proc,
    this.padding,
    dismissOnClicked = false,
    RxBool? enabled,
    dismissCallback,
  }) : super(
          dismissOnClicked: dismissOnClicked,
          enabled: enabled,
          dismissCallback: dismissCallback,
        );

  Widget _buildChild(BuildContext context, MenuConfig conf) {
    super.enabled ??= true.obs;
    return Obx(() => Container(
        width: conf.boxWidth,
        child: TextButton(
          onPressed: super.enabled!.value
              ? () {
                  if (super.dismissOnClicked && Navigator.canPop(context)) {
                    Navigator.pop(context);
                    if (super.dismissCallback != null) {
                      super.dismissCallback!();
                    }
                  }
                  proc();
                }
              : null,
          child: Container(
            padding: padding,
            alignment: AlignmentDirectional.centerStart,
            constraints:
                BoxConstraints(minHeight: conf.height, maxHeight: conf.height),
            child: childBuilder(
                super.enabled!.value ? enabledStyle(context) : disabledStyle()),
          ),
        )));
  }

  @override
  List<mod_menu.PopupMenuEntry<T>> build(
      BuildContext context, MenuConfig conf) {
    return [
      mod_menu.PopupMenuItem(
        padding: EdgeInsets.zero,
        height: conf.height,
        child: _buildChild(context, conf),
      )
    ];
  }
}

class CustomPopupMenuTheme {
  static const Color commonColor = MyTheme.accent;
  // kMinInteractiveDimension
  static const double height = 20.0;
  static const double dividerHeight = 3.0;
}
