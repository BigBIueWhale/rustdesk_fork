import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/common/widgets/toolbar.dart';
import 'package:get/get.dart';

import '../../common.dart';
import '../../models/platform_model.dart';

// R-G4 / R-X4 / R-G1 (§19): the mobile "ID/Relay Server" editor dialog (id/relay/api-server +
// the trust-anchor `key`, plus config import/export) was the same trust-anchor-injection surface
// as rustdesk://config — editable-but-inert under the R-S16 funnel pins + R-X4's get_key-ignores-
// override, the exact R-S12 "defaulted-off-but-present" trap R-G1 forbids. It is REMOVED, not
// greyed; its only entry point (the scan_page config-QR path) is excised with it, and the desktop
// twin was already gone. See setting_widgets.ServerConfigImportExportWidgets / common.importConfig.

void setPrivacyModeDialog(
  OverlayDialogManager dialogManager,
  List<TToggleMenu> privacyModeList,
  RxString privacyModeState,
) async {
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate('Privacy mode')),
      content: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: privacyModeList
              .map((value) => CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    visualDensity: VisualDensity.compact,
                    title: value.child,
                    value: value.value,
                    onChanged: value.onChanged,
                  ))
              .toList()),
    );
  }, backDismiss: true, clickMaskDismiss: true);
}
