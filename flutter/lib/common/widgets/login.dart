import 'package:flutter/material.dart';

import '../../common.dart';

// R-G4 / R-SV6 (§19): the ACCOUNT SIGN-IN + OIDC flow is REMOVED. A sovereign, direct-IP fork has
// NO account server (R-SV6), and the Rust account/auth module plus generic HTTP FFI are deleted, so
// the inherited login dialog (the username/password + email/2FA-code entry) is a dead, misleading
// egress surface and is excised here:
//   - loginDialog()           (the account credential dialog)
//   - verificationCodeDialog() (the email-code / account-2FA second step)
//   - logOutConfirmDialog()    (already caller-less after the logout button was removed)
//   - LoginWidgetUserPass      (the credential form widget)
// The Address Book / "Accessible devices" (group) tabs that hosted the two "Login" buttons are
// already structurally OFF (peer_tab_model.dart) — Recent/Favorites are the local, login-free peer
// lists (R-SV5). The remaining `loginDialog()` shim below renders no credential form: it states
// account login is unavailable, so a future build cannot re-expose the credential entry by flipping
// a runtime flag (R-G1: remove, don't grey).
//
// NOTE (entanglement honoured, not hidden): the abModel/userModel/groupModel subsystem itself
// (~170 refs woven through peer_card / peers_view / dialog / the gFFI struct, all live for the kept
// Recent/Favorites lists) is NOT compiled out here — that is the deferred follow-on tracked in
// HARDENING_STATUS §19. This removal is bounded to the actuating account-login UI surface.

// call this directly
Future<bool?> loginDialog() async {
  return await gFFI.dialogManager.show<bool>((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate('Login')),
      content: Text(translate('account_login_unavailable_tip')),
      actions: [
        dialogButton('Close', onPressed: () => close(false)),
      ],
      onCancel: () => close(false),
    );
  });
}
