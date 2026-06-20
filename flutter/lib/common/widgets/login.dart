import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/user_model.dart';
import 'package:get/get.dart';

import '../../common.dart';
import './dialog.dart';

class LoginWidgetUserPass extends StatelessWidget {
  final TextEditingController username;
  final TextEditingController pass;
  final String? usernameMsg;
  final String? passMsg;
  final bool isInProgress;
  final RxString curOP;
  final Function() onLogin;
  final FocusNode? userFocusNode;
  const LoginWidgetUserPass({
    Key? key,
    this.userFocusNode,
    required this.username,
    required this.pass,
    required this.usernameMsg,
    required this.passMsg,
    required this.isInProgress,
    required this.curOP,
    required this.onLogin,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Padding(
        padding: EdgeInsets.all(0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const SizedBox(height: 8.0),
            DialogTextField(
                title: translate(DialogTextField.kUsernameTitle),
                controller: username,
                focusNode: userFocusNode,
                prefixIcon: DialogTextField.kUsernameIcon,
                errorText: usernameMsg),
            PasswordWidget(
              controller: pass,
              autoFocus: false,
              reRequestFocus: true,
              errorText: passMsg,
            ),
            // NOT use Offstage to wrap LinearProgressIndicator
            if (isInProgress) const LinearProgressIndicator(),
            const SizedBox(height: 12.0),
            FittedBox(
                child:
                    Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              Container(
                height: 38,
                width: 200,
                child: Obx(() => ElevatedButton(
                      child: Text(
                        translate('Login'),
                        style: TextStyle(fontSize: 16),
                      ),
                      onPressed:
                          curOP.value.isEmpty || curOP.value == 'rustdesk'
                              ? () {
                                  onLogin();
                                }
                              : null,
                    )),
              ),
            ])),
          ],
        ));
  }
}

// call this directly
Future<bool?> loginDialog() async {
  var username =
      TextEditingController(text: UserModel.getLocalUserInfo()?['name'] ?? '');
  var password = TextEditingController();
  final userFocusNode = FocusNode()..requestFocus();
  Timer(Duration(milliseconds: 100), () => userFocusNode..requestFocus());

  String? usernameMsg;
  String? passwordMsg;
  var isInProgress = false;
  final RxString curOP = ''.obs;
  // Track hover state for the close icon
  bool isCloseHovered = false;

  final res = await gFFI.dialogManager.show<bool>((setState, close, context) {
    username.addListener(() {
      if (usernameMsg != null) {
        setState(() => usernameMsg = null);
      }
    });

    password.addListener(() {
      if (passwordMsg != null) {
        setState(() => passwordMsg = null);
      }
    });

    onDialogCancel() {
      isInProgress = false;
      close(false);
    }

    handleLoginResponse(LoginResponse resp, bool storeIfAccessToken,
        void Function([dynamic])? close) async {
      switch (resp.type) {
        case HttpType.kAuthResTypeToken:
          if (resp.access_token != null) {
            if (storeIfAccessToken) {
              await bind.mainSetLocalOption(
                  key: 'access_token', value: resp.access_token!);
              await bind.mainSetLocalOption(
                  key: 'user_info', value: jsonEncode(resp.user ?? {}));
            }
            if (close != null) {
              close(true);
            }
            return;
          }
          break;
        case HttpType.kAuthResTypeEmailCheck:
          bool? isEmailVerification;
          if (resp.tfa_type == null ||
              resp.tfa_type == HttpType.kAuthResTypeEmailCheck) {
            isEmailVerification = true;
          } else if (resp.tfa_type == HttpType.kAuthResTypeTfaCheck) {
            isEmailVerification = false;
          } else {
            passwordMsg = "Failed, bad tfa type from server";
          }
          if (isEmailVerification != null) {
            if (isMobile) {
              if (close != null) close(null);
              verificationCodeDialog(
                  resp.user, resp.secret, isEmailVerification);
            } else {
              setState(() => isInProgress = false);
              // Workaround for web, close the dialog first, then show the verification code dialog.
              // Otherwise, the text field will keep selecting the text and we can't input the code.
              // Not sure why this happens.
              if (isWeb && close != null) close(null);
              final res = await verificationCodeDialog(
                  resp.user, resp.secret, isEmailVerification);
              if (res == true) {
                if (!isWeb && close != null) close(false);
                return;
              }
            }
          }
          break;
        default:
          passwordMsg = "Failed, bad response from server";
          break;
      }
    }

    onLogin() async {
      // validate
      if (username.text.isEmpty) {
        setState(() => usernameMsg = translate('Username missed'));
        return;
      }
      if (password.text.isEmpty) {
        setState(() => passwordMsg = translate('Password missed'));
        return;
      }
      curOP.value = 'rustdesk';
      setState(() => isInProgress = true);
      try {
        final resp = await gFFI.userModel.login(LoginRequest(
            username: username.text,
            password: password.text,
            id: await bind.mainGetMyId(),
            uuid: await bind.mainGetUuid(),
            autoLogin: true,
            type: HttpType.kAuthReqTypeAccount));
        await handleLoginResponse(resp, true, close);
      } on RequestException catch (err) {
        passwordMsg = translate(err.cause);
      } catch (err) {
        passwordMsg = "Unknown Error: $err";
      }
      curOP.value = '';
      setState(() => isInProgress = false);
    }

    final title = Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          translate('Login'),
        ).marginOnly(top: MyTheme.dialogPadding),
        MouseRegion(
          onEnter: (_) => setState(() => isCloseHovered = true),
          onExit: (_) => setState(() => isCloseHovered = false),
          child: InkWell(
            child: Icon(
              Icons.close,
              size: 25,
              // No need to handle the branch of null.
              // Because we can ensure the color is not null when debug.
              color: isCloseHovered
                  ? Colors.white
                  : Theme.of(context)
                      .textTheme
                      .titleLarge
                      ?.color
                      ?.withOpacity(0.55),
            ),
            onTap: onDialogCancel,
            hoverColor: Colors.red,
            borderRadius: BorderRadius.circular(5),
          ),
        ).marginOnly(top: 10, right: 15),
      ],
    );
    final titlePadding = EdgeInsets.fromLTRB(MyTheme.dialogPadding, 0, 0, 0);

    return CustomAlertDialog(
      title: title,
      titlePadding: titlePadding,
      contentBoxConstraints: BoxConstraints(minWidth: 400),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          const SizedBox(
            height: 8.0,
          ),
          LoginWidgetUserPass(
            username: username,
            pass: password,
            usernameMsg: usernameMsg,
            passMsg: passwordMsg,
            isInProgress: isInProgress,
            curOP: curOP,
            onLogin: onLogin,
            userFocusNode: userFocusNode,
          ),
        ],
      ),
      onCancel: onDialogCancel,
      onSubmit: onLogin,
    );
  });

  if (res != null) {
    await UserModel.updateOtherModels();
  }

  return res;
}

Future<bool?> verificationCodeDialog(
    UserPayload? user, String? secret, bool isEmailVerification) async {
  var autoLogin = true;
  var isInProgress = false;
  String? errorText;

  final code = TextEditingController();

  final res = await gFFI.dialogManager.show<bool>((setState, close, context) {
    void onVerify() async {
      setState(() => isInProgress = true);

      try {
        final resp = await gFFI.userModel.login(LoginRequest(
            verificationCode: code.text,
            tfaCode: isEmailVerification ? null : code.text,
            secret: secret,
            username: user?.name,
            id: await bind.mainGetMyId(),
            uuid: await bind.mainGetUuid(),
            autoLogin: autoLogin,
            type: HttpType.kAuthReqTypeEmailCode));

        switch (resp.type) {
          case HttpType.kAuthResTypeToken:
            if (resp.access_token != null) {
              await bind.mainSetLocalOption(
                  key: 'access_token', value: resp.access_token!);
              close(true);
              return;
            }
            break;
          default:
            errorText = "Failed, bad response from server";
            break;
        }
      } on RequestException catch (err) {
        errorText = translate(err.cause);
      } catch (err) {
        errorText = "Unknown Error: $err";
      }

      setState(() => isInProgress = false);
    }

    final codeField = isEmailVerification
        ? DialogEmailCodeField(
            controller: code,
            errorText: errorText,
            readyCallback: onVerify,
            onChanged: () => errorText = null,
          )
        : Dialog2FaField(
            controller: code,
            errorText: errorText,
            readyCallback: onVerify,
            onChanged: () => errorText = null,
          );

    getOnSubmit() => codeField.isReady ? onVerify : null;

    return CustomAlertDialog(
        title: Text(translate("Verification code")),
        contentBoxConstraints: BoxConstraints(maxWidth: 300),
        content: Column(
          children: [
            Offstage(
                offstage: !isEmailVerification || user?.email == null,
                child: TextField(
                  decoration: InputDecoration(
                      labelText: "Email", prefixIcon: Icon(Icons.email)),
                  readOnly: true,
                  controller: TextEditingController(text: user?.email),
                ).workaroundFreezeLinuxMint()),
            isEmailVerification ? const SizedBox(height: 8) : const Offstage(),
            codeField,
            /*
            CheckboxListTile(
              contentPadding: const EdgeInsets.all(0),
              dense: true,
              controlAffinity: ListTileControlAffinity.leading,
              title: Row(children: [
                Expanded(child: Text(translate("Trust this device")))
              ]),
              value: trustThisDevice,
              onChanged: (v) {
                if (v == null) return;
                setState(() => trustThisDevice = !trustThisDevice);
              },
            ),
            */
            // NOT use Offstage to wrap LinearProgressIndicator
            if (isInProgress) const LinearProgressIndicator(),
          ],
        ),
        onCancel: close,
        onSubmit: getOnSubmit(),
        actions: [
          dialogButton("Cancel", onPressed: close, isOutline: true),
          dialogButton("Verify", onPressed: getOnSubmit()),
        ]);
  });
  // For verification code, desktop update other models in login dialog, mobile need to close login dialog first,
  // otherwise the soft keyboard will jump out on each key press, so mobile update in verification code dialog.
  if (isMobile && res == true) {
    await UserModel.updateOtherModels();
  }

  return res;
}

void logOutConfirmDialog() {
  gFFI.dialogManager.show((setState, close, context) {
    submit() {
      close();
      gFFI.userModel.logOut();
    }

    return CustomAlertDialog(
      content: Text(translate("logout_tip")),
      actions: [
        dialogButton(translate("Cancel"), onPressed: close, isOutline: true),
        dialogButton(translate("OK"), onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}
