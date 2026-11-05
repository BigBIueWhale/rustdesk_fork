import 'dart:io';

final presentationTraceEnabled_ =
    Platform.environment['RUSTDESK_PRESENTATION_TRACE'] == '1';

final isAndroid_ = Platform.isAndroid;
final isIOS_ = Platform.isIOS;
final isWindows_ = Platform.isWindows;
final isMacOS_ = Platform.isMacOS;
final isLinux_ = Platform.isLinux;
final isWeb_ = false;
final isWebDesktop_ = false;

final isDesktop_ = Platform.isWindows || Platform.isMacOS || Platform.isLinux;

String get screenInfo_ => '';

final isWebOnWindows_ = false;
final isWebOnLinux_ = false;
final isWebOnMacOS_ = false;
