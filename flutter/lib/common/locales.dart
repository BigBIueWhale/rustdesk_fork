import 'package:flutter/widgets.dart';

List<Locale> supportedLocales = const [
  Locale('en', 'US'),
  Locale('zh', 'CN'),
  Locale('zh', 'TW'),
  Locale('zh', 'SG'),
  Locale('fr'),
  Locale('de'),
  Locale('it'),
  Locale('ja'),
  Locale('cs'),
  Locale('pl'),
  Locale('ko'),
  Locale('hu'),
  Locale('pt'),
  Locale('pt', 'PT'),
  Locale('ru'),
  Locale('sk'),
  Locale('id'),
  Locale('da'),
  Locale('tr'),
  Locale('kk'),
  Locale('es'),
  Locale('nl'),
  Locale('nb'),
  Locale('et'),
  Locale('eu'),
  Locale('bg'),
  Locale('be'),
  Locale('vi'),
  Locale('uk'),
  Locale('fa'),
  Locale('ca'),
  Locale('el'),
  Locale('sv'),
  Locale('sq'),
  Locale('sr'),
  Locale('th'),
  Locale('sl'),
  Locale('ro'),
  Locale('lt'),
  Locale('lv'),
  Locale('ar'),
  Locale('he'),
  Locale('hr'),
  Locale('fi'),
  Locale('ka'),
  Locale('gu'),
  Locale('hi'),
  Locale('ml'),
  Locale('ta'),
];

Locale _resolveAppLocale(String configured, List<Locale>? preferred,
    Iterable<Locale> supported) {
  if (configured.isEmpty) return basicLocaleListResolution(preferred, supported);
  final key = configured.toLowerCase();
  final locale = switch (key) {
    'kz' => const Locale('kk'),
    'ge' => const Locale('ka'),
    'br' || 'pt' => const Locale('pt'),
    'pt-pt' => const Locale('pt', 'PT'),
    'zh-cn' => const Locale('zh', 'CN'),
    'zh-tw' => const Locale('zh', 'TW'),
    'en' || 'it' || 'fr' || 'de' || 'nl' || 'nb' || 'es' || 'et' ||
    'eu' || 'hu' || 'bg' || 'be' || 'ru' || 'sk' || 'id' || 'cs' ||
    'da' || 'tr' || 'vi' || 'pl' || 'ja' || 'ko' || 'uk' || 'fa' ||
    'ca' || 'el' || 'sv' || 'sq' || 'sr' || 'th' || 'sl' || 'ro' ||
    'lt' || 'lv' || 'ar' || 'he' || 'hr' || 'ta' || 'fi' || 'ml' ||
    'hi' || 'gu' => Locale(key),
    // Esperanto and Sardinian catalogues have no Flutter framework delegate.
    _ => const Locale('en', 'US'),
  };
  return basicLocaleListResolution([locale], supported);
}

LocaleListResolutionCallback appLocaleResolver(String configured) {
  // GetMaterialApp retains its initial explicit locale. Resolve the current
  // preference against the platform list instead of that cached argument.
  return (_, supported) => _resolveAppLocale(configured,
      WidgetsBinding.instance.platformDispatcher.locales, supported);
}

TransitionBuilder localizedAppBuilder(TransitionBuilder builder) {
  return (context, child) => Directionality(
        // GetMaterialApp installs its own direction from Get.locale. The
        // framework's resolved locale owns both built-in text and direction.
        textDirection: WidgetsLocalizations.of(context).textDirection,
        child: Builder(builder: (context) => builder(context, child)),
      );
}
