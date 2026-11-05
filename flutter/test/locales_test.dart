import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/locales.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

Widget _app() => MaterialApp(
      supportedLocales: supportedLocales,
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      home: Scaffold(body: Builder(builder: (context) {
        return Text(MaterialLocalizations.of(context).cancelButtonLabel,
            key: const ValueKey('cancel-label'));
      })),
    );

void _expectLocale(WidgetTester tester, String language, String label,
    {TextDirection direction = TextDirection.ltr}) {
  final context = tester.element(find.byKey(const ValueKey('cancel-label')));
  expect(Localizations.localeOf(context).languageCode, language);
  expect(MaterialLocalizations.of(context), isA<GlobalMaterialLocalizations>());
  expect(CupertinoLocalizations.of(context), isNot(isA<DefaultCupertinoLocalizations>()));
  expect(Directionality.of(context), direction);
  expect(find.text(label), findsOneWidget);
  expect(tester.takeException(), isNull);
}

Widget _getApp(String configured) {
  final resolveLocale = appLocaleResolver(configured);
  return GetMaterialApp(
      supportedLocales: supportedLocales,
      locale: resolveLocale(null, supportedLocales),
      localeListResolutionCallback: resolveLocale,
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      builder: localizedAppBuilder((context, child) {
        expectSync(Directionality.of(context),
            WidgetsLocalizations.of(context).textDirection);
        return child!;
      }),
      home: Scaffold(body: Builder(builder: (context) {
        return Text(MaterialLocalizations.of(context).cancelButtonLabel,
            key: const ValueKey('cancel-label'));
      })),
    );
}

void _testGetLocale(String name, Future<void> Function(WidgetTester) body) {
  testWidgets(name, (tester) async {
    Get.testMode = true;
    try {
      await body(tester);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pumpAndSettle();
      Get.reset();
      tester.binding.platformDispatcher.clearLocalesTestValue();
    }
  });
}

void main() {
  _testGetLocale('configured locale overrides platform at startup', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('en', 'US')];
    await tester.pumpWidget(_getApp('he'));
    await tester.pumpAndSettle();
    _expectLocale(tester, 'he', 'ביטול', direction: TextDirection.rtl);
  });

  _testGetLocale('configured locale changes preserve navigator ownership', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('en', 'US')];
    await tester.pumpWidget(_getApp('en'));
    await tester.pumpAndSettle();
    final navigator = tester.state<NavigatorState>(find.byType(Navigator));
    final element = tester.element(find.byKey(const ValueKey('cancel-label')));
    for (final sample in <(String, String, TextDirection)>[
      ('he', 'ביטול', TextDirection.rtl),
      ('ar', 'الإلغاء', TextDirection.rtl),
      ('fr', 'Annuler', TextDirection.ltr),
      ('en', 'Cancel', TextDirection.ltr),
    ]) {
      await tester.pumpWidget(_getApp(sample.$1));
      await tester.pumpAndSettle();
      _expectLocale(tester, sample.$1, sample.$2, direction: sample.$3);
      expect(tester.state<NavigatorState>(find.byType(Navigator)), same(navigator));
      expect(tester.element(find.byKey(const ValueKey('cancel-label'))), same(element));
    }
  });

  _testGetLocale('automatic locale resumes live system selection', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('vi', 'VN')];
    await tester.pumpWidget(_getApp('he'));
    await tester.pumpAndSettle();
    _expectLocale(tester, 'he', 'ביטול', direction: TextDirection.rtl);
    await tester.pumpWidget(_getApp(''));
    await tester.pumpAndSettle();
    _expectLocale(tester, 'vi', 'Huỷ');
    tester.binding.platformDispatcher.localesTestValue = [const Locale('he', 'IL')];
    await tester.pumpAndSettle();
    _expectLocale(tester, 'he', 'ביטול', direction: TextDirection.rtl);
    tester.binding.platformDispatcher.localesTestValue = [const Locale('en', 'US')];
    await tester.pumpAndSettle();
    _expectLocale(tester, 'en', 'Cancel');
  });

  _testGetLocale('configured catalogue aliases resolve framework locales', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('he', 'IL')];
    for (final sample in <(String, Locale)>[
      ('kz', const Locale('kk')),
      ('ge', const Locale('ka')),
      ('br', const Locale('pt')),
      ('pt', const Locale('pt')),
      ('pt-pt', const Locale('pt', 'PT')),
      ('zh-cn', const Locale('zh', 'CN')),
      ('zh-tw', const Locale('zh', 'TW')),
      ('HE', const Locale('he')),
    ]) {
      await tester.pumpWidget(_getApp(sample.$1));
      await tester.pumpAndSettle();
      final context = tester.element(find.byKey(const ValueKey('cancel-label')));
      expect(Localizations.localeOf(context), sample.$2);
      expect(MaterialLocalizations.of(context), isA<GlobalMaterialLocalizations>());
      expect(tester.takeException(), isNull);
    }
  });

  _testGetLocale('unsupported configured languages use framework English', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('he', 'IL')];
    for (final configured in ['eo', 'sc', 'zz', 'he_IL', 'kk', 'ka']) {
      await tester.pumpWidget(_getApp(configured));
      await tester.pumpAndSettle();
      _expectLocale(tester, 'en', 'Cancel');
    }
  });

  _testGetLocale('all supported framework locales load their delegates', (tester) async {
    for (final locale in supportedLocales) {
      tester.binding.platformDispatcher.localesTestValue = [locale];
      await tester.pumpWidget(_getApp(''));
      await tester.pumpAndSettle();
      final context = tester.element(find.byKey(const ValueKey('cancel-label')));
      expect(Localizations.localeOf(context), locale);
      expect(MaterialLocalizations.of(context), isA<GlobalMaterialLocalizations>());
      expect(CupertinoLocalizations.of(context), isNot(isA<DefaultCupertinoLocalizations>()));
      expect(Directionality.of(context), WidgetsLocalizations.of(context).textDirection);
      expect(tester.takeException(), isNull);
    }
  });

  for (final sample in <(String, Locale, String, String)>[
    ('Kazakh language', const Locale('kk'), 'kk', 'Бас тарту'),
    ('Kazakh region', const Locale('kk', 'KZ'), 'kk', 'Бас тарту'),
    ('Vietnamese language', const Locale('vi'), 'vi', 'Huỷ'),
    ('Vietnamese region', const Locale('vi', 'VN'), 'vi', 'Huỷ'),
    ('English', const Locale('en', 'US'), 'en', 'Cancel'),
    ('French', const Locale('fr', 'FR'), 'fr', 'Annuler'),
    ('unsupported language', const Locale('zz', 'ZZ'), 'en', 'Cancel'),
  ]) {
    testWidgets('framework locale resolves ${sample.$1}', (tester) async {
      tester.binding.platformDispatcher.localesTestValue = [sample.$2];
      addTearDown(tester.binding.platformDispatcher.clearLocalesTestValue);
      await tester.pumpWidget(_app());
      await tester.pumpAndSettle();
      _expectLocale(tester, sample.$3, sample.$4);
    });
  }

  testWidgets('framework locale preserves Hebrew direction', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('he', 'IL')];
    addTearDown(tester.binding.platformDispatcher.clearLocalesTestValue);
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    _expectLocale(tester, 'he', 'ביטול', direction: TextDirection.rtl);
  });

  testWidgets('framework locale selects a supported later preference', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [
      const Locale('zz', 'ZZ'), const Locale('vi', 'VN'),
    ];
    addTearDown(tester.binding.platformDispatcher.clearLocalesTestValue);
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    _expectLocale(tester, 'vi', 'Huỷ');
  });

  testWidgets('framework locale follows live system changes', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('en', 'US')];
    addTearDown(tester.binding.platformDispatcher.clearLocalesTestValue);
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    _expectLocale(tester, 'en', 'Cancel');
    for (final sample in <(Locale, String, String)>[
      (const Locale('kk', 'KZ'), 'kk', 'Бас тарту'),
      (const Locale('vi', 'VN'), 'vi', 'Huỷ'),
      (const Locale('pt', 'PT'), 'pt', 'Cancelar'),
      (const Locale('pt', 'BR'), 'pt', 'Cancelar'),
      (const Locale('en', 'US'), 'en', 'Cancel'),
    ]) {
      tester.binding.platformDispatcher.localesTestValue = [sample.$1];
      await tester.pumpAndSettle();
      _expectLocale(tester, sample.$2, sample.$3);
      if (sample.$1.languageCode == 'pt') {
        final context = tester.element(find.byKey(const ValueKey('cancel-label')));
        expect(Localizations.localeOf(context).countryCode,
            sample.$1.countryCode == 'PT' ? 'PT' : isNull);
      }
    }
  });
}
