import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/locales.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

Widget _app() => GetMaterialApp(
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
  expect((MaterialLocalizations.of(context) as GlobalMaterialLocalizations)
      .localeName.split('_').first, language);
  expect(CupertinoLocalizations.of(context), isNot(isA<DefaultCupertinoLocalizations>()));
  expect(Directionality.of(context), direction);
  expect(find.text(label), findsOneWidget);
  expect(tester.takeException(), isNull);
}

void main() {
  tearDown(() => Get.reset());

  for (final sample in <(String, Locale, String, String)>[
    ('Kazakh language', const Locale('kk'), 'kk', 'Бас тарту'),
    ('Kazakh region', const Locale('kk', 'KZ'), 'kk', 'Бас тарту'),
    ('Vietnamese language', const Locale('vi'), 'vi', 'Hủy'),
    ('Vietnamese region', const Locale('vi', 'VN'), 'vi', 'Hủy'),
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
    _expectLocale(tester, 'vi', 'Hủy');
  });

  testWidgets('framework locale follows live system changes', (tester) async {
    tester.binding.platformDispatcher.localesTestValue = [const Locale('en', 'US')];
    addTearDown(tester.binding.platformDispatcher.clearLocalesTestValue);
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    _expectLocale(tester, 'en', 'Cancel');
    for (final sample in <(Locale, String, String)>[
      (const Locale('kk', 'KZ'), 'kk', 'Бас тарту'),
      (const Locale('vi', 'VN'), 'vi', 'Hủy'),
      (const Locale('en', 'US'), 'en', 'Cancel'),
    ]) {
      tester.binding.platformDispatcher.localesTestValue = [sample.$1];
      await tester.pumpAndSettle();
      _expectLocale(tester, sample.$2, sample.$3);
    }
  });
}
