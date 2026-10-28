import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/popup_menu_position.dart';
import 'package:flutter_hbb/desktop/widgets/material_mod_popup_menu.dart'
    as mod_menu;
import 'package:flutter_test/flutter_test.dart';

const _trigger = ValueKey('popup-trigger');
const _entry = ValueKey('popup-entry');

void main() {
  for (final custom in [true, false]) {
    for (final direction in TextDirection.values) {
      for (final layout in ['root', 'offset', 'scaled']) {
        final variant = custom ? 'custom' : 'material';
        testWidgets('popup position $variant ${direction.name} $layout',
            (tester) async {
          final scale = layout == 'scaled' ? 1.2 : 1.0;
          Future<int?>? result;
          late BuildContext menuContext;
          Widget trigger() => Builder(builder: (context) {
                menuContext = context;
                return GestureDetector(
                  key: _trigger,
                  behavior: HitTestBehavior.opaque,
                  onTapDown: (details) {
                    final position =
                        popupMenuPosition(context, details.globalPosition);
                    const constraints = BoxConstraints.tightFor(width: 160);
                    result = custom
                        ? mod_menu.showMenu<int>(
                            context: context,
                            position: position,
                            constraints: constraints,
                            items: const [
                              mod_menu.PopupMenuItem<int>(
                                key: _entry,
                                value: 7,
                                child: Text('Choose'),
                              ),
                            ],
                          )
                        : showMenu<int>(
                            context: context,
                            position: position,
                            constraints: constraints,
                            items: const [
                              PopupMenuItem<int>(
                                key: _entry,
                                value: 7,
                                child: Text('Choose'),
                              ),
                            ],
                          );
                  },
                  onTap: () {},
                  child: const SizedBox.expand(),
                );
              });

          await tester.pumpWidget(MaterialApp(
            theme: ThemeData(
              useMaterial3: false,
              platform: TargetPlatform.linux,
            ),
            builder: (context, child) =>
                Directionality(textDirection: direction, child: child!),
            home: layout == 'root'
                ? trigger()
                : Align(
                    alignment: Alignment.topLeft,
                    child: Padding(
                      padding: const EdgeInsets.only(left: 60, top: 70),
                      child: Transform.scale(
                        scale: scale,
                        alignment: Alignment.topLeft,
                        child: SizedBox(
                          width: 500,
                          height: 400,
                          child: Navigator(
                            onGenerateRoute: (_) => MaterialPageRoute<void>(
                              builder: (_) => trigger(),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
          ));
          await tester.pumpAndSettle();
          final point = tester.getTopLeft(find.byKey(_trigger)) +
              Offset(200 * scale, 120 * scale);
          await tester.tapAt(point);
          await tester.pumpAndSettle();
          expect(result, isNotNull);
          try {
            final bounds = tester.getRect(find.byKey(_entry));
            // The custom menu grows in reading order. The Material menu
            // grows into the greater space to the right of this anchor.
            final edge = custom && direction == TextDirection.rtl
                ? bounds.right
                : bounds.left;
            expect(edge, closeTo(point.dx, 0.01));
            expect(bounds.top, closeTo(point.dy + 8 * scale, 0.01));
            expect(bounds.width, closeTo(160 * scale, 0.01));
            await tester.tap(find.text('Choose'));
            await tester.pumpAndSettle();
            expect(await result, 7);
            expect(find.byKey(_entry), findsNothing);
          } finally {
            if (find.byKey(_entry).evaluate().isNotEmpty) {
              Navigator.of(menuContext).pop();
              await tester.pumpAndSettle();
              await result;
            }
          }
          expect(tester.takeException(), isNull);
        });
      }
    }
  }
}
