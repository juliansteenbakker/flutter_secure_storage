import 'package:flutter/material.dart';
import 'package:flutter_secure_storage_example/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('Secure Storage Example', (WidgetTester tester) async {
    await tester.pumpWidget(const MaterialApp(home: ItemsWidget()));
    await tester.pumpAndSettle();

    final HomePageObject pageObject = HomePageObject(tester);

    await pageObject.deleteAll();
    pageObject.hasNoRow(0);

    await pageObject.addRandom();
    await Future.delayed(const Duration(seconds: 3));
    pageObject.hasRow(0);
    await pageObject.addRandom();
    await Future.delayed(const Duration(seconds: 3));
    pageObject.hasRow(1);

    await pageObject.editRow('Row 0', 0);
    await Future.delayed(const Duration(seconds: 3));
    await pageObject.editRow('Row 1', 1);

    await Future.delayed(const Duration(seconds: 3));

    pageObject.rowHasTitle('Row 0', 0);
    await Future.delayed(const Duration(seconds: 3));
    pageObject.rowHasTitle('Row 1', 1);

    await Future.delayed(const Duration(seconds: 3));

    await pageObject.deleteRow(1);
    await Future.delayed(const Duration(seconds: 3));
    pageObject.hasNoRow(1);

    await Future.delayed(const Duration(seconds: 3));

    pageObject.rowHasTitle('Row 0', 0);
    await Future.delayed(const Duration(seconds: 3));
    await pageObject.deleteRow(0);
    await Future.delayed(const Duration(seconds: 3));
    pageObject.hasNoRow(0);

    await Future.delayed(const Duration(seconds: 1));

    await pageObject.isProtectedDataAvailable();

    await pageObject.deleteAll();
  });
}

class HomePageObject {
  HomePageObject(this.tester);

  final WidgetTester tester;
  final Finder _addRandomButtonFinder = find.byKey(const Key('add_random'));
  final Finder _deleteAllButtonFinder = find.byKey(const Key('delete_all'));
  final Finder _popUpMenuButtonFinder = find.byKey(const Key('popup_menu'));
  final Finder _isProtectedDataAvailableButtonFinder =
      find.byKey(const Key('is_protected_data_available'));

  Future<void> deleteAll() async {
    expect(_popUpMenuButtonFinder, findsOneWidget);
    await tester.tap(_popUpMenuButtonFinder);
    await tester.pumpAndSettle();

    expect(_deleteAllButtonFinder, findsOneWidget);
    await tester.tap(_deleteAllButtonFinder);
    await tester.pumpAndSettle();
  }

  Future<void> addRandom() async {
    expect(_addRandomButtonFinder, findsOneWidget);
    await tester.tap(_addRandomButtonFinder);
    await tester.pumpAndSettle();
  }

  Future<void> editRow(String title, int index) async {
    final Finder popupRow = find.byKey(Key('popup_row_$index'));
    expect(popupRow, findsOneWidget);
    await tester.tap(popupRow);
    await tester.pumpAndSettle();

    final Finder editRow = find.byKey(Key('edit_row_$index'));
    expect(editRow, findsOneWidget);
    await tester.tap(editRow);
    await tester.pumpAndSettle();

    final Finder textFieldFinder = find.byKey(const Key('title_field'));
    expect(textFieldFinder, findsOneWidget);
    await tester.tap(textFieldFinder);
    await tester.pumpAndSettle();

    await tester.enterText(textFieldFinder, title);
    await tester.pumpAndSettle();

    final Finder saveButtonFinder = find.byKey(const Key('save'));
    expect(saveButtonFinder, findsOneWidget);
    await tester.tap(saveButtonFinder);
    await tester.pumpAndSettle();
  }

  void rowHasTitle(String title, int index) {
    final Finder titleRow = find.byKey(Key('title_row_$index'));
    expect(titleRow, findsOneWidget);
    expect((titleRow.evaluate().single.widget as Text).data, equals(title));
  }

  void hasRow(int index) {
    expect(find.byKey(Key('title_row_$index')), findsOneWidget);
  }

  Future<void> deleteRow(int index) async {
    final Finder popupRow = find.byKey(Key('popup_row_$index'));
    expect(popupRow, findsOneWidget);
    await tester.tap(popupRow);
    await tester.pumpAndSettle();

    final Finder deleteRow = find.byKey(Key('delete_row_$index'));
    expect(deleteRow, findsOneWidget);
    await tester.tap(deleteRow);
    await tester.pumpAndSettle();
  }

  void hasNoRow(int index) {
    expect(find.byKey(Key('title_row_$index')), findsNothing);
  }

  Future<void> isProtectedDataAvailable() async {
    expect(_popUpMenuButtonFinder, findsOneWidget);
    await tester.tap(_popUpMenuButtonFinder);
    await tester.pumpAndSettle();

    expect(_isProtectedDataAvailableButtonFinder, findsOneWidget);
    await tester.tap(_isProtectedDataAvailableButtonFinder);
    await tester.pumpAndSettle();
  }
}
