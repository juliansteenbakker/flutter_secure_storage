import 'package:flutter/material.dart';
import 'package:flutter_secure_storage_example/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Secure Storage Tests', () {
    testWidgets('Add a Random Row', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      pageObject.verifyRowExists(0);
    });

    testWidgets('Edit a Row Value', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.editValue('Updated Row', 0);
      pageObject.verifyValue('Updated Row', 0);
    });

    testWidgets('Delete a Row', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.deleteRow(0);
      pageObject.verifyRowDoesNotExist(0);
    });

    testWidgets('Check Protected Data Availability',
        (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.checkProtectedDataAvailability();
    });

    testWidgets('Contains Key for a Row', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.containsKeyForRow(0, expectedResult: true);
    });

    testWidgets('Read Value for a Row', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.editValue('Read Test', 0); // Ensure there's a value
      await pageObject.readValueForRow(
        0,
        expectedValue: 'Read Test',
      );
    });

    testWidgets('Add Multiple Rows and Verify', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.addRandomRow();
      pageObject
        ..verifyRowExists(0)
        ..verifyRowExists(1);
    });

    testWidgets('Edit Multiple Rows', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.addRandomRow();
      await pageObject.editValue('First Row', 0);
      await pageObject.editValue('Second Row', 1);
      pageObject
        ..verifyValue('First Row', 0)
        ..verifyValue('Second Row', 1);
    });

    testWidgets('Delete All Rows', (WidgetTester tester) async {
      final pageObject = await _setupHomePage(tester);
      await pageObject.addRandomRow();
      await pageObject.addRandomRow();
      await pageObject.deleteAll();
      pageObject
        ..verifyRowDoesNotExist(0)
        ..verifyRowDoesNotExist(1);
    });
  });
}

Duration duration = const Duration(milliseconds: 300);

Future<HomePageObject> _setupHomePage(WidgetTester tester) async {
  await tester.pumpWidget(const MaterialApp(home: HomePage()));
  await tester.pumpAndSettle(duration);
  final pageObject = HomePageObject(tester);
  await pageObject.deleteAll();
  return pageObject;
}

class HomePageObject {
  HomePageObject(this.tester);

  final WidgetTester tester;
  final Finder _addRandomButton = find.byKey(const Key('add_random'));
  final Finder _deleteAllButton = find.byKey(const Key('delete_all'));
  final Finder _popupMenuButton = find.byKey(const Key('popup_menu'));
  final Finder _protectedDataButton =
      find.byKey(const Key('is_protected_data_available'));

  Future<void> deleteAll() async {
    await _tap(_popupMenuButton);
    await _tap(_deleteAllButton);
  }

  Future<void> addRandomRow() async {
    await _tap(_addRandomButton);
  }

  Future<void> editValue(String newValue, int index) async {
    await _tap(find.byKey(Key('popup_row_$index')));
    await _tap(find.byKey(Key('edit_row_$index')));

    final textField = find.byKey(const Key('value_field'));
    expect(textField, findsOneWidget, reason: 'Value text field not found');
    await tester.enterText(textField, newValue);
    await tester.pumpAndSettle(duration);

    await _tap(find.byKey(const Key('save')));
  }

  Future<void> deleteRow(int index) async {
    await _tap(find.byKey(Key('popup_row_$index')));
    await _tap(find.byKey(Key('delete_row_$index')));
  }

  Future<void> checkProtectedDataAvailability() async {
    await _tap(_popupMenuButton);
    await _tap(_protectedDataButton);
  }

  Future<void> containsKeyForRow(
    int index, {
    required bool expectedResult,
  }) async {
    await _tap(find.byKey(Key('popup_row_$index')));
    await _tap(find.byKey(Key('contains_row_$index')));

    final keyFinder = find.byKey(Key('key_row_$index'));
    expect(keyFinder, findsOneWidget, reason: 'Row $index not found');
    final keyWidget = tester.widget<Text>(keyFinder);

    // Enter key in the dialog
    final textField = find.byKey(const Key('key_field'));
    expect(textField, findsOneWidget);
    await tester.enterText(textField, keyWidget.data!);
    await tester.pumpAndSettle(duration);

    // Confirm the action
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle(duration);

    // Verify the SnackBar message
    final expectedText = 'Contains Key: $expectedResult';
    expect(find.textContaining(expectedText), findsOneWidget);
  }

  Future<void> readValueForRow(
    int index, {
    required String expectedValue,
  }) async {
    await _tap(find.byKey(Key('popup_row_$index')));
    await _tap(find.byKey(Key('read_row_$index')));

    final keyFinder = find.byKey(Key('key_row_$index'));
    expect(keyFinder, findsOneWidget, reason: 'Row $index not found');
    final keyWidget = tester.widget<Text>(keyFinder);

    // Enter key in the dialog
    final textField = find.byKey(const Key('key_field'));
    expect(textField, findsOneWidget);
    await tester.enterText(textField, keyWidget.data!);
    await tester.pumpAndSettle(duration);

    // Confirm the action
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle(duration);

    // Verify the SnackBar message
    expect(find.text('value: $expectedValue'), findsOneWidget);
  }

  void verifyValue(String expectedValue, int index) {
    final valueFinder = find.byKey(Key('value_row_$index'));
    expect(valueFinder, findsOneWidget, reason: 'Row $index not found');
    final textWidget = tester.widget<Text>(valueFinder);
    expect(
      textWidget.data,
      equals(expectedValue),
      reason: 'Expected "$expectedValue" but found "${textWidget.data}" in row '
          '$index',
    );
  }

  void verifyRowExists(int index) {
    expect(
      find.byKey(Key('value_row_$index')),
      findsOneWidget,
      reason: 'Expected row $index to exist',
    );
  }

  void verifyRowDoesNotExist(int index) {
    expect(
      find.byKey(Key('value_row_$index')),
      findsNothing,
      reason: 'Expected row $index to be absent',
    );
  }

  Future<void> _tap(Finder finder) async {
    expect(
      finder,
      findsOneWidget,
      reason: 'Widget not found for tapping: $finder',
    );
    await tester.tap(finder);
    await tester.pumpAndSettle(duration);
  }
}
