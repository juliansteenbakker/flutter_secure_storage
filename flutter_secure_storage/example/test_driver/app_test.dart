import 'package:flutter_driver/flutter_driver.dart';
import 'package:test/test.dart';

void main() {
  group('Secure Storage Example', () {
    late HomePageObject pageObject;
    late FlutterDriver driver;

    // Connect to the Flutter driver before running any tests.
    setUpAll(() async {
      driver = await FlutterDriver.connect();
      pageObject = HomePageObject(driver);

      await pageObject.deleteAll();
    });

    // Close the connection to the driver after the tests have completed.
    tearDownAll(() async {
      await pageObject.deleteAll();
      driver.close();
    });

    test(
      'basic operations',
      () async {
        await pageObject.hasNoRow(0);

        await pageObject.addRandom();
        await pageObject.hasRow(0);
        await pageObject.addRandom();
        await pageObject.hasRow(1);

        await pageObject.editRow('Row 0', 0);
        await pageObject.editRow('Row 1', 1);

        await Future.delayed(const Duration(seconds: 3));

        await pageObject.rowHasTitle('Row 0', 0);
        await pageObject.rowHasTitle('Row 1', 1);

        await Future.delayed(const Duration(seconds: 3));

        await pageObject.deleteRow(1);
        await pageObject.hasNoRow(1);

        await Future.delayed(const Duration(seconds: 3));

        await pageObject.rowHasTitle('Row 0', 0);
        await pageObject.deleteRow(0);
        await pageObject.hasNoRow(0);

        await Future.delayed(const Duration(seconds: 1));

        await pageObject.isProtectedDataAvailable();
      },
      timeout: const Timeout(Duration(seconds: 120)),
    );
  });
}

class HomePageObject {
  HomePageObject(this.driver);

  final FlutterDriver driver;
  final _addRandomButtonFinder = find.byValueKey('add_random');
  final _deleteAllButtonFinder = find.byValueKey('delete_all');
  final _popUpMenuButtonFinder = find.byValueKey('popup_menu');
  final _isProtectedDataAvailableButtonFinder =
      find.byValueKey('is_protected_data_available');

  Future deleteAll() async {
    await driver.tap(_popUpMenuButtonFinder);
    await driver.tap(_deleteAllButtonFinder);
  }

  Future addRandom() async {
    await driver.tap(_addRandomButtonFinder);
  }

  Future editRow(String title, int index) async {
    await driver.tap(find.byValueKey('popup_row_$index'));
    await driver.tap(find.byValueKey('edit_row_$index'));

    await driver.tap(find.byValueKey('title_field'));
    await driver.enterText(title);
    await driver.tap(find.byValueKey('save'));
  }

  Future rowHasTitle(String title, int index) async {
    expect(await driver.getText(find.byValueKey('title_row_$index')), title);
  }

  Future hasRow(int index) async {
    await driver.waitFor(find.byValueKey('title_row_$index'));
  }

  Future deleteRow(int index) async {
    await driver.tap(find.byValueKey('popup_row_$index'));
    await driver.tap(find.byValueKey('delete_row_$index'));
  }

  Future hasNoRow(int index) async {
    await driver.waitForAbsent(find.byValueKey('title_row_$index'));
  }

  Future<void> isProtectedDataAvailable() async {
    await driver.tap(_popUpMenuButtonFinder);
    await driver.tap(_isProtectedDataAvailableButtonFinder);
  }
}
