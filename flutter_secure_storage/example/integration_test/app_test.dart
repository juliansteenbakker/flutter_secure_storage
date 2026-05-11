// Some tests intentionally construct AndroidOptions with deprecated cipher
// algorithms to verify migration paths from legacy to current defaults.
// ignore_for_file: deprecated_member_use

import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_secure_storage_example/main.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Secure Storage Tests', () {
    testWidgets(
      'Android: deleteAll() must not clear other '
      'sharedPreferencesName namespace (regression #1023)',
      (WidgetTester tester) async {
        // This is a plugin-level regression test for:
        // https://github.com/juliansteenbakker/flutter_secure_storage/issues/1023
        //
        // The Android implementation must isolate namespaces created via
        // AndroidOptions.sharedPreferencesName. A deleteAll() issued against
        // one
        // namespace must not delete keys stored in another namespace.
        final pageObject = await _setupHomePage(tester);

        // Use the app's popup menu path to ensure the plugin is initialized and
        // stable before we run the direct namespace assertions below.
        await pageObject.deleteAll();

        const storageA = FlutterSecureStorage(
          aOptions: AndroidOptions(storageNamespace: 'namespace_a'),
        );
        const storageB = FlutterSecureStorage(
          aOptions: AndroidOptions(storageNamespace: 'namespace_b'),
        );

        const key = 'it_android_namespace_key';
        const valueA = 'value_a';
        const valueB = 'value_b';

        // Arrange
        await storageA.write(key: key, value: valueA);
        await storageB.write(key: key, value: valueB);

        // Act
        await storageB.deleteAll();

        // Assert
        final readA = await storageA.read(key: key);
        expect(
          readA,
          equals(valueA),
          reason: 'Deleting keys from namespace_b must not affect namespace_a',
        );
      },
      skip: !Platform.isAndroid,
    );

    testWidgets(
      'Android: namespaces with different cipher algorithms must not interfere '
      '(full storageNamespace isolation)',
      (WidgetTester tester) async {
        // This test verifies that storageNamespace provides full isolation:
        // data prefs, config markers, KeyStore aliases, and key storage.
        // Different namespaces can safely use different cipher algorithms
        // without conflicting KeyStore entries or wrapped keys.
        final pageObject = await _setupHomePage(tester);
        await pageObject.deleteAll();

        // Use different algorithms per namespace to test full isolation
        const storageA = FlutterSecureStorage(
          aOptions: AndroidOptions(
            storageNamespace: 'namespace_alg_a',
            keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
            storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
          ),
        );
        // storageB uses default algorithms (OAEP/GCM) — distinct from storageA
        const storageB = FlutterSecureStorage(
          aOptions: AndroidOptions(storageNamespace: 'namespace_alg_b'),
        );

        const key = 'it_android_algorithm_isolation_key';
        const valueA = 'value_algorithm_a';
        const valueB = 'value_algorithm_b';

        // Arrange: Write values to both namespaces with different algorithms
        await storageA.write(key: key, value: valueA);
        await storageB.write(key: key, value: valueB);

        // Verify both can read their own values
        expect(await storageA.read(key: key), equals(valueA));
        expect(await storageB.read(key: key), equals(valueB));

        // Act: Force re-initialization by reading again (triggers config
        // marker checks). This simulates what happens when switching between
        // namespaces.
        final readA2 = await storageA.read(key: key);
        final readB2 = await storageB.read(key: key);

        // Assert: Both namespaces should still read their correct values.
        // With full storageNamespace isolation, each namespace has its own
        // KeyStore aliases and key storage, so different algorithms cannot
        // interfere.
        expect(
          readA2,
          equals(valueA),
          reason: 'Namespace A must read its value correctly even after '
              'namespace B initializes with different algorithms',
        );
        expect(
          readB2,
          equals(valueB),
          reason: 'Namespace B must read its value correctly even after '
              'namespace A initializes with different algorithms',
        );

        // Additional verification: Write new values and read back
        const newValueA = 'updated_value_a';
        const newValueB = 'updated_value_b';
        await storageA.write(key: key, value: newValueA);
        await storageB.write(key: key, value: newValueB);

        expect(await storageA.read(key: key), equals(newValueA));
        expect(await storageB.read(key: key), equals(newValueB));
      },
      skip: !Platform.isAndroid,
    );

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

    testWidgets('Enclave requested on iOS Simulator falls back gracefully',
        skip: !(Platform.isIOS &&
            Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      const key = 'it_enclave_sim_fallback_key';
      const value = 'sim_fallback_secret';

      // Write with enclave requested
      // ignore: undefined_named_parameter
      await storage.write(
        key: key,
        value: value,
        iOptions: const IOSOptions(useSecureEnclave: true),
      );

      // Read should succeed due to fallback
      // ignore: undefined_named_parameter
      final readBack = await storage.read(
        key: key,
        iOptions: const IOSOptions(useSecureEnclave: true),
      );
      expect(readBack, value);

      // Delete should also succeed
      // ignore: undefined_named_parameter
      await storage.delete(
        key: key,
        iOptions: const IOSOptions(useSecureEnclave: true),
      );
      final afterDelete = await storage.read(
        key: key,
        iOptions: const IOSOptions(useSecureEnclave: true),
      );
      expect(afterDelete, isNull);
    });

    testWidgets(
        'iOS device: baseline (useSecureEnclave=false) write/read/delete',
        skip: !(Platform.isIOS &&
            !Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      const key = 'it_enclave_device_baseline_key';
      const value = 'device_baseline_secret';

      await storage.write(
        key: key,
        value: value,
        iOptions: IOSOptions.defaultOptions,
      );

      final readBack = await storage.read(
        key: key,
        iOptions: IOSOptions.defaultOptions,
      );
      expect(readBack, value);

      await storage.delete(
        key: key,
        iOptions: IOSOptions.defaultOptions,
      );
      final afterDelete = await storage.read(
        key: key,
        iOptions: IOSOptions.defaultOptions,
      );
      expect(afterDelete, isNull);
    });

    testWidgets(
        'iOS device: useSecureEnclave=true with non-prompting access control (applicationPassword) write/read/delete',
        skip: !(Platform.isIOS &&
            !Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      const key = 'it_enclave_device_enabled_key';
      const value = 'device_enclave_secret';

      await storage.write(
        key: key,
        value: value,
        // Use a non-prompting flag to make test automation stable.
        // ignore: undefined_named_parameter
        iOptions: const IOSOptions(
          useSecureEnclave: true,
          accessControlFlags: [AccessControlFlag.applicationPassword],
        ),
      );

      final readBack = await storage.read(
        key: key,
        iOptions: const IOSOptions(
          useSecureEnclave: true,
          accessControlFlags: [AccessControlFlag.applicationPassword],
        ),
      );
      expect(readBack, value);

      await storage.delete(
        key: key,
        iOptions: const IOSOptions(
          useSecureEnclave: true,
          accessControlFlags: [AccessControlFlag.applicationPassword],
        ),
      );
      final afterDelete = await storage.read(
        key: key,
        iOptions: const IOSOptions(
          useSecureEnclave: true,
          accessControlFlags: [AccessControlFlag.applicationPassword],
        ),
      );
      expect(afterDelete, isNull);
    });

    // Note: On real devices, Secure Enclave will prompt for device
    // passcode/biometrics. Enter your device passcode when prompted - it should
    // only prompt once per test run due to LAContext reuse (30 second window).
    testWidgets('iOS device: readAll with Secure Enclave items',
        skip: !(Platform.isIOS &&
            !Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      // Use default userPresence (no applicationPassword) - should work with
      // device passcode
      const enclaveOptions = IOSOptions(
        useSecureEnclave: true,
        // accessControlFlags defaults to userPresence which works with device
        // passcode
      );

      // Write multiple Secure Enclave items
      await storage.write(
        key: 'enclave_key1',
        value: 'enclave_value1',
        iOptions: enclaveOptions,
      );
      await storage.write(
        key: 'enclave_key2',
        value: 'enclave_value2',
        iOptions: enclaveOptions,
      );
      await storage.write(
        key: 'enclave_key3',
        value: 'enclave_value3',
        iOptions: enclaveOptions,
      );

      // Read all items
      final allItems = await storage.readAll(iOptions: enclaveOptions);

      // Verify all items are returned
      expect(allItems, isNotNull);
      final items = allItems;
      expect(items.length, greaterThanOrEqualTo(3));
      expect(items['enclave_key1'], 'enclave_value1');
      expect(items['enclave_key2'], 'enclave_value2');
      expect(items['enclave_key3'], 'enclave_value3');

      // Cleanup
      await storage.delete(key: 'enclave_key1', iOptions: enclaveOptions);
      await storage.delete(key: 'enclave_key2', iOptions: enclaveOptions);
      await storage.delete(key: 'enclave_key3', iOptions: enclaveOptions);
    });

    testWidgets(
        'iOS device: readAll with mixed Secure Enclave and standard items',
        skip: !(Platform.isIOS &&
            !Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      // Use default userPresence - should work with device passcode
      const enclaveOptions = IOSOptions(
        useSecureEnclave: true,
      );
      const standardOptions = IOSOptions.defaultOptions;

      // Write Secure Enclave item
      await storage.write(
        key: 'mixed_enclave_key',
        value: 'enclave_value',
        iOptions: enclaveOptions,
      );

      // Write standard item
      await storage.write(
        key: 'mixed_standard_key',
        value: 'standard_value',
        iOptions: standardOptions,
      );

      // Read all with Secure Enclave enabled - should return both
      final allItems = await storage.readAll(iOptions: enclaveOptions);

      // Verify both items are returned
      expect(allItems, isNotNull);
      final items = allItems;
      expect(items.containsKey('mixed_enclave_key'), isTrue);
      expect(items['mixed_enclave_key'], 'enclave_value');
      expect(items.containsKey('mixed_standard_key'), isTrue);
      expect(items['mixed_standard_key'], 'standard_value');

      // Cleanup
      await storage.delete(key: 'mixed_enclave_key', iOptions: enclaveOptions);
      await storage.delete(
        key: 'mixed_standard_key',
        iOptions: standardOptions,
      );
    });

    // Android Algorithm Migration Tests
    testWidgets(
      'Android: migrates single value from RSA_PKCS1/AES_CBC to OAEP/GCM',
      skip: !Platform.isAndroid,
      (WidgetTester tester) async {
        const legacyOptions = AndroidOptions(
          keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
          storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
          migrateOnAlgorithmChange: false,
        );

        // newOptions uses all defaults (OAEP/GCM + migrateOnAlgorithmChange: true)
        const legacyStorage = FlutterSecureStorage(aOptions: legacyOptions);
        const newStorage = FlutterSecureStorage();

        await legacyStorage.deleteAll(aOptions: legacyOptions);
        await legacyStorage.write(
          key: 'migrate_single_key',
          value: 'migrate_single_value',
          aOptions: legacyOptions,
        );

        final value = await newStorage.read(key: 'migrate_single_key');
        expect(value, 'migrate_single_value');

        await newStorage.deleteAll();
      },
    );

    testWidgets(
      'Android: migrates multiple values from RSA_PKCS1/AES_CBC to OAEP/GCM',
      skip: !Platform.isAndroid,
      (WidgetTester tester) async {
        const legacyOptions = AndroidOptions(
          keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
          storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
          migrateOnAlgorithmChange: false,
        );

        // newStorage uses all defaults (OAEP/GCM + migrateOnAlgorithmChange: true)
        const legacyStorage = FlutterSecureStorage(aOptions: legacyOptions);
        const newStorage = FlutterSecureStorage();

        await legacyStorage.deleteAll(aOptions: legacyOptions);

        final entries = {
          'migrate_key_1': 'migrate_value_1',
          'migrate_key_2': 'migrate_value_2',
          'migrate_key_3': 'migrate_value_3',
        };

        for (final entry in entries.entries) {
          await legacyStorage.write(
            key: entry.key,
            value: entry.value,
            aOptions: legacyOptions,
          );
        }

        for (final entry in entries.entries) {
          final value = await newStorage.read(key: entry.key);
          expect(
            value,
            entry.value,
            reason: 'Key ${entry.key} was not migrated correctly',
          );
        }

        await newStorage.deleteAll();
      },
    );

    testWidgets(
      'Android: data remains readable without migration when algorithms '
      'unchanged',
      skip: !Platform.isAndroid,
      (WidgetTester tester) async {
        // Uses all defaults (OAEP/GCM + migrateOnAlgorithmChange: true)
        const storage = FlutterSecureStorage();

        await storage.deleteAll();
        await storage.write(
          key: 'no_migration_key',
          value: 'no_migration_value',
        );

        // Read back with same options — no migration should occur
        final value = await storage.read(key: 'no_migration_key');
        expect(value, 'no_migration_value');

        await storage.deleteAll();
      },
    );

    testWidgets(
      'Android: migrateOnAlgorithmChange false skips migration',
      skip: !Platform.isAndroid,
      (WidgetTester tester) async {
        const legacyOptions = AndroidOptions(
          keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
          storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
          migrateOnAlgorithmChange: false,
          resetOnError: false,
        );
        // OAEP/GCM (defaults) but explicitly no migration, no reset
        const newOptionsNoMigrate = AndroidOptions(
          migrateOnAlgorithmChange: false,
          resetOnError: false,
        );

        const legacyStorage = FlutterSecureStorage(aOptions: legacyOptions);

        await legacyStorage.deleteAll(aOptions: legacyOptions);
        await legacyStorage.write(
          key: 'no_migrate_key',
          value: 'no_migrate_value',
          aOptions: legacyOptions,
        );

        // Reading with a different algorithm and no migration should throw or
        // return null — either is acceptable, the key point is it does NOT
        // silently return the correct plaintext.
        try {
          final value = await const FlutterSecureStorage().read(
            key: 'no_migrate_key',
            aOptions: newOptionsNoMigrate,
          );
          expect(value, isNot('no_migrate_value'));
        } on Object catch (_) {
          // Throwing is also acceptable — data is unreadable without migration
        }

        await legacyStorage.deleteAll(aOptions: legacyOptions);
      },
    );

    testWidgets(
      'Android: migrateWithBackup migrates data from RSA_PKCS1/AES_CBC to '
      'OAEP/GCM',
      skip: !Platform.isAndroid,
      (WidgetTester tester) async {
        const legacyOptions = AndroidOptions(
          keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
          storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
          migrateOnAlgorithmChange: false,
        );
        // Default algorithms (OAEP/GCM) with backup-protected migration
        const backupStorage = FlutterSecureStorage(
          aOptions: AndroidOptions(migrateWithBackup: true),
        );
        const legacyStorage = FlutterSecureStorage(aOptions: legacyOptions);

        await legacyStorage.deleteAll(aOptions: legacyOptions);
        await legacyStorage.write(
          key: 'backup_migrate_key',
          value: 'backup_migrate_value',
          aOptions: legacyOptions,
        );

        final value = await backupStorage.read(key: 'backup_migrate_key');
        expect(value, 'backup_migrate_value');

        await backupStorage.deleteAll();
      },
    );

    testWidgets(
        'iOS device: item written without SE returns null when read with SE',
        skip: !(Platform.isIOS &&
            !Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      const key = 'it_se_existing_data_key';
      const value = 'existing_value';

      // Write without Secure Enclave (standard Keychain).
      await storage.write(
        key: key,
        value: value,
        iOptions: IOSOptions.defaultOptions,
      );

      // Reading the same key with useSecureEnclave=true should return null
      // because no SE-wrapped companion key exists for this item.
      final readWithSE = await storage.read(
        key: key,
        iOptions: const IOSOptions(useSecureEnclave: true),
      );
      expect(readWithSE, isNull);

      // The original item is still accessible via the standard path.
      final readWithoutSE = await storage.read(
        key: key,
        iOptions: IOSOptions.defaultOptions,
      );
      expect(readWithoutSE, value);

      // Cleanup.
      await storage.delete(key: key, iOptions: IOSOptions.defaultOptions);
    });

    testWidgets('iOS device: deleteAll with Secure Enclave items',
        skip: !(Platform.isIOS &&
            !Platform.environment.containsKey('SIMULATOR_DEVICE_NAME')),
        (WidgetTester tester) async {
      const storage = FlutterSecureStorage();
      // Use default userPresence - should work with device passcode
      const enclaveOptions = IOSOptions(
        useSecureEnclave: true,
      );

      // Write multiple Secure Enclave items
      await storage.write(
        key: 'delete_all_key1',
        value: 'value1',
        iOptions: enclaveOptions,
      );
      await storage.write(
        key: 'delete_all_key2',
        value: 'value2',
        iOptions: enclaveOptions,
      );

      // Verify items exist
      final beforeDelete = await storage.readAll(iOptions: enclaveOptions);
      expect(beforeDelete, isNotNull);
      final beforeItems = beforeDelete;
      expect(beforeItems.containsKey('delete_all_key1'), isTrue);
      expect(beforeItems.containsKey('delete_all_key2'), isTrue);

      // Delete all items
      await storage.deleteAll(iOptions: enclaveOptions);

      // Verify all items are deleted (including wrapped keys)
      final afterDelete = await storage.readAll(iOptions: enclaveOptions);
      expect(afterDelete.isEmpty, isTrue);
      expect(
        await storage.read(key: 'delete_all_key1', iOptions: enclaveOptions),
        isNull,
      );
      expect(
        await storage.read(key: 'delete_all_key2', iOptions: enclaveOptions),
        isNull,
      );
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

    await Future<void>.delayed(const Duration(seconds: 1));
    await tester.pumpAndSettle(duration);
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
