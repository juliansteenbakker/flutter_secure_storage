import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage_legacy_migration/flutter_secure_storage_legacy_migration.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const storageChannel = MethodChannel(
    'plugins.it_nomads.com/flutter_secure_storage',
  );
  const migrationChannel = MethodChannel(
    'plugins.it_nomads.com/flutter_secure_storage_legacy_migration',
  );
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(
    () {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
    },
  );

  tearDown(
    () {
      debugDefaultTargetPlatformOverride = null;
      messenger.setMockMethodCallHandler(
        storageChannel,
        null,
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        null,
      );
    },
  );

  test(
    "uses native verification when the inspector excludes biometric user keys ending in BACKUP",
    () async {
      final methods = <String>[];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          "state": "unknown",
          "reason": "authenticationRequired",
          "entryCount": 1,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          methods.add(
            call.method,
          );
          if (call.method == "hasPendingMigration") {
            return true;
          }
          if (call.method == "getSelectedEntryCount" || call.method == "migrate") {
            return 2;
          }
          return null;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions.biometric(),
        ),
        isTrue,
      );
      expect(
        methods.last,
        "completeMigration",
      );
    },
  );

  test(
    "migrates native legacy keys even when the inspector reports an empty store",
    () async {
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {"state": "ok", "reason": "none", "entryCount": 0},
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "hasPendingMigration") {
            return true;
          }
          if (call.method == "getSelectedEntryCount" || call.method == "migrate") {
            return 1;
          }
          return null;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        isTrue,
      );
    },
  );

  test(
    "skips Jetpack entries belonging only to another prefix",
    () async {
      final methods = <String>[];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          "state": "legacyDataUnreadable",
          "reason": "legacyBackendPresent",
          "entryCount": 1,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          methods.add(
            call.method,
          );
          return false;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions(
            preferencesKeyPrefix: "selected",
          ),
        ),
        isFalse,
      );
      expect(
        methods,
        ["hasPendingMigration"],
      );
    },
  );

  test(
    "migrates the selected Jetpack prefix despite a file-wide inspector count",
    () async {
      var inspections = 0;
      final methods = <String>[];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async {
          inspections++;
          if (inspections == 1) {
            return {
              "state": "legacyDataUnreadable",
              "reason": "legacyBackendPresent",
              "entryCount": 2,
            };
          }
          return {"state": "ok", "reason": "none", "entryCount": 1};
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          methods.add(
            call.method,
          );
          if (call.method == "hasPendingMigration") {
            return true;
          }
          if (call.method == "getSelectedEntryCount" || call.method == "migrate") {
            return 1;
          }
          return null;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions(
            preferencesKeyPrefix: "selected",
          ),
        ),
        isTrue,
      );
      expect(
        methods,
        contains("completeMigration"),
      );
    },
  );

  test(
    "resumes pending biometric cleanup despite the inspector probing the saved cipher",
    () async {
      var inspections = 0;
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async {
          inspections++;
          if (inspections == 1) {
            return {"state": "legacyDataUnreadable", "reason": "decryptFailed", "entryCount": 1};
          }
          return {"state": "unknown", "reason": "authenticationRequired", "entryCount": 1};
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "hasPendingMigration") {
            return true;
          }
          if (call.method == "getSelectedEntryCount" || call.method == "migrate") {
            return 1;
          }
          return null;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions.biometric(),
        ),
        isTrue,
      );
    },
  );

  test(
    "skips healthy authentication-protected storage without prompting",
    () async {
      final methods = <String>[];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          "state": "unknown",
          "reason": "authenticationRequired",
          "entryCount": 2,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "getSelectedEntryCount") {
            return 2;
          }

          methods.add(
            call.method,
          );
          return false;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions.biometric(),
        ),
        isFalse,
      );
      expect(
        methods,
        ["hasPendingMigration"],
      );
    },
  );

  test(
    "accepts authenticated native verification for pending biometric migration",
    () async {
      final methods = <String>[];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          "state": "unknown",
          "reason": "authenticationRequired",
          "entryCount": 2,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "getSelectedEntryCount") {
            return 2;
          }

          methods.add(
            call.method,
          );
          if (call.method == "hasPendingMigration") {
            return true;
          }
          if (call.method == "migrate") {
            return 2;
          }
          return null;
        },
      );
      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions.biometric(),
        ),
        isTrue,
      );
      expect(
        methods,
        ["hasPendingMigration", "migrate", "completeMigration"],
      );
    },
  );

  for (final options in [const AndroidOptions(), const AndroidOptions.biometric()]) {
    test(
      "retains originals when postcheck cannot verify target ${options.toMap()["keyCipherAlgorithm"]}",
      () async {
        var checks = 0;
        final methods = <String>[];
        messenger.setMockMethodCallHandler(
          storageChannel,
          (MethodCall call) async {
            checks++;
            if (checks == 1) {
              return {"state": "legacyDataUnreadable", "reason": "removedCipher", "entryCount": 2};
            }
            final String reason;
            if (options.toMap()["keyCipherAlgorithm"] == "AES_GCM_NoPadding") {
              reason = "none";
            } else {
              reason = "authenticationRequired";
            }
            return {"state": "unknown", "reason": reason, "entryCount": 2};
          },
        );
        messenger.setMockMethodCallHandler(
          migrationChannel,
          (MethodCall call) async {
            if (call.method == "hasPendingMigration") {
              return true;
            }

            if (call.method == "getSelectedEntryCount") {
              return 2;
            }

            methods.add(
              call.method,
            );
            return 2;
          },
        );
        await expectLater(
          FlutterSecureStorageLegacyMigration.migrateIfNeeded(
            options: options,
          ),
          throwsStateError,
        );
        expect(
          methods,
          ["migrate"],
        );
      },
    );
  }

  test(
    "authentication cancellation preserves pending migration",
    () async {
      final methods = <String>[];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          "state": "unknown",
          "reason": "authenticationRequired",
          "entryCount": 2,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "getSelectedEntryCount") {
            return 2;
          }

          methods.add(
            call.method,
          );
          if (call.method == "hasPendingMigration") {
            return true;
          }
          throw PlatformException(
            code: "migration_failed",
            message: "Authentication cancelled",
          );
        },
      );
      await expectLater(
        FlutterSecureStorageLegacyMigration.migrateIfNeeded(
          options: const AndroidOptions.biometric(),
        ),
        throwsA(
          isA<PlatformException>(),
        ),
      );
      expect(
        methods,
        ["hasPendingMigration", "migrate"],
      );
    },
  );

  test(
    'does not invoke the legacy reader for readable storage',
    () async {
      var migrationCalls = 0;
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          'state': 'ok',
          'reason': 'none',
          'entryCount': 1,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (
          MethodCall call,
        ) async {
          if (call.method == "getSelectedEntryCount") {
            return 1;
          }

          if (call.method == "completeMigration") {
            return null;
          }
          if (call.method == 'hasPendingMigration') {
            return false;
          }
          migrationCalls++;
          return 1;
        },
      );

      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        isFalse,
      );
      expect(
        migrationCalls,
        0,
      );
    },
  );

  test(
    'migrates pending legacy entries even when current data is readable',
    () async {
      var migrationCalls = 0;
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          'state': 'ok',
          'reason': 'none',
          'entryCount': 2,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (
          MethodCall call,
        ) async {
          if (call.method == "getSelectedEntryCount") {
            return 2;
          }

          if (call.method == "completeMigration") {
            return null;
          }
          if (call.method == 'hasPendingMigration') {
            return true;
          }
          migrationCalls++;
          return 3;
        },
      );

      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        isTrue,
      );
      expect(
        migrationCalls,
        1,
      );
    },
  );

  test(
    'forces backup migration before version 11 reads the result',
    () async {
      var statusCalls = 0;
      Map<Object?, Object?>? migrationOptions;
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async {
          if (call.method == "completeMigration") {
            return null;
          }
          statusCalls++;
          if (statusCalls == 1) {
            return {
              'state': 'legacyDataUnreadable',
              'reason': 'removedCipher',
              'entryCount': 2,
            };
          }
          return {'state': 'ok', 'reason': 'none', 'entryCount': 2};
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (
          MethodCall call,
        ) async {
          if (call.method == "hasPendingMigration") {
            return true;
          }

          if (call.method == "getSelectedEntryCount") {
            return 2;
          }

          if (call.method == "completeMigration") {
            return null;
          }
          migrationOptions = call.arguments as Map<Object?, Object?>;
          return 2;
        },
      );

      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        isTrue,
      );
      expect(
        migrationOptions?['resetOnError'],
        'false',
      );
      expect(
        migrationOptions?['migrateWithBackup'],
        'true',
      );
      expect(
        migrationOptions?['migrateOnAlgorithmChange'],
        'true',
      );
      expect(
        statusCalls,
        2,
      );
    },
  );

  test(
    'rejects an incomplete migration',
    () async {
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async => {
          'state': 'legacyDataUnreadable',
          'reason': 'legacyBackendPresent',
          'entryCount': 2,
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "hasPendingMigration") {
            return true;
          }
          if (call.method == "getSelectedEntryCount") {
            return 2;
          }
          return 1;
        },
      );

      await expectLater(
        FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        throwsStateError,
      );
    },
  );

  test(
    'uses the Jetpack backend migration branch when needed',
    () async {
      var statusCalls = 0;
      Map<Object?, Object?>? migrationOptions;
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async {
          if (call.method == "completeMigration") {
            return null;
          }
          statusCalls++;
          if (statusCalls == 1) {
            return {
              'state': 'legacyDataUnreadable',
              'reason': 'legacyBackendPresent',
              'entryCount': 1,
            };
          }
          return {'state': 'ok', 'reason': 'none', 'entryCount': 1};
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (
          MethodCall call,
        ) async {
          if (call.method == "hasPendingMigration") {
            return true;
          }

          if (call.method == "getSelectedEntryCount") {
            return 1;
          }

          if (call.method == "completeMigration") {
            return null;
          }
          migrationOptions = call.arguments as Map<Object?, Object?>;
          return 1;
        },
      );

      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        isTrue,
      );
      expect(
        migrationOptions?['legacyBackendPresent'],
        'true',
      );
      expect(
        migrationOptions?['migrateWithBackup'],
        'false',
      );
    },
  );

  test(
    'resets secure storage only when explicitly requested',
    () async {
      String? method;
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (
          MethodCall call,
        ) async {
          if (call.method == "completeMigration") {
            return null;
          }
          method = call.method;
          return null;
        },
      );

      await FlutterSecureStorageLegacyMigration.resetStorage();

      expect(
        method,
        'resetStorage',
      );
    },
  );

  test(
    'reads selected legacy entries without invoking migration',
    () async {
      MethodCall? recoveryCall;
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (
          MethodCall call,
        ) async {
          if (call.method == "completeMigration") {
            return null;
          }
          recoveryCall = call;
          return {'auth-user-id': '42', 'api-last-sync-version': '1000'};
        },
      );

      final entries = await FlutterSecureStorageLegacyMigration.readLegacyEntries(
        ['auth-user-id', 'api-last-sync-version'],
      );

      expect(
        recoveryCall?.method,
        'readLegacyEntries',
      );
      expect(
        entries['auth-user-id'],
        '42',
      );
      expect(
        entries['api-last-sync-version'],
        '1000',
      );
    },
  );
  test(
    'recovers pending backups when the upgrade inspector sees no entries',
    () async {
      int statusCalls = 0;
      final List<String> calls = [];
      messenger.setMockMethodCallHandler(
        storageChannel,
        (MethodCall call) async {
          if (call.method == "completeMigration") {
            return null;
          }
          statusCalls++;
          return {
            'state': 'ok',
            'reason': 'none',
            'entryCount': statusCalls == 1 ? 0 : 2,
          };
        },
      );
      messenger.setMockMethodCallHandler(
        migrationChannel,
        (MethodCall call) async {
          if (call.method == "getSelectedEntryCount") {
            return 2;
          }

          if (call.method == "completeMigration") {
            return null;
          }
          calls.add(
            call.method,
          );
          if (call.method == 'hasPendingMigration') {
            return true;
          }
          return 2;
        },
      );

      expect(
        await FlutterSecureStorageLegacyMigration.migrateIfNeeded(),
        isTrue,
      );
      expect(
        calls,
        ['hasPendingMigration', 'migrate'],
      );
    },
  );
}
