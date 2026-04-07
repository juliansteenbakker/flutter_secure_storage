import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Windows-specific integration tests, ported from the Windows example app.
///
/// Covers:
///   - Basic CRUD
///   - Backward-compatibility migration (new DPAPI storage + legacy Credential
///     Store coexistence)
///   - Special-character keys and values
///
/// Run with:
///   flutter test integration_test/windows_test.dart -d windows

// ---------------------------------------------------------------------------
// Legacy Credential Store helpers
// ---------------------------------------------------------------------------
// The C++ plugin still registers itself on the
// "plugins.it_nomads.com/flutter_secure_storage" channel and handles the
// Windows Credential Store. Calling it directly lets us seed legacy data
// without going through the new FFI layer.

const _legacyChannel =
    MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

Future<void> _legacyWrite(String key, String value) =>
    _legacyChannel.invokeMethod<void>('write', {
      'key': key,
      'value': value,
      'options': <String, String>{},
    });

Future<Map<String, String>> _legacyReadAll() async {
  final raw = await _legacyChannel.invokeMethod<Map<Object?, Object?>>(
    'readAll',
    {'options': <String, String>{}},
  );
  return raw?.cast<String, String>() ?? <String, String>{};
}

Future<void> _legacyDeleteAll() =>
    _legacyChannel.invokeMethod<void>('deleteAll', {
      'options': <String, String>{},
    });

// ---------------------------------------------------------------------------
// Shared storage instances
// ---------------------------------------------------------------------------

const _storage = FlutterSecureStorage(
  wOptions: WindowsOptions(useBackwardCompatibility: true),
);

const _storageNoCompat = FlutterSecureStorage();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verifies that the legacy Credential Store is empty, confirming that
/// migration has completed.
Future<void> _checkMigration() async {
  final legacy = await _legacyReadAll();
  expect(
    legacy,
    isEmpty,
    reason: 'Legacy Credential Store should be empty after migration',
  );
}

/// Runs a complete CRUD cycle (write → read → containsKey → readAll → delete
/// → deleteAll) against `storage`, using [key1] and optionally [key2].
Future<void> _doTestSuite({
  required String key1,
  String? key2,
  String value1 = 'value-for-key1',
  String? value2,
  bool useBackwardCompatibility = true,
}) async {
  final s = useBackwardCompatibility ? _storage : _storageNoCompat;
  final v2 = value2 ?? (key2 != null ? 'value-for-key2' : null);

  // Write
  await s.write(key: key1, value: value1);
  if (key2 != null) await s.write(key: key2, value: v2);

  // Read
  expect(await s.read(key: key1), value1);
  if (key2 != null) expect(await s.read(key: key2), v2);

  // ContainsKey
  expect(await s.containsKey(key: key1), isTrue);
  if (key2 != null) expect(await s.containsKey(key: key2), isTrue);

  // ReadAll
  final all = await s.readAll();
  expect(all, containsPair(key1, value1));
  if (key2 != null) expect(all, containsPair(key2, v2));

  // Delete key1
  await s.delete(key: key1);
  expect(await s.read(key: key1), isNull);
  expect(await s.containsKey(key: key1), isFalse);

  final afterDelete = await s.readAll();
  expect(afterDelete, isNot(contains(key1)));
  if (key2 != null) expect(afterDelete, containsPair(key2, v2));

  // Re-write key1 so deleteAll has something to clear when there is no key2.
  if (key2 == null) await s.write(key: key1, value: value1);

  // DeleteAll
  await s.deleteAll();
  expect(await s.read(key: key2 ?? key1), isNull);
  expect(await s.containsKey(key: key2 ?? key1), isFalse);
  expect(await s.readAll(), isEmpty);
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    await _storage.deleteAll(); // cleans DPAPI store
    // (and legacy when compat=true)
    await _legacyDeleteAll(); // belt-and-suspenders: clean Credential Store
  });

  tearDown(() async {
    await _storage.deleteAll();
    await _legacyDeleteAll();
  });

  // -------------------------------------------------------------------------
  // Basic test
  // -------------------------------------------------------------------------

  group(
    'Basic test',
    () {
      testWidgets('Smoke test', (_) async {
        await _doTestSuite(key1: 'key1', key2: 'key2');
      });
    },
    skip: kIsWeb || !Platform.isWindows ? 'Windows only' : null,
  );

  // -------------------------------------------------------------------------
  // Backward compatibility cases
  // -------------------------------------------------------------------------

  group(
    'Backwards compatibility cases',
    () {
      // readAll ---------------------------------------------------------------

      testWidgets('readAll - empty, empty', (_) async {
        final all = await _storage.readAll();
        expect(all, isEmpty);
        await _checkMigration();
      });

      testWidgets('readAll - 1 entry (new), 1 entry (legacy), different keys',
          (_) async {
        const key1 = 'key1';
        const key2 = 'key2';
        const v1 = 'dpapi-v1';
        const v2 = 'legacy-v2';

        await _storage.write(key: key1, value: v1);
        await _legacyWrite(key2, v2);

        final all = await _storage.readAll();
        expect(all, containsPair(key1, v1));
        expect(all, containsPair(key2, v2));
        await _checkMigration();
      });

      testWidgets('readAll - 1 entry (new), 1 entry (legacy), same key',
          (_) async {
        const key = 'key';
        const dpapiValue = 'dpapi-value';
        const legacyValue = 'legacy-value';

        await _storage.write(key: key, value: dpapiValue);
        await _legacyWrite(key, legacyValue);

        // DPAPI takes precedence when both stores have the same key.
        final all = await _storage.readAll();
        expect(all, containsPair(key, dpapiValue));
        expect(all.length, 1);
        await _checkMigration();
      });

      testWidgets('readAll - empty (new), 1 entry (legacy)', (_) async {
        const key = 'key';
        const v = 'legacy-value';

        await _legacyWrite(key, v);

        final all = await _storage.readAll();
        expect(all, containsPair(key, v));
        await _checkMigration();
      });

      testWidgets('readAll - 1 entry (new), empty (legacy)', (_) async {
        const key = 'key';
        const v = 'dpapi-value';

        await _storage.write(key: key, value: v);

        final all = await _storage.readAll();
        expect(all, containsPair(key, v));
        await _checkMigration();
      });

      testWidgets(
          'readAll - 2 entries (new), 2 entries (legacy), overlapping keys',
          (_) async {
        const key1 = 'key1';
        const key2 = 'key2';
        const key3 = 'key3';
        const dpapiV1 = 'dpapi-v1';
        const dpapiV2 = 'dpapi-v2';
        const legacyV3 = 'legacy-v3';
        const legacyV1 = 'legacy-v1-different'; // same key as key1

        await _storage.write(key: key1, value: dpapiV1);
        await _storage.write(key: key2, value: dpapiV2);
        await _legacyWrite(key3, legacyV3);
        await _legacyWrite(key1, legacyV1); // DPAPI should win

        final all = await _storage.readAll();
        // DPAPI value wins for key1
        expect(all, containsPair(key1, dpapiV1));
        expect(all, containsPair(key2, dpapiV2));
        expect(all, containsPair(key3, legacyV3));
        expect(all.length, 3);
        await _checkMigration();
      });

      // read ------------------------------------------------------------------

      testWidgets('read - exists in new, exists in legacy (same key)',
          (_) async {
        const key = 'key';
        const dpapiValue = 'dpapi-value';

        await _storage.write(key: key, value: dpapiValue);
        await _legacyWrite(key, 'legacy-value');

        // DPAPI takes precedence.
        expect(await _storage.read(key: key), dpapiValue);
        await _checkMigration();
      });

      testWidgets('read - not in new, exists in legacy', (_) async {
        const key = 'key';
        const v = 'legacy-value';

        await _legacyWrite(key, v);

        expect(await _storage.read(key: key), v);
        await _checkMigration();
      });

      testWidgets('read - exists in new, not in legacy', (_) async {
        const key = 'key';
        const v = 'dpapi-value';

        await _storage.write(key: key, value: v);

        expect(await _storage.read(key: key), v);
        await _checkMigration();
      });

      testWidgets('read - not in new, not in legacy', (_) async {
        expect(await _storage.read(key: 'key'), isNull);
        await _checkMigration();
      });

      // containsKey -----------------------------------------------------------
      // Note: containsKey does NOT trigger auto-migration.

      testWidgets('containsKey - exists in new, exists in legacy', (_) async {
        const key = 'key';

        await _storage.write(key: key, value: 'dpapi-value');
        await _legacyWrite(key, 'legacy-value');

        expect(await _storage.containsKey(key: key), isTrue);
        // No migration expected — containsKey does not migrate.
      });

      testWidgets('containsKey - not in new, exists in legacy', (_) async {
        const key = 'key';

        await _legacyWrite(key, 'legacy-value');

        expect(await _storage.containsKey(key: key), isTrue);
        // No migration expected.
      });

      testWidgets('containsKey - exists in new, not in legacy', (_) async {
        const key = 'key';

        await _storage.write(key: key, value: 'dpapi-value');

        expect(await _storage.containsKey(key: key), isTrue);
      });

      testWidgets('containsKey - not in new, not in legacy', (_) async {
        expect(await _storage.containsKey(key: 'key'), isFalse);
      });

      // write -----------------------------------------------------------------

      testWidgets('write - new key', (_) async {
        const key = 'key';
        const v = 'written-value';

        await _storage.write(key: key, value: v);
        await _checkMigration();

        expect(await _storage.read(key: key), v);
      });

      testWidgets('write - overwrite existing key', (_) async {
        const key = 'key';

        await _storage.write(key: key, value: 'first');
        await _checkMigration();

        await _storage.write(key: key, value: 'second');
        await _checkMigration();

        expect(await _storage.read(key: key), 'second');
      });

      testWidgets('write - legacy value exists for same key', (_) async {
        const key = 'key';
        const legacyValue = 'legacy-value';
        const newValue = 'new-dpapi-value';

        await _legacyWrite(key, legacyValue);

        await _storage.write(key: key, value: newValue);
        await _checkMigration();

        expect(await _storage.read(key: key), newValue);
      });

      // delete ----------------------------------------------------------------

      testWidgets('delete - exists in new, exists in legacy', (_) async {
        const key = 'key';

        await _storage.write(key: key, value: 'dpapi-value');
        await _legacyWrite(key, 'legacy-value');

        await _storage.delete(key: key);
        await _checkMigration();

        expect(await _storage.containsKey(key: key), isFalse);
      });

      testWidgets('delete - exists in new, not in legacy', (_) async {
        const key = 'key';

        await _storage.write(key: key, value: 'dpapi-value');

        await _storage.delete(key: key);
        await _checkMigration();

        expect(await _storage.containsKey(key: key), isFalse);
      });

      testWidgets('delete - not in new, exists in legacy', (_) async {
        const key = 'key';

        await _legacyWrite(key, 'legacy-value');

        await _storage.delete(key: key);
        await _checkMigration();

        expect(await _storage.containsKey(key: key), isFalse);
      });

      testWidgets('delete - not in new, not in legacy', (_) async {
        await _storage.delete(key: 'key');
        await _checkMigration();

        expect(await _storage.containsKey(key: 'key'), isFalse);
      });

      // deleteAll -------------------------------------------------------------

      testWidgets('deleteAll - empty, empty', (_) async {
        await _storage.deleteAll();
        await _checkMigration();

        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets('deleteAll - 1 entry (new), 1 entry (legacy), different keys',
          (_) async {
        await _storage.write(key: 'key1', value: 'dpapi-v1');
        await _legacyWrite('key2', 'legacy-v2');

        await _storage.deleteAll();
        await _checkMigration();

        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets('deleteAll - 1 entry (new), 1 entry (legacy), same key',
          (_) async {
        const key = 'key';

        await _storage.write(key: key, value: 'dpapi-value');
        await _legacyWrite(key, 'legacy-value');

        await _storage.deleteAll();
        await _checkMigration();

        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets('deleteAll - empty (new), 1 entry (legacy)', (_) async {
        await _legacyWrite('key', 'legacy-value');

        await _storage.deleteAll();
        await _checkMigration();

        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets('deleteAll - 1 entry (new), empty (legacy)', (_) async {
        await _storage.write(key: 'key', value: 'dpapi-value');

        await _storage.deleteAll();
        await _checkMigration();

        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets(
          'deleteAll - 2 entries (new), 2 entries (legacy), overlapping keys',
          (_) async {
        await _storage.write(key: 'key1', value: 'dpapi-v1');
        await _storage.write(key: 'key2', value: 'dpapi-v2');
        await _legacyWrite('key3', 'legacy-v3');
        await _legacyWrite('key1', 'legacy-v1-different');

        await _storage.deleteAll();
        await _checkMigration();

        expect(await _storage.readAll(), isEmpty);
      });
    },
    skip: kIsWeb || !Platform.isWindows ? 'Windows only' : null,
  );

  // -------------------------------------------------------------------------
  // Special character handling
  // -------------------------------------------------------------------------

  group(
    'Special characters handling',
    () {
      testWidgets('URL key', (_) async {
        await _doTestSuite(
          key1: 'http://example.com',
          useBackwardCompatibility: false,
        );
      });

      testWidgets('Double dot key', (_) async {
        await _doTestSuite(key1: '/../a');
      });

      testWidgets('Long key (256 chars)', (_) async {
        await _doTestSuite(
          key1: String.fromCharCodes(Iterable.generate(256, (_) => 65)),
          useBackwardCompatibility: false,
        );
      });

      testWidgets('Empty key and value', (_) async {
        await _doTestSuite(key1: '', value1: '');
      });

      for (final entry in <String, int>{
        'ASCII space (U+0020)': 0x20,
        'Non-breaking space (U+00A0)': 0xA0,
        'Full-width space (U+3000)': 0x3000,
      }.entries) {
        testWidgets('Space key and value - ${entry.key}', (_) async {
          await _doTestSuite(
            key1: String.fromCharCode(entry.value),
            value1: String.fromCharCode(entry.value),
          );
        });
      }

      testWidgets('Horizontal tab key and value (U+0009)', (_) async {
        await _doTestSuite(
          key1: String.fromCharCode(0x09),
          value1: String.fromCharCode(0x09),
          useBackwardCompatibility: false,
        );
      });

      for (final entry in <String, String>{
        'Latin-1 / French': 'cl\u00E9',
        'CJK / Japanese': '\u30AD\u30FC',
        'Surrogate pair / Emoji': '\uD83D\uDD11',
      }.entries) {
        testWidgets('Non-ASCII key and value - ${entry.key}', (_) async {
          await _doTestSuite(
            key1: entry.value,
            value1: entry.value,
          );
        });
      }

      testWidgets('Case-sensitive keys (key vs KEY)', (_) async {
        await _doTestSuite(key1: 'key', key2: 'KEY');
      });
    },
    skip: kIsWeb || !Platform.isWindows ? 'Windows only' : null,
  );
}
