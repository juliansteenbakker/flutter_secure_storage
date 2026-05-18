import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Linux-specific integration tests.
///
/// Covers write/read/containsKey/readAll/delete/deleteAll and a sample of
/// special-character keys.
///
/// Run with:
///   flutter test integration_test/linux_test.dart -d linux

const _storage = FlutterSecureStorage();

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    await _storage.deleteAll();
  });

  tearDown(() async {
    await _storage.deleteAll();
  });

  // ---------------------------------------------------------------------------
  // Basic CRUD
  // ---------------------------------------------------------------------------

  group(
    'Basic CRUD',
    () {
      testWidgets('write and read round trip', (_) async {
        await _storage.write(key: 'key1', value: 'value1');
        expect(await _storage.read(key: 'key1'), 'value1');
      });

      testWidgets('read missing key returns null', (_) async {
        expect(await _storage.read(key: 'nonexistent'), isNull);
      });

      testWidgets('overwrite returns new value', (_) async {
        await _storage.write(key: 'k', value: 'first');
        await _storage.write(key: 'k', value: 'second');
        expect(await _storage.read(key: 'k'), 'second');
      });

      testWidgets('containsKey true after write', (_) async {
        await _storage.write(key: 'k', value: 'v');
        expect(await _storage.containsKey(key: 'k'), isTrue);
      });

      testWidgets('containsKey false for missing key', (_) async {
        expect(await _storage.containsKey(key: 'nonexistent'), isFalse);
      });

      testWidgets('delete removes key', (_) async {
        await _storage.write(key: 'k', value: 'v');
        await _storage.delete(key: 'k');
        expect(await _storage.containsKey(key: 'k'), isFalse);
        expect(await _storage.read(key: 'k'), isNull);
      });

      testWidgets('delete nonexistent key is no-op', (_) async {
        await _storage.delete(key: 'never_written');
        expect(await _storage.containsKey(key: 'never_written'), isFalse);
      });

      testWidgets('readAll returns all written entries', (_) async {
        await _storage.write(key: 'k1', value: 'v1');
        await _storage.write(key: 'k2', value: 'v2');
        final all = await _storage.readAll();
        expect(all, containsPair('k1', 'v1'));
        expect(all, containsPair('k2', 'v2'));
      });

      testWidgets('deleteAll clears every key', (_) async {
        await _storage.write(key: 'a', value: '1');
        await _storage.write(key: 'b', value: '2');
        await _storage.deleteAll();
        expect(await _storage.readAll(), isEmpty);
      });
    },
    skip: kIsWeb || !Platform.isLinux ? 'Linux only' : null,
  );

  // ---------------------------------------------------------------------------
  // deleteAll state recovery
  // ---------------------------------------------------------------------------

  group(
    'deleteAll state recovery',
    () {
      testWidgets('readAll after deleteAll returns empty map', (_) async {
        await _storage.write(key: 'a', value: '1');
        await _storage.write(key: 'b', value: '2');
        await _storage.deleteAll();

        expect(await _storage.readAll(), isEmpty);
      });

      testWidgets('operations after deleteAll behave correctly', (_) async {
        await _storage.write(key: 'before', value: 'old');
        await _storage.deleteAll();

        await _storage.write(key: 'after', value: 'new');
        expect(await _storage.read(key: 'after'), 'new');
        expect(await _storage.read(key: 'before'), isNull);
        expect(await _storage.containsKey(key: 'after'), isTrue);
        expect(await _storage.containsKey(key: 'before'), isFalse);
        expect(await _storage.readAll(), {'after': 'new'});
      });

      testWidgets('values read from storage are valid UTF-8', (_) async {
        const key = 'utf8-key';
        const value = 'café';
        await _storage.write(key: key, value: value);
        expect(await _storage.read(key: key), value);
      });
    },
    skip: kIsWeb || !Platform.isLinux ? 'Linux only' : null,
  );

  // ---------------------------------------------------------------------------
  // Special-character keys
  // ---------------------------------------------------------------------------

  group(
    'Special-character keys',
    () {
      testWidgets('URL key', (_) async {
        const key = 'http://example.com';
        await _storage.write(key: key, value: 'url-value');
        expect(await _storage.read(key: key), 'url-value');
        expect(await _storage.containsKey(key: key), isTrue);
        await _storage.delete(key: key);
        expect(await _storage.containsKey(key: key), isFalse);
      });

      testWidgets('Non-ASCII key (Latin-1)', (_) async {
        const key = 'clé';
        await _storage.write(key: key, value: key);
        expect(await _storage.read(key: key), key);
        await _storage.delete(key: key);
        expect(await _storage.containsKey(key: key), isFalse);
      });

      testWidgets('Case-sensitive keys', (_) async {
        await _storage.write(key: 'key', value: 'lower');
        await _storage.write(key: 'KEY', value: 'upper');
        expect(await _storage.read(key: 'key'), 'lower');
        expect(await _storage.read(key: 'KEY'), 'upper');
        final all = await _storage.readAll();
        expect(all.length, 2);
      });
    },
    skip: kIsWeb || !Platform.isLinux ? 'Linux only' : null,
  );
}
