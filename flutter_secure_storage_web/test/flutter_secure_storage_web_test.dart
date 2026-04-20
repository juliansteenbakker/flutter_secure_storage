@TestOn('browser')
library;

import 'package:flutter_secure_storage_web/flutter_secure_storage_web.dart';
import 'package:flutter_test/flutter_test.dart';

/// Options that use sessionStorage so test data is never persisted across
/// browser sessions and each test run starts clean.
const _opts = <String, String>{
  'publicKey': 'test_fss_web',
  'useSessionStorage': 'true',
};

const _otherOpts = <String, String>{
  'publicKey': 'test_fss_web_other',
  'useSessionStorage': 'true',
};

void main() {
  late FlutterSecureStorageWeb storage;

  setUp(() {
    storage = FlutterSecureStorageWeb();
  });

  tearDown(() async {
    await storage.deleteAll(options: _opts);
    await storage.deleteAll(options: _otherOpts);
  });

  group('write / read', () {
    test('round-trip returns the written value', () async {
      await storage.write(key: 'k', value: 'v', options: _opts);
      expect(await storage.read(key: 'k', options: _opts), 'v');
    });

    test('read returns null for an absent key', () async {
      expect(await storage.read(key: 'missing', options: _opts), isNull);
    });

    test('overwriting a key returns the new value', () async {
      await storage.write(key: 'k', value: 'first', options: _opts);
      await storage.write(key: 'k', value: 'second', options: _opts);
      expect(await storage.read(key: 'k', options: _opts), 'second');
    });
  });

  group('containsKey', () {
    test('returns true for a written key', () async {
      await storage.write(key: 'k', value: 'v', options: _opts);
      expect(await storage.containsKey(key: 'k', options: _opts), isTrue);
    });

    test('returns false for an absent key', () async {
      expect(
        await storage.containsKey(key: 'missing', options: _opts),
        isFalse,
      );
    });
  });

  group('delete', () {
    test('removes the key', () async {
      await storage.write(key: 'k', value: 'v', options: _opts);
      await storage.delete(key: 'k', options: _opts);
      expect(await storage.containsKey(key: 'k', options: _opts), isFalse);
    });

    test('is a no-op for an absent key', () async {
      await expectLater(
        storage.delete(key: 'missing', options: _opts),
        completes,
      );
    });
  });

  group('readAll', () {
    test('returns all written entries', () async {
      await storage.write(key: 'a', value: '1', options: _opts);
      await storage.write(key: 'b', value: '2', options: _opts);
      await storage.write(key: 'c', value: '3', options: _opts);

      expect(await storage.readAll(options: _opts), {
        'a': '1',
        'b': '2',
        'c': '3',
      });
    });

    test('returns empty map when storage is empty', () async {
      expect(await storage.readAll(options: _opts), isEmpty);
    });

    test('excludes keys belonging to other namespaces', () async {
      await storage.write(key: 'mine', value: 'yes', options: _opts);
      await storage.write(key: 'theirs', value: 'no', options: _otherOpts);

      final result = await storage.readAll(options: _opts);
      expect(result, {'mine': 'yes'});
    });
  });

  group('deleteAll', () {
    test('removes all keys in the namespace', () async {
      await storage.write(key: 'a', value: '1', options: _opts);
      await storage.write(key: 'b', value: '2', options: _opts);
      await storage.deleteAll(options: _opts);

      expect(await storage.readAll(options: _opts), isEmpty);
    });

    test('does not affect keys in other namespaces', () async {
      await storage.write(key: 'k', value: 'mine', options: _opts);
      await storage.write(key: 'k', value: 'other', options: _otherOpts);

      await storage.deleteAll(options: _opts);

      expect(await storage.read(key: 'k', options: _otherOpts), 'other');
    });
  });
}
