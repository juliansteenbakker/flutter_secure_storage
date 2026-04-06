import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Web-specific integration tests.
///
/// These tests avoid dart:io so that they compile on all platforms.
/// Platform-guarding is done via `skip: !kIsWeb` so that running
/// `flutter test integration_test` on Android/iOS/Windows does not
/// execute (or fail) these tests.
///
/// Run with:
///   flutter test integration_test/web_test.dart -d chrome
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // Use sessionStorage-backed namespaces so test data never persists across
  // browser sessions.
  const storageA = FlutterSecureStorage(
    webOptions: WebOptions(
      publicKey: 'it_web_namespace_a',
      useSessionStorage: true,
    ),
  );
  const storageB = FlutterSecureStorage(
    webOptions: WebOptions(
      publicKey: 'it_web_namespace_b',
      useSessionStorage: true,
    ),
  );

  setUp(() async {
    await storageA.deleteAll();
    await storageB.deleteAll();
  });

  tearDown(() async {
    await storageA.deleteAll();
    await storageB.deleteAll();
  });

  group(
    'Web: basic CRUD',
    () {
      testWidgets('write and read round-trip', (_) async {
        await storageA.write(key: 'greeting', value: 'hello');
        expect(await storageA.read(key: 'greeting'), 'hello');
      });

      testWidgets('read returns null for absent key', (_) async {
        expect(await storageA.read(key: 'missing'), isNull);
      });

      testWidgets('containsKey reflects write and delete', (_) async {
        await storageA.write(key: 'k', value: 'v');
        expect(await storageA.containsKey(key: 'k'), isTrue);

        await storageA.delete(key: 'k');
        expect(await storageA.containsKey(key: 'k'), isFalse);
      });

      testWidgets('readAll returns all written entries', (_) async {
        await storageA.write(key: 'x', value: '1');
        await storageA.write(key: 'y', value: '2');

        final all = await storageA.readAll();
        expect(all, {'x': '1', 'y': '2'});
      });

      testWidgets('deleteAll removes all entries', (_) async {
        await storageA.write(key: 'x', value: '1');
        await storageA.write(key: 'y', value: '2');

        await storageA.deleteAll();
        expect(await storageA.readAll(), isEmpty);
      });
    },
    skip: !kIsWeb ? 'Web only' : null,
  );

  group(
    'Web: namespace isolation',
    () {
      testWidgets(
        'deleteAll on one namespace does not affect another',
        (_) async {
          const key = 'shared_key';
          await storageA.write(key: key, value: 'value_a');
          await storageB.write(key: key, value: 'value_b');

          await storageA.deleteAll();

          expect(
            await storageB.read(key: key),
            'value_b',
            reason: 'Deleting namespace A must not touch namespace B',
          );
          expect(await storageA.read(key: key), isNull);
        },
      );

      testWidgets(
        'readAll only returns entries from its own namespace',
        (_) async {
          await storageA.write(key: 'mine', value: 'yes');
          await storageB.write(key: 'theirs', value: 'no');

          final result = await storageA.readAll();
          expect(result, {'mine': 'yes'});
          expect(result.containsKey('theirs'), isFalse);
        },
      );

      testWidgets(
        'same key in two namespaces holds independent values',
        (_) async {
          await storageA.write(key: 'k', value: 'a');
          await storageB.write(key: 'k', value: 'b');

          expect(await storageA.read(key: 'k'), 'a');
          expect(await storageB.read(key: 'k'), 'b');
        },
      );
    },
    skip: !kIsWeb ? 'Web only' : null,
  );
}
