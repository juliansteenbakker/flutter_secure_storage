import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Linux locked-keyring integration tests.
///
/// Must run before the keyring is unlocked. The gnome-keyring-daemon is
/// registered on D-Bus but the default collection is locked, so every
/// libsecret call that requires collection access will fail.
///
/// Run with (keyring daemon running but locked):
///   flutter test integration_test/linux_locked_keyring_test.dart -d linux

const _storage = FlutterSecureStorage();

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group(
    'Locked keyring',
    () {
      Future<void> expectLockedKeyringError(Future<void> Function() op) async {
        Object? caught;
        try {
          await op();
        } on Object catch (e) {
          caught = e;
        }

        expect(
          caught,
          isNotNull,
          reason: 'Expected an exception but the operation succeeded',
        );

        // A FormatException means the native plugin returned non-UTF-8 bytes
        // that crashed Dart's StandardMethodCodec decoder.
        expect(caught, isNot(isA<FormatException>()));

        expect(
          caught,
          isA<PlatformException>(),
          reason: 'Expected PlatformException, got ${caught.runtimeType}',
        );

        final e = caught! as PlatformException;

        expect(e.code, 'KeyringLocked');
        expect(e.message, isA<String>());
      }

      testWidgets('read throws on locked keyring', (_) async {
        await expectLockedKeyringError(() => _storage.read(key: 'k'));
      });

      testWidgets('write throws on locked keyring', (_) async {
        await expectLockedKeyringError(
          () => _storage.write(key: 'k', value: 'v'),
        );
      });

      testWidgets('readAll throws on locked keyring', (_) async {
        await expectLockedKeyringError(() => _storage.readAll());
      });

      testWidgets('containsKey throws on locked keyring', (_) async {
        await expectLockedKeyringError(() => _storage.containsKey(key: 'k'));
      });

      testWidgets('delete throws on locked keyring', (_) async {
        await expectLockedKeyringError(() => _storage.delete(key: 'k'));
      });

      // deleteAll bypasses warmupKeyring and calls secret_password_storev_sync
      // directly, so the raw GError message reaches the catch block. If that
      // message contains non-UTF-8 bytes Dart throws FormatException instead
      // of PlatformException.
      testWidgets('deleteAll throws PlatformException, not FormatException',
          (_) async {
        await expectLockedKeyringError(() => _storage.deleteAll());
      });
    },
    skip: kIsWeb || !Platform.isLinux ? 'Linux only' : null,
  );
}
