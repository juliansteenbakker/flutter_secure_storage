import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('SecureStorageUpgradeStatus.fromMap', () {
    test('parses a full report', () {
      final status = SecureStorageUpgradeStatus.fromMap(const {
        'state': 'legacyDataUnreadable',
        'reason': 'removedCipher',
        'entryCount': 3,
        'willDiscardOnNextAccess': true,
        'details': 'RSA_ECB_PKCS1Padding was removed in v11.',
      });

      expect(status.state, SecureStorageUpgradeState.legacyDataUnreadable);
      expect(status.reason, SecureStorageUpgradeReason.removedCipher);
      expect(status.entryCount, 3);
      expect(status.willDiscardOnNextAccess, true);
      expect(status.details, 'RSA_ECB_PKCS1Padding was removed in v11.');
      expect(status.hasDataLoss, true);
    });

    test('falls back on names a newer native side might send', () {
      final status = SecureStorageUpgradeStatus.fromMap(const {
        'state': 'somethingAddedLater',
        'reason': 'alsoAddedLater',
      });

      expect(status.state, SecureStorageUpgradeState.unknown);
      expect(status.reason, SecureStorageUpgradeReason.none);
      expect(status.entryCount, 0);
      expect(status.willDiscardOnNextAccess, false);
      expect(status.details, isNull);
    });

    test('parses the legacyBackendPresent reason', () {
      final status = SecureStorageUpgradeStatus.fromMap(const {
        'state': 'legacyDataUnreadable',
        'reason': 'legacyBackendPresent',
        'entryCount': 4,
        'willDiscardOnNextAccess': false,
      });

      expect(status.reason, SecureStorageUpgradeReason.legacyBackendPresent);
      expect(status.hasDataLoss, true);
      expect(status.willDiscardOnNextAccess, false);
    });

    test('hasDataLoss covers data that was already discarded', () {
      final status = SecureStorageUpgradeStatus.fromMap(const {
        'state': 'legacyDataDiscarded',
        'reason': 'decryptFailed',
      });

      expect(status.hasDataLoss, true);
      expect(status.willDiscardOnNextAccess, false);
    });

    test('ok reports no data loss', () {
      final status = SecureStorageUpgradeStatus.fromMap(const {
        'state': 'ok',
        'reason': 'none',
        'entryCount': 5,
      });

      expect(status.hasDataLoss, false);
      expect(status.entryCount, 5);
    });
  });

  group('SecureStorageUpgradeStatus value semantics', () {
    const a = SecureStorageUpgradeStatus(
      state: SecureStorageUpgradeState.legacyDataUnreadable,
      reason: SecureStorageUpgradeReason.removedCipher,
      entryCount: 2,
      willDiscardOnNextAccess: true,
      details: 'x',
    );

    test('equal values compare equal and share a hashCode', () {
      const b = SecureStorageUpgradeStatus(
        state: SecureStorageUpgradeState.legacyDataUnreadable,
        reason: SecureStorageUpgradeReason.removedCipher,
        entryCount: 2,
        willDiscardOnNextAccess: true,
        details: 'x',
      );

      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, a); // identical fast path
    });

    test('different values are not equal', () {
      expect(a == SecureStorageUpgradeStatus.unsupported, isFalse);
      expect(a == const Object(), isFalse);
    });

    test('toString names the fields', () {
      expect(
        a.toString(),
        'SecureStorageUpgradeStatus(state: legacyDataUnreadable, '
        'reason: removedCipher, entryCount: 2, '
        'willDiscardOnNextAccess: true, details: x)',
      );
    });
  });

  group('MethodChannelFlutterSecureStorage.checkUpgradeStatus', () {
    const channel = MethodChannel(
      'plugins.it_nomads.com/flutter_secure_storage',
    );
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    final storage = MethodChannelFlutterSecureStorage();
    const options = <String, String>{'resetOnError': 'true'};

    tearDown(() => messenger.setMockMethodCallHandler(channel, null));

    test('forwards options and parses the reply', () async {
      final log = <MethodCall>[];
      messenger.setMockMethodCallHandler(channel, (call) async {
        log.add(call);
        return <Object?, Object?>{
          'state': 'legacyDataUnreadable',
          'reason': 'missingAlgorithmMarkers',
          'entryCount': 2,
          'willDiscardOnNextAccess': true,
          'details': 'No algorithm markers found.',
        };
      });

      final status = await storage.checkUpgradeStatus(options: options);

      expect(log, [
        isMethodCall('checkUpgradeStatus', arguments: {'options': options}),
      ]);
      expect(status.state, SecureStorageUpgradeState.legacyDataUnreadable);
      expect(status.reason, SecureStorageUpgradeReason.missingAlgorithmMarkers);
      expect(status.entryCount, 2);
      expect(status.willDiscardOnNextAccess, true);
    });

    test('reports unsupported when the platform has no handler', () async {
      // No mock handler registered, so the channel raises
      // MissingPluginException, exactly as a native side predating this
      // method would.
      final status = await storage.checkUpgradeStatus(options: options);

      expect(status, SecureStorageUpgradeStatus.unsupported);
      expect(status.state, SecureStorageUpgradeState.ok);
      expect(status.reason, SecureStorageUpgradeReason.unsupportedPlatform);
      expect(status.hasDataLoss, false);
    });

    test('reports unsupported when the platform replies with null', () async {
      messenger.setMockMethodCallHandler(channel, (call) async => null);

      final status = await storage.checkUpgradeStatus(options: options);

      expect(status, SecureStorageUpgradeStatus.unsupported);
    });
  });
}
