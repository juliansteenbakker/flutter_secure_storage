import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

// ✅ Correct Mock Class Implementation
class MockFlutterSecureStoragePlatform extends Mock
    with MockPlatformInterfaceMixin
    implements FlutterSecureStoragePlatform {}

void main() {
  late FlutterSecureStorage storage;
  late MockFlutterSecureStoragePlatform mockPlatform;

  setUp(() {
    mockPlatform = MockFlutterSecureStoragePlatform();
    FlutterSecureStoragePlatform.instance = mockPlatform;
    storage = const FlutterSecureStorage();
  });

  group('FlutterSecureStorage Tests', () {
    const testKey = 'testKey';
    const testValue = 'testValue';

    test('write should call platform write method', () async {
      when(
        () => mockPlatform.write(
          key: any(named: 'key'),
          value: any(named: 'value'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async {});

      await storage.write(key: testKey, value: testValue);

      verify(
        () => mockPlatform.write(
          key: testKey,
          value: testValue,
          options: any(named: 'options'),
        ),
      ).called(1);
    });

    test('read should return correct value', () async {
      when(
        () => mockPlatform.read(
          key: any(named: 'key'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async => testValue);

      final result = await storage.read(key: testKey);

      expect(result, equals(testValue));
      verify(
        () => mockPlatform.read(
          key: testKey,
          options: any(named: 'options'),
        ),
      ).called(1);
    });

    test('delete should call platform delete method', () async {
      when(
        () => mockPlatform.delete(
          key: any(named: 'key'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async {});

      await storage.delete(key: testKey);

      verify(
        () => mockPlatform.delete(
          key: testKey,
          options: any(named: 'options'),
        ),
      ).called(1);
    });

    test('containsKey should return true if key exists', () async {
      when(
        () => mockPlatform.containsKey(
          key: any(named: 'key'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async => true);

      final result = await storage.containsKey(key: testKey);

      expect(result, isTrue);
      verify(
        () => mockPlatform.containsKey(
          key: testKey,
          options: any(named: 'options'),
        ),
      ).called(1);
    });

    test('write with null value should trigger delete', () async {
      when(
        () => mockPlatform.delete(
          key: any(named: 'key'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async {});

      await storage.write(key: testKey, value: null);

      verify(
        () => mockPlatform.delete(
          key: testKey,
          options: any(named: 'options'),
        ),
      ).called(1);
    });
  });

  group('AndroidOptions Tests', () {
    test('Default AndroidOptions should have correct default values', () {
      const options = AndroidOptions.defaultOptions;

      expect(options.toMap(), {
        'encryptedSharedPreferences': 'false',
        'resetOnError': 'false',
        'keyCipherAlgorithm': 'RSA_ECB_PKCS1Padding',
        'storageCipherAlgorithm': 'AES_CBC_PKCS7Padding',
        'sharedPreferencesName': '',
        'preferencesKeyPrefix': '',
      });
    });

    test('AndroidOptions with custom values', () {
      const options = AndroidOptions(
        resetOnError: true,
        keyCipherAlgorithm:
            KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
        storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
        sharedPreferencesName: 'customPrefs',
        preferencesKeyPrefix: 'customPrefix',
      );

      expect(options.toMap(), {
        'encryptedSharedPreferences': 'false',
        'resetOnError': 'true',
        'keyCipherAlgorithm': 'RSA_ECB_OAEPwithSHA_256andMGF1Padding',
        'storageCipherAlgorithm': 'AES_GCM_NoPadding',
        'sharedPreferencesName': 'customPrefs',
        'preferencesKeyPrefix': 'customPrefix',
      });
    });

    test('copyWith should correctly override values', () {
      const original = AndroidOptions.defaultOptions;

      final copied = original.copyWith(
        resetOnError: true,
        sharedPreferencesName: 'newPrefs',
      );

      expect(copied.toMap(), {
        'encryptedSharedPreferences': 'false',
        'resetOnError': 'true',
        'keyCipherAlgorithm': 'RSA_ECB_PKCS1Padding',
        'storageCipherAlgorithm': 'AES_CBC_PKCS7Padding',
        'sharedPreferencesName': 'newPrefs',
        'preferencesKeyPrefix': '',
      });
    });

    test('copyWith without changes should retain original values', () {
      const original = AndroidOptions(
        resetOnError: true,
        keyCipherAlgorithm:
            KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
        storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
      );

      final copied = original.copyWith();

      expect(copied.toMap(), original.toMap());
    });

    test(
        'AndroidOptions handles null sharedPreferencesName and '
        'preferencesKeyPrefix', () {
      const options = AndroidOptions.defaultOptions;

      expect(options.toMap()['sharedPreferencesName'], '');
      expect(options.toMap()['preferencesKeyPrefix'], '');
    });

    test('Deprecated encryptedSharedPreferences still functions', () {
      // Ignore for test
      // ignore: deprecated_member_use_from_same_package
      const options = AndroidOptions(encryptedSharedPreferences: true);

      expect(options.toMap()['encryptedSharedPreferences'], 'true');
    });
  });

  group('WebOptions Tests', () {
    test('Default WebOptions should have correct default values', () {
      const options = WebOptions.defaultOptions;

      expect(options.toMap(), {
        'dbName': 'FlutterEncryptedStorage',
        'publicKey': 'FlutterSecureStorage',
        'wrapKey': '',
        'wrapKeyIv': '',
        'useSessionStorage': 'false',
      });
    });

    test('WebOptions with custom values', () {
      const options = WebOptions(
        dbName: 'CustomDB',
        publicKey: 'CustomPublicKey',
        wrapKey: 'CustomWrapKey',
        wrapKeyIv: 'CustomWrapKeyIv',
        useSessionStorage: true,
      );

      expect(options.toMap(), {
        'dbName': 'CustomDB',
        'publicKey': 'CustomPublicKey',
        'wrapKey': 'CustomWrapKey',
        'wrapKeyIv': 'CustomWrapKeyIv',
        'useSessionStorage': 'true',
      });
    });

    test('WebOptions handles empty wrapKey and wrapKeyIv', () {
      const options = WebOptions.defaultOptions;

      expect(options.toMap()['wrapKey'], '');
      expect(options.toMap()['wrapKeyIv'], '');
    });

    test('WebOptions defaultOptions matches default constructor', () {
      const defaultOptions = WebOptions.defaultOptions;
      // Ignore for test
      // ignore: use_named_constants
      const constructorOptions = WebOptions();

      expect(defaultOptions.toMap(), constructorOptions.toMap());
    });

    test('WebOptions with only sessionStorage enabled', () {
      const options = WebOptions(useSessionStorage: true);

      expect(options.toMap(), {
        'dbName': 'FlutterEncryptedStorage',
        'publicKey': 'FlutterSecureStorage',
        'wrapKey': '',
        'wrapKeyIv': '',
        'useSessionStorage': 'true',
      });
    });
  });

  group('WindowsOptions Tests', () {
    test('Default WindowsOptions should have correct default values', () {
      const options = WindowsOptions.defaultOptions;

      expect(options.toMap(), {
        'useBackwardCompatibility': 'false',
      });
    });

    test('WindowsOptions with useBackwardCompatibility set to true', () {
      const options = WindowsOptions(useBackwardCompatibility: true);

      expect(options.toMap(), {
        'useBackwardCompatibility': 'true',
      });
    });

    test('WindowsOptions copyWith should override values correctly', () {
      const original = WindowsOptions.defaultOptions;

      final copied = original.copyWith(useBackwardCompatibility: true);

      expect(copied.toMap(), {
        'useBackwardCompatibility': 'true',
      });
    });

    test(
        'WindowsOptions copyWith without changes should retain original values',
        () {
      const original = WindowsOptions(useBackwardCompatibility: true);

      final copied = original.copyWith();

      expect(copied.toMap(), original.toMap());
    });

    test('WindowsOptions defaultOptions matches default constructor', () {
      const defaultOptions = WindowsOptions.defaultOptions;
      // Ignore for test
      // ignore: use_named_constants
      const constructorOptions = WindowsOptions();

      expect(defaultOptions.toMap(), constructorOptions.toMap());
    });
  });

  group('IOSOptions Tests', () {
    test('Default IOSOptions should have correct default values', () {
      const options = IOSOptions.defaultOptions;

      expect(options.toMap(), {
        'accountName': 'flutter_secure_storage_service',
        'accessibility': 'unlocked',
        'synchronizable': 'false',
      });
    });

    test('IOSOptions with custom values', () {
      final options = IOSOptions(
        accountName: 'customAccount',
        groupId: 'group.com.example',
        accessibility: KeychainAccessibility.unlocked_this_device,
        synchronizable: true,
        label: 'Custom Label',
        description: 'Test Description',
        comment: 'Test Comment',
        isInvisible: true,
        isNegative: false,
        creationDate: DateTime(2023),
        lastModifiedDate: DateTime(2024),
        resultLimit: 10,
        shouldReturnPersistentReference: true,
        authenticationUIBehavior: 'require_auth',
        accessControlFlags: [AccessControlFlag.biometryCurrentSet],
      );

      expect(options.toMap(), {
        'accountName': 'customAccount',
        'groupId': 'group.com.example',
        'accessibility': 'unlocked_this_device',
        'synchronizable': 'true',
        'label': 'Custom Label',
        'description': 'Test Description',
        'comment': 'Test Comment',
        'isInvisible': 'true',
        'isNegative': 'false',
        'creationDate': '2023-01-01T00:00:00.000',
        'lastModifiedDate': '2024-01-01T00:00:00.000',
        'resultLimit': '10',
        'shouldReturnPersistentReference': 'true',
        'authenticationUIBehavior': 'require_auth',
        'accessControlFlags':
            [AccessControlFlag.biometryCurrentSet.name].toString(),
      });
    });

    test('IOSOptions defaultOptions matches default constructor', () {
      const defaultOptions = IOSOptions.defaultOptions;
      // Ignore for test
      // ignore: use_named_constants
      const constructorOptions = IOSOptions();

      expect(defaultOptions.toMap(), constructorOptions.toMap());
    });
  });

  group('MacOsOptions Tests', () {
    test('Default MacOsOptions should have correct default values', () {
      // Ignore for test
      // ignore: use_named_constants
      const options = MacOsOptions();

      expect(options.toMap(), {
        'accountName': 'flutter_secure_storage_service',
        'accessibility': 'unlocked',
        'synchronizable': 'false',
        'usesDataProtectionKeychain': 'true',
      });
    });

    test('MacOsOptions with custom values', () {
      const options = MacOsOptions(
        accountName: 'macAccount',
        groupId: 'group.mac.example',
        accessibility: KeychainAccessibility.first_unlock,
        synchronizable: true,
        usesDataProtectionKeychain: false,
      );

      expect(options.toMap(), {
        'accountName': 'macAccount',
        'groupId': 'group.mac.example',
        'accessibility': 'first_unlock',
        'synchronizable': 'true',
        'usesDataProtectionKeychain': 'false',
      });
    });

    test('MacOsOptions defaultOptions matches default constructor', () {
      const defaultOptions = MacOsOptions.defaultOptions;
      // Ignore for test
      // ignore: use_named_constants
      const constructorOptions = MacOsOptions();

      expect(defaultOptions.toMap(), constructorOptions.toMap());
    });
  });
}
