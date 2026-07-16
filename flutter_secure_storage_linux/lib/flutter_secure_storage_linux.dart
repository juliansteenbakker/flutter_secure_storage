import 'dart:convert' show jsonEncode, jsonDecode;

import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:freedesktop_secret/freedesktop_secret.dart';
import 'package:linux_application_id/linux_application_id.dart';

typedef _StorageMap = Map<String, String>;

/// Linux implementation of [FlutterSecureStoragePlatform] using the `org.freedesktop.secrets` D-Bus API.
class FlutterSecureStorageLinux extends FlutterSecureStoragePlatform {
  /// Registers this class as the default instance of [FlutterSecureStoragePlatform].
  static void registerWith() {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageLinux();
  }

  /// Secret Service client (`org.freedesktop.secrets`).
  final FreeDesktopSecret _client = FreeDesktopSecret();
  late String _applicationId;

  Future<void>? _initialization;
  Future<void> _initialize() async {
    _applicationId = applicationIdOverride ??
        linuxApplicationId() ??
        (throw UnsupportedError(
          'No Linux application ID is available. This must be called from a running Flutter Linux application.',
        ));

    await _client.initialize();

    if (migrateLegacyData) {
      await migrateLegacyDataIfNeeded();
    }
  }

  /// Automatically migrates data from the legacy Linux implementation.
  bool migrateLegacyData = true;

  /// Deletes the legacy secret after a successful migration.
  bool deleteLegacyData = false;

  /// Overrides the Linux application ID.
  ///
  /// The application ID is used for the `xdg:schema` attribute of stored secrets
  /// and for migrating legacy secrets.
  String? applicationIdOverride;

  Future<void> migrateLegacyDataIfNeeded() async {
    final secretCount =
        await _client.countSecrets(attributes: _lookupAttributes());
    if (secretCount > 0) {
      // A new-format secret already exists. Preserve it and skip migration.
      return;
    }

    final legacyAttributes = _legacyLookupAttributes();
    final legacySecret = await _client.lookupSecret(
      attributes: legacyAttributes,
      duplicateStrategy: LookupSecretDuplicateStrategy.newestCreated,
    );
    if (legacySecret == null) {
      return;
    }

    await _writeStorageMap(legacySecret.storageMap());

    if (deleteLegacyData) {
      await _client.deleteSecret(attributes: legacyAttributes);
    }
  }

  Future<void> _ensureInitialized() => _initialization ??= _initialize();

  /// We intentionally do not include `xdg:schema` here.
  /// The previous `flutter_secure_storage_linux` implementation incorrectly
  /// populated the `xdg:schema` attribute with unstable yet unique values (for example,
  /// `*` or `9`). Instead, we match only on the application-specific
  /// `account` attribute, which was populated consistently, to preserve
  /// compatibility with existing data.
  ///
  /// See: https://github.com/juliansteenbakker/flutter_secure_storage/issues/1181
  Map<String, String> _legacyLookupAttributes() =>
      {'account': '$_applicationId.secureStorage'};

  /// Note: Changes to these lookup attributes are not backward compatible.
  Map<String, String> _lookupAttributes() =>
      {'xdg:schema': _applicationId, 'package': 'flutter_secure_storage'};

  /// Reads and decodes the stored key/value map.
  Future<_StorageMap> _readStorageMap() async {
    final secret = await _client.lookupSecret(
      attributes: _lookupAttributes(),
      duplicateStrategy: LookupSecretDuplicateStrategy.first,
    );
    return secret == null ? {} : secret.storageMap();
  }

  /// Encodes and stores the key/value map.
  Future<void> _writeStorageMap(_StorageMap map) async {
    await _client.storeSecretText(
      attributes: _lookupAttributes(),
      label: '$_applicationId/FlutterSecureStorage',
      secret: jsonEncode(map),
      replace: true,
    );
  }

  @override
  Future<bool> containsKey(
      {required String key, required Map<String, String> options}) async {
    await _ensureInitialized();

    final map = await _readStorageMap();
    return map.containsKey(key);
  }

  @override
  Future<void> delete(
      {required String key, required Map<String, String> options}) async {
    await _ensureInitialized();

    final map = await _readStorageMap();
    map.remove(key);

    await _writeStorageMap(map);
  }

  @override
  Future<void> deleteAll({required Map<String, String> options}) async {
    await _ensureInitialized();

    await _writeStorageMap({});
  }

  @override
  Future<String?> read(
      {required String key, required Map<String, String> options}) async {
    await _ensureInitialized();

    final map = await _readStorageMap();
    return map[key];
  }

  @override
  Future<Map<String, String>> readAll(
      {required Map<String, String> options}) async {
    await _ensureInitialized();

    return await _readStorageMap();
  }

  @override
  Future<void> write(
      {required String key,
      required String value,
      required Map<String, String> options}) async {
    await _ensureInitialized();

    final map = await _readStorageMap();
    map[key] = value;

    await _writeStorageMap(map);
  }
}

extension on SecretItem {
  /// Decodes the stored key/value map.
  _StorageMap storageMap() =>
      (jsonDecode(secretAsText()) as Map<String, Object?>).cast();
}
