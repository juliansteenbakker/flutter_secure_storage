import 'dart:io';

import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:linux_application_id/linux_application_id.dart';
import 'package:xdg_desktop_portal/xdg_desktop_portal.dart';
import 'package:xdg_directories/xdg_directories.dart';
import 'package:xdg_secret_portal_store/xdg_secret_portal_store.dart';
import 'package:xdg_secret_portal_store_default/xdg_secret_portal_store_default.dart';

typedef _StorageMap = Map<String, String>;

/// Linux implementation of [FlutterSecureStoragePlatform] using the XDG
/// Desktop Portal Secret API.
class FlutterSecureStorageLinuxPortal extends FlutterSecureStoragePlatform {
  /// Registers this class as the default instance of [FlutterSecureStoragePlatform].
  static void registerWith() {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageLinuxPortal();
  }

  late final XdgDesktopPortalClient _client;
  late final XdgSecretPortalStore _store;
  late String _applicationId;

  Future<void>? _initialization;
  Future<void> _initialize() async {
    _applicationId =
        applicationIdOverride ??
        linuxApplicationId() ??
        (throw UnsupportedError(
          'No Linux application ID is available. This must be called from a running Flutter Linux application.',
        ));

    _client = XdgDesktopPortalClient();

    final filePath =
        '${dataHome.path}/$_applicationId/xdg_secret_portal_store/secrets.json';

    _store = XdgSecretPortalStore(
      masterSecretRetriever: _client.secret.retrieveSecret,
      persistence: SecretStorePersistenceFile(File(filePath)),
      crypto: SecretStoreCryptoDefault(),
    );

    await _store.loadMasterSecret();
  }

  Future<void> _ensureInitialized() => _initialization ??= _initialize();

  /// Overrides the Linux application ID.
  ///
  /// The application ID is used to determine the directory where the encrypted
  /// secret store is persisted.
  String? applicationIdOverride;

  Future<_StorageMap> _readStorageMap() => _store.read();
  Future<void> _writeStorageMap(_StorageMap map) => _store.write(map);

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async {
    await _ensureInitialized();
    final map = await _readStorageMap();
    return map.containsKey(key);
  }

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async {
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
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    await _ensureInitialized();

    final map = await _readStorageMap();
    return map[key];
  }

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    await _ensureInitialized();

    return _readStorageMap();
  }

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async {
    await _ensureInitialized();

    final map = await _readStorageMap();
    map[key] = value;

    await _writeStorageMap(map);
  }
}
