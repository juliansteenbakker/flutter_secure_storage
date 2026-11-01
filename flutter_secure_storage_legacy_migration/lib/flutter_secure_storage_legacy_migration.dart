import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Migrates Android data written by flutter_secure_storage before version 10,
/// including stores that also contain version 10 entries.
final class FlutterSecureStorageLegacyMigration {
  FlutterSecureStorageLegacyMigration._();

  static const MethodChannel _channel = MethodChannel(
    'plugins.it_nomads.com/flutter_secure_storage_legacy_migration',
  );

  /// Returns true if legacy data was migrated and false if migration was unnecessary.
  ///
  /// Call before the first read or write through [FlutterSecureStorage].
  /// Migration errors are surfaced so the app can stop before ordinary access.
  static Future<bool> migrateIfNeeded({
    AndroidOptions options = const AndroidOptions(),
  }) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) {
      return false;
    }

    final storage = FlutterSecureStorage(
      aOptions: options,
    );
    final before = await storage.checkUpgradeStatus();
    final authenticationRequired =
        before.state == SecureStorageUpgradeState.unknown &&
        before.reason == SecureStorageUpgradeReason.authenticationRequired;
    final pending =
        await _channel.invokeMethod<bool>(
          "hasPendingMigration",
          options.toMap(),
        ) ==
        true;
    if (!pending &&
        (before.state == SecureStorageUpgradeState.ok ||
            authenticationRequired ||
            before.reason == SecureStorageUpgradeReason.legacyBackendPresent)) {
      return false;
    }
    if (before.state != SecureStorageUpgradeState.ok &&
        !authenticationRequired &&
        !pending &&
        (before.state != SecureStorageUpgradeState.legacyDataUnreadable ||
            (before.reason != SecureStorageUpgradeReason.removedCipher &&
                before.reason != SecureStorageUpgradeReason.missingAlgorithmMarkers &&
                before.reason != SecureStorageUpgradeReason.legacyBackendPresent))) {
      throw StateError(
        'Secure storage cannot be migrated: $before',
      );
    }

    final selectedEntryCount =
        await _channel.invokeMethod<int>(
          "getSelectedEntryCount",
          options.toMap(),
        ) ??
        -1;
    if (selectedEntryCount < 0) {
      throw StateError(
        "Secure storage migration did not report a selected entry count",
      );
    }

    final migrationOptions = <String, String>{
      ...options.toMap(),
      'legacyBackendPresent': '${before.reason == SecureStorageUpgradeReason.legacyBackendPresent}',
      'resetOnError': 'false',
      'migrateOnAlgorithmChange': 'true',
      'migrateWithBackup': '${before.reason != SecureStorageUpgradeReason.legacyBackendPresent}',
    };
    final migratedCount = await _channel.invokeMethod<int>(
      'migrate',
      migrationOptions,
    );
    if (migratedCount == null || migratedCount < selectedEntryCount) {
      throw StateError(
        "Secure storage migration recovered $migratedCount of $selectedEntryCount selected entries",
      );
    }

    final after = await storage.checkUpgradeStatus();
    final authenticatedMigration =
        after.state == SecureStorageUpgradeState.unknown &&
        after.reason == SecureStorageUpgradeReason.authenticationRequired &&
        options.toMap()["keyCipherAlgorithm"] == "AES_GCM_NoPadding";
    final emptySelectedScope =
        selectedEntryCount == 0 &&
        migratedCount == 0 &&
        after.state == SecureStorageUpgradeState.legacyDataUnreadable &&
        after.reason == SecureStorageUpgradeReason.legacyBackendPresent;
    if (after.state != SecureStorageUpgradeState.ok &&
        !authenticatedMigration &&
        !emptySelectedScope) {
      throw StateError(
        'Secure storage migration did not complete: $after',
      );
    }
    await _channel.invokeMethod<void>(
      "completeMigration",
      options.toMap(),
    );
    return true;
  }

  static Future<void> resetStorage({
    AndroidOptions options = const AndroidOptions(),
  }) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) {
      return;
    }

    await _channel.invokeMethod<void>(
      'resetStorage',
      options.toMap(),
    );
  }

  static Future<Map<String, String>> readLegacyEntries(
    List<String> keys, {
    AndroidOptions options = const AndroidOptions(),
  }) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) {
      return const {};
    }

    final entries = await _channel.invokeMapMethod<String, String>(
      'readLegacyEntries',
      {'options': options.toMap(), 'keys': keys},
    );
    return entries ?? const {};
  }
}
