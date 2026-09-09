part of '../flutter_secure_storage_platform_interface.dart';

/// The overall result of [FlutterSecureStoragePlatform.checkUpgradeStatus].
enum SecureStorageUpgradeState {
  /// Nothing at risk: the storage is empty, verified readable, or the platform
  /// has nothing to report.
  ok,

  /// Data is present that this plugin version cannot decrypt. Not touched yet;
  /// see [SecureStorageUpgradeStatus.willDiscardOnNextAccess].
  legacyDataUnreadable,

  /// Unreadable data was already deleted by an earlier access. Reported once,
  /// then cleared.
  legacyDataDiscarded,

  /// The state could not be checked without side effects, usually a biometric
  /// prompt.
  unknown,
}

/// Explains why storage is in the reported [SecureStorageUpgradeState].
enum SecureStorageUpgradeReason {
  /// No further detail.
  none,

  /// Encrypted with a cipher that v11 removed.
  removedCipher,

  /// No algorithm markers, so it was written by v9 or earlier.
  missingAlgorithmMarkers,

  /// Still in the EncryptedSharedPreferences (Jetpack Security / Tink) store,
  /// whose backend v11 removed.
  legacyBackendPresent,

  /// The key needed to decrypt the data is gone.
  missingKeyMaterial,

  /// Decrypting a stored entry was tried and failed.
  decryptFailed,

  /// Reading needs user authentication, so nothing was tried.
  authenticationRequired,

  /// The platform does not implement this check.
  unsupportedPlatform,
}

/// A read-only report from [FlutterSecureStoragePlatform.checkUpgradeStatus]
/// on whether stored data survived a plugin upgrade. Producing it never writes,
/// migrates, or deletes anything.
@immutable
class SecureStorageUpgradeStatus {
  /// Creates an upgrade status report.
  const SecureStorageUpgradeStatus({
    required this.state,
    this.reason = SecureStorageUpgradeReason.none,
    this.entryCount = 0,
    this.willDiscardOnNextAccess = false,
    this.details,
  });

  /// Builds a status from the map sent over the method channel. Unrecognised
  /// names decay to [SecureStorageUpgradeState.unknown] /
  /// [SecureStorageUpgradeReason.none] so a newer native side can't crash an
  /// older Dart side.
  factory SecureStorageUpgradeStatus.fromMap(Map<Object?, Object?> map) =>
      SecureStorageUpgradeStatus(
        state: _enumByName(
          SecureStorageUpgradeState.values,
          map['state'],
          SecureStorageUpgradeState.unknown,
        ),
        reason: _enumByName(
          SecureStorageUpgradeReason.values,
          map['reason'],
          SecureStorageUpgradeReason.none,
        ),
        entryCount: map['entryCount'] is int ? map['entryCount']! as int : 0,
        willDiscardOnNextAccess: map['willDiscardOnNextAccess'] == true,
        details: map['details'] as String?,
      );

  /// The status returned on platforms that do not implement the check.
  static const unsupported = SecureStorageUpgradeStatus(
    state: SecureStorageUpgradeState.ok,
    reason: SecureStorageUpgradeReason.unsupportedPlatform,
  );

  /// What, if anything, is wrong.
  final SecureStorageUpgradeState state;

  /// Why storage is in this [state].
  final SecureStorageUpgradeReason reason;

  /// How many stored entries the report covers. For
  /// [SecureStorageUpgradeState.legacyDataUnreadable], how many would be lost.
  final int entryCount;

  /// Whether the next read or write will delete the unreadable data. True when
  /// [state] is [SecureStorageUpgradeState.legacyDataUnreadable] and
  /// `resetOnError` is enabled (the default); when false the data stays on disk
  /// and the next access fails.
  final bool willDiscardOnNextAccess;

  /// A human-readable explanation for a log line, if the platform gave one. Not
  /// for end users.
  final String? details;

  /// Whether data is or was lost, so the app should re-authenticate the user
  /// or re-fetch what it had cached.
  bool get hasDataLoss =>
      state == SecureStorageUpgradeState.legacyDataUnreadable ||
      state == SecureStorageUpgradeState.legacyDataDiscarded;

  @override
  String toString() => 'SecureStorageUpgradeStatus(state: ${state.name}, '
      'reason: ${reason.name}, entryCount: $entryCount, '
      'willDiscardOnNextAccess: $willDiscardOnNextAccess, '
      'details: $details)';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SecureStorageUpgradeStatus &&
          other.state == state &&
          other.reason == reason &&
          other.entryCount == entryCount &&
          other.willDiscardOnNextAccess == willDiscardOnNextAccess &&
          other.details == details;

  @override
  int get hashCode => Object.hash(
        state,
        reason,
        entryCount,
        willDiscardOnNextAccess,
        details,
      );
}

T _enumByName<T extends Enum>(List<T> values, Object? name, T fallback) {
  for (final value in values) {
    if (value.name == name) {
      return value;
    }
  }
  return fallback;
}
