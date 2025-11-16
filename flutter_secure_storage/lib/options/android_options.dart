part of '../flutter_secure_storage.dart';
// Documentation ignored because enums will be removed in a later release
//ignore_for_file: public_member_api_docs
//ignore_for_file: constant_identifier_names
//ignore_for_file: deprecated_member_use_from_same_package

enum KeyCipherAlgorithm {
  RSA_ECB_PKCS1Padding,
  RSA_ECB_OAEPwithSHA_256andMGF1Padding,
  AES_GCM_NoPadding_BIOMETRIC,
}

enum StorageCipherAlgorithm {
  AES_CBC_PKCS7Padding,
  AES_GCM_NoPadding,
  AES_GCM_NoPadding_BIOMETRIC,
}

/// Specific options for Android platform.
class AndroidOptions extends Options {
  /// Standard secure storage using AES-GCM with RSA key wrapping (Recommended).
  /// - No biometric authentication required
  /// - Strong authenticated encryption (AES/GCM/NoPadding)
  /// - Hardware-backed RSA key protection
  /// - API 23+ (Android 6.0+)
  const AndroidOptions.standard({
    @Deprecated(
      'EncryptedSharedPreferences is deprecated and will be removed in v10.0.0. '
      'The Jetpack Security library is deprecated by Google. '
      'Your data will be automatically migrated to AES_GCM_NoPadding on first access. '
      'Remove this parameter - it will be ignored.'
    )
    bool encryptedSharedPreferences = false,
    bool resetOnError = false,
    bool migrateOnAlgorithmChange = true,
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
  })  : _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
        _migrateOnAlgorithmChange = migrateOnAlgorithmChange,
        _keyCipherAlgorithm = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
        _storageCipherAlgorithm = StorageCipherAlgorithm.AES_GCM_NoPadding,
        biometricPromptTitle = null,
        biometricPromptSubtitle = null;

  /// Enhanced secure storage using AES-GCM with stronger RSA OAEP key wrapping.
  /// - No biometric authentication required
  /// - Strong authenticated encryption (AES/GCM/NoPadding)
  /// - Hardware-backed RSA OAEP key protection (more secure than PKCS1)
  /// - API 23+ (Android 6.0+)
  const AndroidOptions.standardSecure({
    @Deprecated(
      'EncryptedSharedPreferences is deprecated and will be removed in v10.0.0. '
      'The Jetpack Security library is deprecated by Google. '
      'Your data will be automatically migrated to AES_GCM_NoPadding on first access. '
      'Remove this parameter - it will be ignored.'
    )
    bool encryptedSharedPreferences = false,
    bool resetOnError = false,
    bool migrateOnAlgorithmChange = true,
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
  })  : _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
        _migrateOnAlgorithmChange = migrateOnAlgorithmChange,
        _keyCipherAlgorithm =
            KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
        _storageCipherAlgorithm = StorageCipherAlgorithm.AES_GCM_NoPadding,
        biometricPromptTitle = null,
        biometricPromptSubtitle = null;

  /// Maximum security storage requiring biometric authentication.
  /// - Requires biometric authentication once per app session
  /// - Strong authenticated encryption (AES/GCM/NoPadding 256-bit)
  /// - Hardware-backed AES key with user presence requirement
  /// - API 28+ (Android 9.0+)
  /// - Automatically falls back to standard RSA encryption if biometrics unavailable
  const AndroidOptions.biometric({
    @Deprecated(
      'EncryptedSharedPreferences is deprecated and will be removed in v10.0.0. '
      'The Jetpack Security library is deprecated by Google. '
      'Remove this parameter - it will be ignored.'
    )
    bool encryptedSharedPreferences = false,
    bool resetOnError = false,
    bool migrateOnAlgorithmChange = true,
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
    this.biometricPromptTitle,
    this.biometricPromptSubtitle,
  })  : _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
        _migrateOnAlgorithmChange = migrateOnAlgorithmChange,
        _keyCipherAlgorithm = KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC,
        _storageCipherAlgorithm =
            StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC;

  /// Advanced constructor for custom algorithm combinations.
  ///
  /// **Warning:** Not all combinations are valid. Use named constructors (standard,
  /// standardSecure, biometric) unless you need specific control.
  ///
  /// Valid combinations:
  /// - AES_CBC_PKCS7Padding storage + RSA_ECB_PKCS1Padding key
  /// - AES_CBC_PKCS7Padding storage + RSA_ECB_OAEPwithSHA_256andMGF1Padding key
  /// - AES_GCM_NoPadding storage + RSA_ECB_PKCS1Padding key
  /// - AES_GCM_NoPadding storage + RSA_ECB_OAEPwithSHA_256andMGF1Padding key
  /// - AES_GCM_NoPadding_BIOMETRIC storage + AES_GCM_NoPadding_BIOMETRIC key (only)
  const AndroidOptions({
    @Deprecated(
      'EncryptedSharedPreferences is deprecated and will be removed in v10.0.0. '
      'The Jetpack Security library is deprecated by Google. '
      'Your data will be automatically migrated to custom ciphers on first access. '
      'Remove this parameter - it will be ignored.'
    )
    bool encryptedSharedPreferences = false,
    bool resetOnError = false,
    bool migrateOnAlgorithmChange = true,
    KeyCipherAlgorithm keyCipherAlgorithm =
        KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
    StorageCipherAlgorithm storageCipherAlgorithm =
        StorageCipherAlgorithm.AES_GCM_NoPadding,
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
    this.biometricPromptTitle,
    this.biometricPromptSubtitle,
  })  : assert(
          // Validate biometric storage requires biometric key
          storageCipherAlgorithm !=
                  StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC ||
              keyCipherAlgorithm ==
                  KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC,
          'AES_GCM_NoPadding_BIOMETRIC storage requires AES_GCM_NoPadding_BIOMETRIC key cipher. '
          'Invalid combination: $storageCipherAlgorithm + $keyCipherAlgorithm. '
          'Use AndroidOptions.biometric() for biometric storage.',
        ),
        assert(
          // Validate non-biometric storage uses RSA keys
          storageCipherAlgorithm ==
                  StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC ||
              keyCipherAlgorithm !=
                  KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC,
          'AES_GCM_NoPadding_BIOMETRIC key cipher can only be used with AES_GCM_NoPadding_BIOMETRIC storage. '
          'Invalid combination: $storageCipherAlgorithm + $keyCipherAlgorithm. '
          'Use AndroidOptions.standard() or AndroidOptions.standardSecure() for non-biometric storage.',
        ),
        _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
        _migrateOnAlgorithmChange = migrateOnAlgorithmChange,
        _keyCipherAlgorithm = keyCipherAlgorithm,
        _storageCipherAlgorithm = storageCipherAlgorithm;

  /// EncryptedSharedPrefences are only available on API 23 and greater
  final bool _encryptedSharedPreferences;

  /// When an error is detected, automatically reset all data. This will prevent
  /// fatal errors regarding an unknown key however keep in mind that it will
  /// PERMANENLTY erase the data when an error occurs.
  ///
  /// Defaults to false.
  final bool _resetOnError;

  /// When the encryption algorithm changes, automatically migrate existing data
  /// to the new algorithm. This preserves data across algorithm upgrades.
  /// If false, data will be lost when algorithm changes unless resetOnError is true.
  ///
  /// Defaults to true.
  final bool _migrateOnAlgorithmChange;

  /// If EncryptedSharedPrefences is set to false, you can select algorithm
  /// that will be used to encrypt secret key.
  /// By default RSA/ECB/PKCS1Padding if used.
  /// Newer RSA/ECB/OAEPWithSHA-256AndMGF1Padding is available from Android 6.
  /// Plugin will fall back to default algorithm in previous system versions.
  final KeyCipherAlgorithm _keyCipherAlgorithm;

  /// If EncryptedSharedPrefences is set to false, you can select algorithm
  /// that will be used to encrypt properties.
  /// By default AES/CBC/PKCS7Padding if used.
  /// Newer AES/GCM/NoPadding is available from Android 6.
  /// Plugin will fall back to default algorithm in previous system versions.
  final StorageCipherAlgorithm _storageCipherAlgorithm;

  /// The name of the sharedPreference database to use.
  /// You can select your own name if you want. A default name will
  /// be used if nothing is provided here.
  ///
  /// WARNING: If you change this you can't retrieve already saved preferences.
  final String? sharedPreferencesName;

  /// The prefix for a shared preference key. The prefix is used to make sure
  /// the key is unique to your application. If not provided, a default prefix
  /// will be used.
  ///
  /// WARNING: If you change this you can't retrieve already saved preferences.
  final String? preferencesKeyPrefix;

  final String? biometricPromptTitle;
  final String? biometricPromptSubtitle;

  static const AndroidOptions defaultOptions = AndroidOptions.standard();

  @override
  Map<String, String> toMap() => <String, String>{
        'encryptedSharedPreferences': '$_encryptedSharedPreferences',
        'resetOnError': '$_resetOnError',
        'migrateOnAlgorithmChange': '$_migrateOnAlgorithmChange',
        'keyCipherAlgorithm': _keyCipherAlgorithm.name,
        'storageCipherAlgorithm': _storageCipherAlgorithm.name,
        'sharedPreferencesName': sharedPreferencesName ?? '',
        'preferencesKeyPrefix': preferencesKeyPrefix ?? '',
        'biometricPromptTitle': biometricPromptTitle ??
            'Authenticate to access',
        'biometricPromptSubtitle': biometricPromptSubtitle ??
            'Use biometrics or device credentials',

      };

  AndroidOptions copyWith({
    bool? encryptedSharedPreferences,
    bool? resetOnError,
    bool? migrateOnAlgorithmChange,
    KeyCipherAlgorithm? keyCipherAlgorithm,
    StorageCipherAlgorithm? storageCipherAlgorithm,
    String? preferencesKeyPrefix,
    String? sharedPreferencesName,
    String? biometricPromptTitle,
    String? biometricPromptSubtitle,
  }) =>
      AndroidOptions(
        encryptedSharedPreferences:
            encryptedSharedPreferences ?? _encryptedSharedPreferences,
        resetOnError: resetOnError ?? _resetOnError,
        migrateOnAlgorithmChange:
            migrateOnAlgorithmChange ?? _migrateOnAlgorithmChange,
        keyCipherAlgorithm: keyCipherAlgorithm ?? _keyCipherAlgorithm,
        storageCipherAlgorithm:
            storageCipherAlgorithm ?? _storageCipherAlgorithm,
        sharedPreferencesName: sharedPreferencesName ?? this.sharedPreferencesName,
        preferencesKeyPrefix: preferencesKeyPrefix ?? this.preferencesKeyPrefix,
        biometricPromptTitle: biometricPromptTitle ?? this.biometricPromptTitle,
        biometricPromptSubtitle: biometricPromptSubtitle ?? this.biometricPromptSubtitle,
      );
}
