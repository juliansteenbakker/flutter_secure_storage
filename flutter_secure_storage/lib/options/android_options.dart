// Ignore name convention for constants for backwards compatibility
// ignore_for_file: constant_identifier_names

part of '../flutter_secure_storage.dart';

/// Algorithm used to encrypt/wrap the secret key in Android KeyStore.
enum KeyCipherAlgorithm {
  /// Legacy RSA/ECB/PKCS1Padding for backwards compatibility.
  RSA_ECB_PKCS1Padding,

  /// RSA/ECB/OAEPWithSHA-256AndMGF1Padding (default, API 23+).
  RSA_ECB_OAEPwithSHA_256andMGF1Padding,

  /// AES/GCM/NoPadding for KeyStore-based key wrapping (supports biometrics).
  AES_GCM_NoPadding,
}

/// Algorithm used to encrypt stored data.
enum StorageCipherAlgorithm {
  /// Legacy AES/CBC/PKCS7Padding for backwards compatibility.
  AES_CBC_PKCS7Padding,

  /// AES/GCM/NoPadding (default, API 23+).
  AES_GCM_NoPadding,
}

/// Specific options for Android platform.
class AndroidOptions extends Options {
  /// Standard secure storage using AES-GCM with RSA OAEP key wrapping.
  ///
  /// This is the default constructor with strong security:
  /// - RSA/ECB/OAEPWithSHA-256AndMGF1Padding for key protection
  /// - AES/GCM/NoPadding for data encryption
  /// - No biometric authentication required
  /// - API 23+ (Android 6.0+)
  ///
  /// For biometric authentication, use `AndroidOptions.biometric()`.
  ///
  /// Advanced users can customize cipher algorithms for specific use cases.
  /// Valid combinations:
  /// - AES_CBC_PKCS7Padding storage + any key cipher
  /// - AES_GCM_NoPadding storage + RSA key ciphers (standard RSA wrapping)
  /// - AES_GCM_NoPadding storage + AES_GCM_NoPadding key
  ///   (KeyStore-based, supports biometrics)
  const AndroidOptions({
    @Deprecated('EncryptedSharedPreferences is deprecated and will be '
        'removed in v11. The Jetpack Security library is deprecated by Google. '
        'Your data will be automatically migrated to custom ciphers on first '
        'access. Remove this parameter - it will be ignored.')
    bool encryptedSharedPreferences = false,
    bool resetOnError = true,
    bool migrateOnAlgorithmChange = true,
    bool migrateWithBackup = false,
    bool enforceBiometrics = false,
    KeyCipherAlgorithm keyCipherAlgorithm =
        KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
    StorageCipherAlgorithm storageCipherAlgorithm =
        StorageCipherAlgorithm.AES_GCM_NoPadding,
    @Deprecated(
        'Use storageNamespace instead. sharedPreferencesName only isolates '
        'data storage; storageNamespace provides full isolation including '
        'KeyStore aliases and key storage.')
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
    this.storageNamespace,
    this.biometricPromptTitle,
    this.biometricPromptSubtitle,
  })  : _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
        _migrateOnAlgorithmChange = migrateOnAlgorithmChange,
        _migrateWithBackup = migrateWithBackup,
        _enforceBiometrics = enforceBiometrics,
        _keyCipherAlgorithm = keyCipherAlgorithm,
        _storageCipherAlgorithm = storageCipherAlgorithm;

  /// Maximum security storage with optional biometric authentication.
  /// - Optionally requires biometric authentication
  ///   (set enforceBiometrics=true)
  /// - Strong authenticated encryption (AES/GCM/NoPadding 256-bit)
  /// - Hardware-backed AES key with optional user presence requirement
  /// - API 28+ (Android 9.0+)
  /// - When enforceBiometrics=false, gracefully degrades if biometrics
  ///   unavailable
  const AndroidOptions.biometric({
    @Deprecated(
        'EncryptedSharedPreferences is deprecated and will be removed in v11. '
        'The Jetpack Security library is deprecated by Google. '
        'Remove this parameter - it will be ignored.')
    bool encryptedSharedPreferences = false,
    bool resetOnError = true,
    bool migrateOnAlgorithmChange = true,
    bool migrateWithBackup = false,
    bool enforceBiometrics = false,
    @Deprecated(
        'Use storageNamespace instead. sharedPreferencesName only isolates '
        'data storage; storageNamespace provides full isolation including '
        'KeyStore aliases and key storage.')
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
    this.storageNamespace,
    this.biometricPromptTitle,
    this.biometricPromptSubtitle,
  })  : _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
        _migrateOnAlgorithmChange = migrateOnAlgorithmChange,
        _migrateWithBackup = migrateWithBackup,
        _enforceBiometrics = enforceBiometrics,
        _keyCipherAlgorithm = KeyCipherAlgorithm.AES_GCM_NoPadding,
        _storageCipherAlgorithm = StorageCipherAlgorithm.AES_GCM_NoPadding;

  /// EncryptedSharedPrefences are only available on API 23 and greater
  final bool _encryptedSharedPreferences;

  /// When an error is detected, automatically reset all data. This will prevent
  /// fatal errors regarding an unknown key however keep in mind that it will
  /// PERMANENTLY erase the data when an error occurs.
  ///
  /// Defaults to true.
  final bool _resetOnError;

  /// When the encryption algorithm changes, automatically migrate existing data
  /// to the new algorithm. This preserves data across algorithm upgrades.
  /// If false, data will be lost when algorithm changes unless resetOnError
  /// is true.
  ///
  /// Defaults to true.
  final bool _migrateOnAlgorithmChange;

  /// Enable crash-resistant migration with backup protection.
  /// Creates backup copies of encrypted data before migration starts.
  /// If migration fails or crashes, data can be recovered from backup.
  /// Works in conjunction with migrateOnAlgorithmChange.
  ///
  /// Defaults to false.
  final bool _migrateWithBackup;

  /// Whether to enforce biometric/PIN authentication.
  ///
  /// When `true`, the plugin will throw an exception if the device
  /// has no PIN, pattern, password, or biometric enrolled. The key will
  /// be generated with setUserAuthenticationRequired(true).
  ///
  /// When `false` (default), the plugin will gracefully degrade
  /// to storing data without biometric protection if unavailable.
  /// The key will be generated with setUserAuthenticationRequired(false).
  ///
  /// **Security note:** Set to `true` for highly sensitive data
  /// that must never be stored without authentication.
  ///
  /// Defaults to false.
  final bool _enforceBiometrics;

  /// Algorithm used to encrypt the secret key.
  /// By default RSA/ECB/OAEPWithSHA-256AndMGF1Padding is used (API 23+).
  /// Legacy RSA/ECB/PKCS1Padding is available for backwards compatibility.
  final KeyCipherAlgorithm _keyCipherAlgorithm;

  /// Algorithm used to encrypt stored data.
  /// By default AES/GCM/NoPadding is used (API 23+).
  /// Legacy AES/CBC/PKCS7Padding is available for backwards compatibility.
  final StorageCipherAlgorithm _storageCipherAlgorithm;

  /// The name of the sharedPreference database to use.
  /// You can select your own name if you want. A default name will
  /// be used if nothing is provided here.
  ///
  /// WARNING: If you change this you can't retrieve already saved preferences.
  @Deprecated(
      'Use storageNamespace instead. sharedPreferencesName only isolates '
      'data storage; storageNamespace provides full isolation including '
      'KeyStore aliases and key storage.')
  final String? sharedPreferencesName;

  /// The prefix for a shared preference key. The prefix is used to make sure
  /// the key is unique to your application. An underscore (_) is added to the
  /// end of the prefix automatically. If not provided, a default prefix will
  /// be used.
  ///
  /// Example: preferencesKeyPrefix: "my_app" will result in a key like
  /// "my_app_key1".
  ///
  /// WARNING: If you change this you can't retrieve already saved preferences.
  final String? preferencesKeyPrefix;

  /// Provides full namespace isolation for this storage instance.
  ///
  /// When set, **all** storage artifacts are namespaced:
  /// - Data SharedPreferences
  /// - Config/algorithm markers
  /// - Android KeyStore aliases
  /// - Wrapped-key SharedPreferences
  ///
  /// This allows multiple `FlutterSecureStorage` instances to use different
  /// cipher algorithms without conflicting KeyStore entries or key storage.
  ///
  /// Prefer this over `sharedPreferencesName` for new code.
  final String? storageNamespace;

  /// The title shown in the biometric authentication prompt.
  final String? biometricPromptTitle;

  /// The subtitle shown in the biometric authentication prompt.
  final String? biometricPromptSubtitle;

  /// Default Android options with standard secure configuration.
  static const AndroidOptions defaultOptions = AndroidOptions();

  @override
  Map<String, String> toMap() => <String, String>{
        'encryptedSharedPreferences': '$_encryptedSharedPreferences',
        'resetOnError': '$_resetOnError',
        'migrateOnAlgorithmChange': '$_migrateOnAlgorithmChange',
        'migrateWithBackup': '$_migrateWithBackup',
        'enforceBiometrics': '$_enforceBiometrics',
        'keyCipherAlgorithm': _keyCipherAlgorithm.name,
        'storageCipherAlgorithm': _storageCipherAlgorithm.name,
        // ignore: deprecated_member_use_from_same_package — legacy support
        'sharedPreferencesName': sharedPreferencesName ?? '',
        'preferencesKeyPrefix': preferencesKeyPrefix ?? '',
        'storageNamespace': storageNamespace ?? '',
        'biometricPromptTitle':
            biometricPromptTitle ?? 'Authenticate to access',
        'biometricPromptSubtitle':
            biometricPromptSubtitle ?? 'Use biometrics or device credentials',
      };

  /// Creates a copy of this AndroidOptions with the given fields replaced.
  AndroidOptions copyWith({
    bool? encryptedSharedPreferences,
    bool? resetOnError,
    bool? migrateOnAlgorithmChange,
    bool? migrateWithBackup,
    bool? enforceBiometrics,
    KeyCipherAlgorithm? keyCipherAlgorithm,
    StorageCipherAlgorithm? storageCipherAlgorithm,
    String? preferencesKeyPrefix,
    @Deprecated(
        'Use storageNamespace instead. sharedPreferencesName only isolates '
        'data storage; storageNamespace provides full isolation including '
        'KeyStore aliases and key storage.')
    String? sharedPreferencesName,
    String? storageNamespace,
    String? biometricPromptTitle,
    String? biometricPromptSubtitle,
  }) =>
      AndroidOptions(
        // ignore: deprecated_member_use_from_same_package — will be removed in v11
        encryptedSharedPreferences:
            encryptedSharedPreferences ?? _encryptedSharedPreferences,
        resetOnError: resetOnError ?? _resetOnError,
        migrateOnAlgorithmChange:
            migrateOnAlgorithmChange ?? _migrateOnAlgorithmChange,
        migrateWithBackup: migrateWithBackup ?? _migrateWithBackup,
        enforceBiometrics: enforceBiometrics ?? _enforceBiometrics,
        keyCipherAlgorithm: keyCipherAlgorithm ?? _keyCipherAlgorithm,
        storageCipherAlgorithm:
            storageCipherAlgorithm ?? _storageCipherAlgorithm,
        // ignore: deprecated_member_use_from_same_package — legacy support
        sharedPreferencesName:
            // ignore: deprecated_member_use_from_same_package — legacy support
            sharedPreferencesName ?? this.sharedPreferencesName,
        preferencesKeyPrefix: preferencesKeyPrefix ?? this.preferencesKeyPrefix,
        storageNamespace: storageNamespace ?? this.storageNamespace,
        biometricPromptTitle: biometricPromptTitle ?? this.biometricPromptTitle,
        biometricPromptSubtitle:
            biometricPromptSubtitle ?? this.biometricPromptSubtitle,
      );
}
