part of '../flutter_secure_storage.dart';
// Documentation ignored because enums will be removed in a later release
//ignore_for_file: public_member_api_docs
//ignore_for_file: constant_identifier_names
//ignore_for_file: deprecated_member_use_from_same_package

enum KeyCipherAlgorithm {
  RSA_ECB_PKCS1Padding,
  RSA_ECB_OAEPwithSHA_256andMGF1Padding,
  AES_GCM_NoPadding,
}

enum StorageCipherAlgorithm {
  AES_CBC_PKCS7Padding,
  AES_GCM_NoPadding,
  AES_GCM_NoPadding_BIOMETRIC,
}

/// Specific options for Android platform.
class AndroidOptions extends Options {
  const AndroidOptions({
    @Deprecated('EncryptedSharedPreferences will always be true, and will be '
        'removed in the next release')
    bool encryptedSharedPreferences = true,
    bool resetOnError = false,
    KeyCipherAlgorithm keyCipherAlgorithm =
        KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
    StorageCipherAlgorithm storageCipherAlgorithm =
        StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
    this.sharedPreferencesName,
    this.preferencesKeyPrefix,
    this.biometricPromptTitle,
    this.biometricPromptSubtitle,
    this.shouldUseBiometrics = false,
  })  : _encryptedSharedPreferences = encryptedSharedPreferences,
        _resetOnError = resetOnError,
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
  final bool shouldUseBiometrics;

  static const AndroidOptions defaultOptions = AndroidOptions();

  @override
  Map<String, String> toMap() => <String, String>{
        'encryptedSharedPreferences': '$_encryptedSharedPreferences',
        'resetOnError': '$_resetOnError',
        'keyCipherAlgorithm': _keyCipherAlgorithm.name,
        'storageCipherAlgorithm': _storageCipherAlgorithm.name,
        'sharedPreferencesName': sharedPreferencesName ?? '',
        'preferencesKeyPrefix': preferencesKeyPrefix ?? '',
        'biometricPromptTitle': biometricPromptTitle ??
            'Authenticate to access',
        'biometricPromptSubtitle': biometricPromptSubtitle ??
            'Use biometrics or device credentials',
        'shouldUseBiometrics': '$shouldUseBiometrics',

      };

  AndroidOptions copyWith({
    bool? encryptedSharedPreferences,
    bool? resetOnError,
    KeyCipherAlgorithm? keyCipherAlgorithm,
    StorageCipherAlgorithm? storageCipherAlgorithm,
    String? preferencesKeyPrefix,
    String? sharedPreferencesName,
  }) =>
      AndroidOptions(
        encryptedSharedPreferences:
            encryptedSharedPreferences ?? _encryptedSharedPreferences,
        resetOnError: resetOnError ?? _resetOnError,
        keyCipherAlgorithm: keyCipherAlgorithm ?? _keyCipherAlgorithm,
        storageCipherAlgorithm:
            storageCipherAlgorithm ?? _storageCipherAlgorithm,
        sharedPreferencesName: sharedPreferencesName,
        preferencesKeyPrefix: preferencesKeyPrefix,
      );
}
