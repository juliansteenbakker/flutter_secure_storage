part of '../flutter_secure_storage.dart';

/// Specific options for macOS platform.
/// Extends `AppleOptions` and adds the `usesDataProtectionKeychain` parameter.
class MacOsOptions extends AppleOptions {
  /// Creates an instance of `MacosOptions` with configurable parameters
  /// for keychain access and storage behavior.
  const MacOsOptions({
    super.accountName,
    super.groupId,
    super.accessibility,
    super.synchronizable,
    super.label,
    super.description,
    super.comment,
    super.isInvisible,
    super.isNegative,
    super.creationDate,
    super.lastModifiedDate,
    super.resultLimit,
    super.shouldReturnPersistentReference,
    super.authenticationUIBehavior,
    super.accessControlFlags,
    this.usesDataProtectionKeychain = true,
  });

  /// `kSecUseDataProtectionKeychain` (macOS only): **Shared**.
  /// Indicates whether the macOS data protection keychain is used.
  /// Not applicable on iOS.
  final bool usesDataProtectionKeychain;

  /// A predefined `MacosOptions` instance with default settings.
  ///
  /// This can be used as a fallback or when no specific options are required.
  static const MacOsOptions defaultOptions = MacOsOptions();

  @override
  Map<String, String> toMap() => <String, String>{
        ...super.toMap(),
        'usesDataProtectionKeychain': '$usesDataProtectionKeychain',
      };
}
