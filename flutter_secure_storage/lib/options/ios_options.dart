part of '../flutter_secure_storage.dart';

/// Specific options for iOS platform.
/// Currently there are no specific ios options available, but only shared
/// options from apple options.
class IOSOptions extends AppleOptions {
  /// Creates an instance of `IosOptions` with configurable parameters
  /// for keychain access and storage behavior.
  const IOSOptions({
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
  });

  /// A predefined `IosOptions` instance with default settings.
  ///
  /// This can be used as a fallback or when no specific options are required.
  static const IOSOptions defaultOptions = IOSOptions();

  @override
  Map<String, String> toMap() => <String, String>{
        ...super.toMap(),
      };
}
