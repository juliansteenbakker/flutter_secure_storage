part of '../flutter_secure_storage.dart';

/// KeyChain accessibility attributes as defined here:
/// https://developer.apple.com/documentation/security/ksecattraccessible?language=objc
enum KeychainAccessibility {
  /// The data in the keychain can only be accessed when the device
  /// is unlocked. Only available if a passcode is set on the device.
  /// Items with this attribute do not migrate to a new device.
  passcode,

  /// The data in the keychain item can be accessed only while the
  /// device is unlocked by the user.
  unlocked,

  /// The data in the keychain item can be accessed only while the
  /// device is unlocked by the user.
  /// Items with this attribute do not migrate to a new device.
  // ignore: constant_identifier_names
  unlocked_this_device,

  /// The data in the keychain item cannot be accessed after a
  /// restart until the device has been unlocked once by the user.
  // ignore: constant_identifier_names
  first_unlock,

  /// The data in the keychain item cannot be accessed after a
  /// restart until the device has been unlocked once by the user.
  /// Items with this attribute do not migrate to a new device.
  // ignore: constant_identifier_names
  first_unlock_this_device,
}

/// Keychain access control flags that define security conditions for accessing
/// items. These flags can be combined to create complex access control
/// policies.
enum AccessControlFlag {
  /// Constraint to access an item with a passcode.
  devicePasscode,

  /// Constraint to access an item with biometrics (Touch ID/Face ID).
  biometryAny,

  /// Constraint to access an item with the currently enrolled biometrics.
  biometryCurrentSet,

  /// Constraint to access an item with either biometry or passcode.
  userPresence,

  /// Constraint to access an item with a paired watch.
  watch,

  /// Combine multiple constraints with an OR operation.
  or,

  /// Combine multiple constraints with an AND operation.
  and,

  /// Use an application-provided password for encryption.
  applicationPassword,

  /// Enable private key usage for signing operations.
  privateKeyUsage,
}

/// Specific options for Apple platform.
abstract class AppleOptions extends Options {
  /// Creates an instance of `AppleOptions` with configurable parameters
  /// for keychain access and storage behavior.
  const AppleOptions({
    this.accountName = AppleOptions.defaultAccountName,
    this.groupId,
    this.accessibility = KeychainAccessibility.unlocked,
    this.synchronizable = false,
    this.label,
    this.description,
    this.comment,
    this.isInvisible,
    this.isNegative,
    this.creationDate,
    this.lastModifiedDate,
    this.resultLimit,
    this.shouldReturnPersistentReference,
    this.authenticationUIBehavior,
    this.accessControlFlags = const [],
  });

  /// The default account name associated with the keychain items.
  static const defaultAccountName = 'flutter_secure_storage_service';

  /// `kSecAttrService`: **Shared**.
  /// Represents the service or application name associated with the item.
  /// Typically used to group related keychain items.
  final String? accountName;

  /// `kSecAttrAccessGroup`: **Shared**.
  /// Specifies the app group for shared access. Allows multiple apps in the
  /// same app group to access the item.
  ///
  /// Note for macOS: This attribute applies to macOS keychain items only if
  /// you also set a value of true for the kSecUseDataProtectionKeychain key,
  /// the kSecAttrSynchronizable key, or both.
  final String? groupId;

  /// `kSecAttrAccessible`: **Shared**.
  /// Defines the accessibility level of the keychain item. Controls when the
  /// item is accessible
  /// (e.g., when the device is unlocked or after first unlock).
  final KeychainAccessibility? accessibility;

  /// `kSecAttrSynchronizable`: **Shared**.
  /// Indicates whether the keychain item should be synchronized with iCloud.
  /// `true` enables synchronization, `false` disables it.
  final bool synchronizable;

  /// `kSecAttrLabel`: **Unique**.
  /// A user-visible label for the keychain item. Helps identify the item in
  /// keychain management tools.
  final String? label;

  /// `kSecAttrDescription`: **Shared or Unique**.
  /// A description of the keychain item. Can describe a category of items
  /// (shared) or be specific to a single item.
  final String? description;

  /// `kSecAttrComment`: **Shared or Unique**.
  /// A comment associated with the keychain item. Often used for metadata or
  /// debugging information.
  final String? comment;

  /// `kSecAttrIsInvisible`: **Shared or Unique**.
  /// Indicates whether the keychain item is hidden from user-visible lists.
  /// Can apply to all items in a category (shared) or specific items (unique).
  final bool? isInvisible;

  /// `kSecAttrIsNegative`: **Unique**.
  /// Indicates whether the item is a placeholder or a negative entry.
  /// Typically unique to individual keychain items.
  final bool? isNegative;

  /// `kSecAttrCreationDate`: **Unique**.
  /// The creation date of the keychain item. Automatically set by the system
  /// when an item is created.
  final DateTime? creationDate;

  /// `kSecAttrModificationDate`: **Unique**.
  /// The last modification date of the keychain item. Automatically updated
  /// when an item is modified.
  final DateTime? lastModifiedDate;

  /// `kSecMatchLimit`: **Action-Specific**.
  /// Specifies the maximum number of results to return in a query.
  /// For example, `1` for a single result, or `all` for all matching results.
  final int? resultLimit;

  /// `kSecReturnPersistentRef`: **Action-Specific**.
  /// Indicates whether to return a persistent reference to the keychain item.
  /// Used for persistent access across app sessions.
  final bool? shouldReturnPersistentReference;

  /// `kSecUseAuthenticationUI`: **Shared**.
  /// Controls how authentication UI is presented during secure operations.
  /// Determines whether authentication prompts are displayed to the user.
  final String? authenticationUIBehavior;

  /// Keychain access control flags define security conditions for accessing
  /// items. These flags can be combined to create custom security policies.
  ///
  /// ### Using Logical Operators:
  /// - Use `AccessControlFlag.or` to allow access if **any** of the specified
  ///   conditions are met.
  /// - Use `AccessControlFlag.and` to require that **all** specified conditions
  ///   are met.
  ///
  /// **Rules for Combining Flags:**
  /// - Only one logical operator (`or` or `and`) can be used per combination.
  /// - Logical operators should be placed after the security constraints.
  ///
  /// **Supported Flags:**
  /// - `userPresence`: Requires user authentication via biometrics or passcode.
  /// - `biometryAny`: Allows access with any enrolled biometrics.
  /// - `biometryCurrentSet`: Requires currently enrolled biometrics.
  /// - `devicePasscode`: Requires device passcode authentication.
  /// - `watch`: Allows access with a paired Apple Watch.
  /// - `privateKeyUsage`: Enables use of a private key for signing operations.
  /// - `applicationPassword`: Uses an app-defined password for encryption.
  ///
  final List<AccessControlFlag> accessControlFlags;

  @override
  Map<String, String> toMap() => <String, String>{
        if (accountName != null) 'accountName': accountName!,
        if (groupId != null) 'groupId': groupId!,
        if (accessibility != null) 'accessibility': accessibility!.name,
        if (label != null) 'label': label!,
        if (description != null) 'description': description!,
        if (comment != null) 'comment': comment!,
        'synchronizable': '$synchronizable',
        if (isInvisible != null) 'isInvisible': '$isInvisible',
        if (isNegative != null) 'isNegative': '$isNegative',
        if (creationDate != null)
          'creationDate': creationDate!.toIso8601String(),
        if (lastModifiedDate != null)
          'lastModifiedDate': lastModifiedDate!.toIso8601String(),
        if (resultLimit != null) 'resultLimit': resultLimit!.toString(),
        if (shouldReturnPersistentReference != null)
          'shouldReturnPersistentReference': '$shouldReturnPersistentReference',
        if (authenticationUIBehavior != null)
          'authenticationUIBehavior': authenticationUIBehavior!,
        if (accessControlFlags.isNotEmpty)
          'accessControlFlags':
              accessControlFlags.map((e) => e.name).toList().toString(),
      };
}
