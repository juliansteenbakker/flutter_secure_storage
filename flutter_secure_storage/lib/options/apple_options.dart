part of '../flutter_secure_storage.dart';

/// KeyChain accessibility attributes as defined here:
/// https://developer.apple.com/documentation/security/ksecattraccessible?language=objc
enum KeychainAccessibility {
  /// The data in the keychain can only be accessed when the device is unlocked.
  /// Only available if a passcode is set on the device.
  /// Items with this attribute do not migrate to a new device.
  passcode,

  /// The data in the keychain item can be accessed only while the device is unlocked by the user.
  unlocked,

  /// The data in the keychain item can be accessed only while the device is unlocked by the user.
  /// Items with this attribute do not migrate to a new device.
  unlocked_this_device,

  /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
  first_unlock,

  /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
  /// Items with this attribute do not migrate to a new device.
  first_unlock_this_device,
}

abstract class AppleOptions extends Options {
  const AppleOptions({
    String? groupId,
    String? accountName = AppleOptions.defaultAccountName,
    KeychainAccessibility? accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
  })  : _groupId = groupId,
        _accessibility = accessibility,
        _accountName = accountName,
        _synchronizable = synchronizable;

  static const defaultAccountName = 'flutter_secure_storage_service';

  /// A key with a value that’s a string indicating the access group the item is in.
  ///
  /// (kSecAttrAccessGroup)
  final String? _groupId;

  /// A key whose value is a string indicating the item's service.
  ///
  /// (kSecAttrService)
  final String? _accountName;

  /// A key with a value that indicates when the keychain item is accessible.
  /// https://developer.apple.com/documentation/security/ksecattraccessible?language=swift
  /// (kSecAttrAccessible)
  final KeychainAccessibility? _accessibility;

  /// A key with a value that’s a string indicating whether the item synchronizes through iCloud.
  ///
  /// (kSecAttrSynchronizable)
  final bool _synchronizable;

  @override
  Map<String, String> toMap() => <String, String>{
        if (_accessibility != null)
          // TODO: Update min SDK from 2.12 to 2.15 in new major version to fix this deprecation warning
          // ignore: deprecated_member_use
          'accessibility': describeEnum(_accessibility!),
        if (_accountName != null) 'accountName': _accountName!,
        if (_groupId != null) 'groupId': _groupId!,
        'synchronizable': '$_synchronizable',
      };
}
