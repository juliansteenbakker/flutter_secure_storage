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
    KeychainAccessibility accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
  })  : _groupId = groupId,
        _accessibility = accessibility,
        _accountName = accountName,
        _synchronizable = synchronizable;

  static const defaultAccountName = 'flutter_secure_storage_service';

  final String? _groupId;
  final String? _accountName;
  final KeychainAccessibility _accessibility;
  final bool _synchronizable;

  @override
  Map<String, String> toMap() => <String, String>{
        'accessibility': describeEnum(_accessibility),
        if (_accountName != null) 'accountName': _accountName!,
        if (_groupId != null) 'groupId': _groupId!,
        'synchronizable': '$_synchronizable',
      };
}
