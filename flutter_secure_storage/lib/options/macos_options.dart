part of '../flutter_secure_storage.dart';

/// Specific options for macOS platform.
class MacOsOptions extends AppleOptions {
  const MacOsOptions({
    String? groupId,
    String? accountName = AppleOptions.defaultAccountName,
    KeychainAccessibility? accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
    bool useDataProtectionKeyChain = true,
  })  : _useDataProtectionKeyChain = useDataProtectionKeyChain,
        super(
          groupId: groupId,
          accountName: accountName,
          accessibility: accessibility,
          synchronizable: synchronizable,
        );

  static const MacOsOptions defaultOptions = MacOsOptions();

  final bool _useDataProtectionKeyChain;

  MacOsOptions copyWith({
    String? groupId,
    String? accountName,
    KeychainAccessibility? accessibility,
    bool? synchronizable,
    bool? useDataProtectionKeyChain,
  }) =>
      MacOsOptions(
        groupId: groupId ?? _groupId,
        accountName: accountName ?? _accountName,
        accessibility: accessibility ?? _accessibility,
        synchronizable: synchronizable ?? _synchronizable,
        useDataProtectionKeyChain:
            useDataProtectionKeyChain ?? _useDataProtectionKeyChain,
      );

  @override
  Map<String, String> toMap() => <String, String>{
        ...super.toMap(),
        'useDataProtectionKeyChain': '$_useDataProtectionKeyChain',
      };
}
