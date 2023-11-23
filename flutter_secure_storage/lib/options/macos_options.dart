part of '../flutter_secure_storage.dart';

/// Specific options for macOS platform.
class MacOsOptions extends AppleOptions {
  const MacOsOptions({
    String? groupId,
    String? accountName = AppleOptions.defaultAccountName,
    KeychainAccessibility accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
  }) : super(
          groupId: groupId,
          accountName: accountName,
          accessibility: accessibility,
          synchronizable: synchronizable,
        );

  static const MacOsOptions defaultOptions = MacOsOptions();

  MacOsOptions copyWith({
    String? groupId,
    String? accountName,
    KeychainAccessibility? accessibility,
    bool? synchronizable,
  }) =>
      MacOsOptions(
        groupId: groupId ?? _groupId,
        accountName: accountName ?? _accountName,
        accessibility: accessibility ?? _accessibility,
        synchronizable: synchronizable ?? _synchronizable,
      );
}
