# flutter_secure_storage_darwin

This is the platform-specific implementation of `flutter_secure_storage` for iOS macOS.

## Features

- Secure storage using the Keychain API.
- Fully integrated with iOS and macOS security features.

## Installation

Add the dependency in your `pubspec.yaml` and run `flutter pub get`.

## Configuration

You also need to add Keychain Sharing as capability to your iOS or macOS runner. To achieve this, please add the following in *both* your `(ios/macos)/Runner/DebugProfile.entitlements` *and* `(ios/macos)/Runner/Release.entitlements`.

```
<key>keychain-access-groups</key>
<array/>
```

If you have set your application up to use App Groups then you will need to add the name of the App Group to the `keychain-access-groups` argument above. Failure to do so will result in values appearing to be written successfully but never actually being written at all. For example if your app has an App Group named "aoeu" then your value for above would instead read:

```
<key>keychain-access-groups</key>
<array>
	<string>$(AppIdentifierPrefix)aoeu</string>
</array>
```

If you are configuring this value through XCode then the string you set in the Keychain Sharing section would simply read "aoeu" with XCode appending the `$(AppIdentifierPrefix)` when it saves the configuration.

## Secure Enclave

The `useSecureEnclave` option stores encryption keys inside the device's hardware Secure Enclave, providing hardware-backed protection. Each value is encrypted with a per-item AES key that is itself wrapped by an Enclave-resident EC key. The raw key material never leaves the chip.

Requires iOS 11.3+ or macOS 10.15+. On simulators (which have no Secure Enclave chip) operations silently fall back to standard Keychain storage.

```dart
await storage.write(
  key: 'token',
  value: secret,
  iOptions: const IOSOptions(
    useSecureEnclave: true,
    accessControlFlags: [AccessControlFlag.userPresence],
  ),
  mOptions: const MacOsOptions(
    useSecureEnclave: true,
    accessControlFlags: [AccessControlFlag.userPresence],
  ),
);
```

**Things to know:**

- `useSecureEnclave` is a per-operation option, not a global flag. Pass it on every `read`, `write`, and `delete` call.
- iCloud Keychain sync (`synchronizable`) is ignored for Secure Enclave items. Keys are device-bound and cannot leave the hardware.
- Omitting `accessControlFlags` defaults to `userPresence`, which prompts for Face ID, Touch ID, or device passcode when a key is read.

### Migrating to or from Secure Enclave

Existing items written without `useSecureEnclave` are standard Keychain entries and are not automatically re-encrypted. Set `migrateToSecureEnclave: true` to migrate data when enabling or disabling Secure Enclave. Migration runs once on the first operation after a mode change is detected, and is skipped on subsequent calls once all items are already in the target format.

```dart
// Migrating existing standard Keychain data to Secure Enclave
await storage.read(
  key: 'token',
  iOptions: const IOSOptions(
    useSecureEnclave: true,
    migrateToSecureEnclave: true,
  ),
);

// Migrating back: Secure Enclave to standard Keychain
await storage.read(
  key: 'token',
  iOptions: const IOSOptions(
    useSecureEnclave: false,
    migrateToSecureEnclave: true,
  ),
);
```

**How migration works:**

For each key, the plugin reads the existing value, writes it in the new format, verifies the new item is readable, and only then deletes the old item. A per-key verification failure leaves the original intact, so no data is lost on partial failure.

**Important notes:**

- `migrateToSecureEnclave` defaults to `false`. Opt in explicitly when you are ready to migrate.
- Migration is detected from keychain contents (presence of internal `fss.wrapped.*` companion keys), so it survives app reinstalls and OS cache clears.
- Migration runs synchronously on the first call after enabling the option. For large keystores this may take a moment.

**`resetOnError`:** If migration fails (for example, because the Secure Enclave key was deleted externally), setting `resetOnError: true` deletes all storage data and starts fresh rather than leaving the app stuck. This is destructive and applies only to migration failures, not to ordinary read or write errors.

```dart
iOptions: const IOSOptions(
  useSecureEnclave: true,
  migrateToSecureEnclave: true,
  resetOnError: true, // Wipes all data if migration cannot complete
),
```

## Usage

Refer to the main [flutter_secure_storage README](../flutter_secure_storage/README.md) for common usage instructions.

## License

This project is licensed under the BSD 3 License. See the [LICENSE](../LICENSE) file for details.
