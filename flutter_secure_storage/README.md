# flutter_secure_storage

This is the platform-specific implementation of `flutter_secure_storage` for Android and iOS.

## Features

- Secure storage using Keychain (iOS) and Encrypted Shared Preferences with Tink (Android).
- Platform-specific options for encryption and accessibility.

## Installation

Add the dependency in your `pubspec.yaml` and run `flutter pub get`.

### Example Usage

```dart
// Default secure storage - Uses RSA OAEP + AES-GCM (recommended)
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions(),
);

// Or simply use the default
final storage = FlutterSecureStorage();

// Biometric storage with graceful degradation
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions.biometric(
    enforceBiometrics: false, // Default - works without biometrics
    biometricPromptTitle: 'Authenticate',
  ),
);

// Strict biometric enforcement
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions.biometric(
    enforceBiometrics: true, // Requires biometric/PIN
    biometricPromptTitle: 'Authentication Required',
  ),
);

// Custom combination (for advanced users only)
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions(
    keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding, // Legacy RSA
    storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
  ),
);
```

## Configuration

### Android

1. Disable Google Drive backups to avoid key-related exceptions:
    - Add the required settings in your `AndroidManifest.xml`.

2. Exclude shared preferences used by the plugin:
    - Follow the linked documentation for further details.

#### Encryption Options

| Constructor                                          | Key Cipher                            | Storage Cipher    | Biometric Support | Min API           | Description                                                                                                                                          |
|------------------------------------------------------|---------------------------------------|-------------------|-------------------|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AndroidOptions()`                                   | RSA/ECB/OAEPWithSHA-256AndMGF1Padding | AES/GCM/NoPadding | No                | 23 (Android 6.0+) | **Default.** Standard secure storage with RSA OAEP key wrapping. Strong authenticated encryption without biometrics. Recommended for most use cases. |
| `AndroidOptions.biometric(enforceBiometrics: false)` | AES/GCM/NoPadding                     | AES/GCM/NoPadding | Optional          | 23 (Android 6.0+) | KeyStore-based with optional biometric authentication. Gracefully degrades if biometrics unavailable.                                                |
| `AndroidOptions.biometric(enforceBiometrics: true)`  | AES/GCM/NoPadding                     | AES/GCM/NoPadding | Required          | 28 (Android 9.0+) | KeyStore-based requiring biometric/PIN authentication. Throws error if device security not available.                                                |

#### Custom Cipher Combinations

All combinations below are supported when using the advanced `AndroidOptions()` constructor:

| Key Cipher Algorithm                    | Storage Cipher Algorithm | Implementation  | Biometric Support                  | Min API |
|-----------------------------------------|--------------------------|-----------------|------------------------------------|---------|
| `RSA_ECB_PKCS1Padding`                  | `AES_CBC_PKCS7Padding`   | RSA-wrapped AES | No                                 | 1       |
| `RSA_ECB_PKCS1Padding`                  | `AES_GCM_NoPadding`      | RSA-wrapped AES | No                                 | 23      |
| `RSA_ECB_OAEPwithSHA_256andMGF1Padding` | `AES_CBC_PKCS7Padding`   | RSA-wrapped AES | No                                 | 23      |
| `RSA_ECB_OAEPwithSHA_256andMGF1Padding` | `AES_GCM_NoPadding`      | RSA-wrapped AES | No                                 | 23      |
| `AES_GCM_NoPadding`                     | `AES_CBC_PKCS7Padding`   | KeyStore AES    | Optional (via `enforceBiometrics`) | 23      |
| `AES_GCM_NoPadding`                     | `AES_GCM_NoPadding`      | KeyStore AES    | Optional (via `enforceBiometrics`) | 23      |

**Notes:**
- **RSA key ciphers** wrap the AES encryption key with RSA. No biometric support.
- **AES key cipher** stores the key directly in Android KeyStore. Supports optional biometric authentication.
- **`enforceBiometrics` parameter** (default: `false`):
    - `false`: Gracefully degrades if biometrics unavailable (stores without authentication)
    - `true`: Strictly requires device security (PIN/pattern/biometric), throws exception if unavailable
- When using `AES_GCM_NoPadding` key cipher, the implementation automatically selects:
    - `StorageCipherImplementationAES23` for KeyStore-based encryption (supports biometrics)
    - Falls back to no authentication if `enforceBiometrics=false` and device has no security

### iOS

You also need to add Keychain Sharing as capability to your iOS runner. To achieve this, please add the following in *both* your `ios/Runner/DebugProfile.entitlements` *and* `ios/Runner/Release.entitlements`.

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

## Usage

Refer to the main [flutter_secure_storage README](../README.md) for common usage instructions.

## License

This project is licensed under the BSD 3 License. See the [LICENSE](../LICENSE) file for details.
