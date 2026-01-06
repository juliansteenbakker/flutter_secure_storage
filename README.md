# flutter_secure_storage

[![Pub Version](https://img.shields.io/pub/v/flutter_secure_storage.svg)](https://pub.dev/packages/flutter_secure_storage)
[![Pub Version Prerelease](https://img.shields.io/pub/v/flutter_secure_storage.svg?include_prereleases)](https://pub.dev/packages/flutter_secure_storage)
[![Build Status](https://github.com/mogol/flutter_secure_storage/actions/workflows/code-integration.yml/badge.svg)](https://github.com/juliansteenbakker/flutter_secure_storage/actions/workflows/code-integration.yml)
[![Code Quality: Very Good Analysis](https://img.shields.io/badge/style-very_good_analysis-B22C89.svg)](https://pub.dev/packages/very_good_analysis)
[![Codecov](https://codecov.io/gh/juliansteenbakker/flutter_secure_storage/graph/badge.svg?token=UUVTJ6MS4A)](https://codecov.io/gh/juliansteenbakker/flutter_secure_storage)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/juliansteenbakker)](https://github.com/sponsors/juliansteenbakker)

A Flutter plugin to securely store sensitive data in a key-value pair format using platform-specific secure storage solutions. It supports Android, iOS, macOS, Windows, and Linux.

## Features

- **Secure Data Storage**: Uses Keychain for iOS/macOS, custom secure ciphers with optional biometric authentication for Android, and platform-specific secure mechanisms for Windows, Linux, and Web.
- **Encryption**: Encrypts data before storing it using platform-specific encryption (RSA OAEP + AES-GCM on Android by default).
- **Cross-Platform**: Works seamlessly across Android, iOS, macOS, Windows, Linux, and Web.
- **Biometric Authentication**: Optional biometric authentication support on Android (API 23+) and iOS/macOS.
- **Customizable Options**: Configure encryption algorithms, accessibility attributes, biometric requirements, and more.

## Important notice for Android
Version 10.0.0 introduces a major security update with custom cipher implementations. The deprecated Jetpack Security library's `encryptedSharedPreferences` is no longer recommended.

**Key Changes:**
- New default ciphers: RSA OAEP (key cipher) + AES-GCM (storage cipher)
- New `AndroidOptions()` and `AndroidOptions.biometric()` constructors
- Automatic migration from old ciphers via `migrateOnAlgorithmChange` (enabled by default)
- Minimum Android SDK is now 23 (Android 6.0+)
- Enhanced biometric authentication with graceful degradation

## Important notice for Web
flutter_secure_storage only works on HTTPS or localhost environments. [Please see this issue for more information.](https://github.com/juliansteenbakker/flutter_secure_storage/issues/320#issuecomment-976308930)

## Installation

If not present already, please call WidgetsFlutterBinding.ensureInitialized() in your main before you do anything with the MethodChannel. [Please see this issue  for more info.](https://github.com/juliansteenbakker/flutter_secure_storage/issues/336)

Add the dependency in your `pubspec.yaml` file:

```
dependencies:
flutter_secure_storage: ^<latest_version>
```

Then run:

`flutter pub get`

## Usage

### Import the Package


`import 'package:flutter_secure_storage/flutter_secure_storage.dart';`

### Create an Instance

```dart
// Default secure storage - Uses RSA OAEP + AES-GCM (recommended)
final storage = FlutterSecureStorage();

// Or with explicit Android options
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions(),
);

// Biometric storage with graceful degradation
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions.biometric(
    enforceBiometrics: false, // Works without biometrics
    biometricPromptTitle: 'Authenticate to access data',
  ),
);

// Strict biometric enforcement (requires device security)
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions.biometric(
    enforceBiometrics: true, // Requires biometric/PIN/pattern
    biometricPromptTitle: 'Authentication Required',
  ),
);
```

### Write Data

`await storage.write(key: 'username', value: 'flutter_user');`

### Read Data

`String? username = await storage.read(key: 'username');`

### Delete Data

`await storage.delete(key: 'username');`

### Delete All Data

`await storage.deleteAll();`

### Check for Key Existence

`bool containsKey = await storage.containsKey(key: 'username');`

## Configuration

Each platform provides its own set of configuration options to tailor secure storage behavior. For example, on iOS, the `IOSOptions` class includes an `accessibility` option that determines when the app can access secure values stored in the Keychain.

The `accessibility` option allows you to specify conditions under which secure values are accessible. For instance:

- `first_unlock`: Enables access to secure values after the device is unlocked for the first time after a reboot.
- `first_unlock_this_device`: Allows access to secure values only after the device is unlocked for the first time since installation on this device.
- `unlocked` (default): Values are accessible only when the device is unlocked.

Here’s an example of configuring the accessibility option on iOS:

```dart
final options = IOSOptions(accessibility: KeychainAccessibility.first_unlock);
await storage.write(key: key, value: value, iOptions: options);
```

By setting `accessibility`, you can control when secure values are accessible, enhancing security and usability for your app on iOS. Similar platform-specific options are available for other platforms as well.

### Android

#### Disabling Auto Backup

_Note_ By default Android backups data on Google Drive. It can cause exception `java.security.InvalidKeyException: Failed to unwrap key`.
You need to:

- [Disable autobackup](https://developer.android.com/guide/topics/data/autobackup#EnablingAutoBackup), [details](https://github.com/juliansteenbakker/flutter_secure_storage/issues/13#issuecomment-421083742)
- [Exclude sharedprefs](https://developer.android.com/guide/topics/data/autobackup#IncludingFiles) used by `FlutterSecureStorage`, [details](https://github.com/juliansteenbakker/flutter_secure_storage/issues/43#issuecomment-471642126)

Add the following to your `android/app/src/main/AndroidManifest.xml`:

```xml
<application
  android:allowBackup="false"
  ...>
</application>
```

#### Encryption Options (Version 10.0.0+)

Version 10 introduces new cipher options and biometric support. Choose the configuration that fits your security requirements:

| Constructor                                          | Key Cipher                            | Storage Cipher    | Biometric Support | Description                                                                                                                                          |
|------------------------------------------------------|---------------------------------------|-------------------|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AndroidOptions()`                                   | RSA/ECB/OAEPWithSHA-256AndMGF1Padding | AES/GCM/NoPadding | No                | **Default.** Standard secure storage with RSA OAEP key wrapping. Strong authenticated encryption without biometrics. Recommended for most use cases. |
| `AndroidOptions.biometric(enforceBiometrics: false)` | AES/GCM/NoPadding                     | AES/GCM/NoPadding | Optional          | KeyStore-based with optional biometric authentication. Gracefully degrades if biometrics unavailable.                                                |
| `AndroidOptions.biometric(enforceBiometrics: true)`  | AES/GCM/NoPadding                     | AES/GCM/NoPadding | Required          | KeyStore-based requiring biometric/PIN authentication. Throws error if device security not available. Requires API 28+ for biometric enforcement.    |

#### Custom Cipher Combinations (Advanced)

For advanced users, all combinations below are supported using the `AndroidOptions()` constructor with custom parameters:

| Key Cipher Algorithm                    | Storage Cipher Algorithm | Implementation  | Biometric Support                  |
|-----------------------------------------|--------------------------|-----------------|------------------------------------|
| `RSA_ECB_PKCS1Padding`                  | `AES_CBC_PKCS7Padding`   | RSA-wrapped AES | No                                 |
| `RSA_ECB_PKCS1Padding`                  | `AES_GCM_NoPadding`      | RSA-wrapped AES | No                                 |
| `RSA_ECB_OAEPwithSHA_256andMGF1Padding` | `AES_CBC_PKCS7Padding`   | RSA-wrapped AES | No                                 |
| `RSA_ECB_OAEPwithSHA_256andMGF1Padding` | `AES_GCM_NoPadding`      | RSA-wrapped AES | No                                 |
| `AES_GCM_NoPadding`                     | `AES_CBC_PKCS7Padding`   | KeyStore AES    | Optional (via `enforceBiometrics`) |
| `AES_GCM_NoPadding`                     | `AES_GCM_NoPadding`      | KeyStore AES    | Optional (via `enforceBiometrics`) |

**Notes:**
- **RSA key ciphers** wrap the AES encryption key with RSA. No biometric support.
- **AES key cipher** stores the key directly in Android KeyStore. Supports optional biometric authentication.
- **`enforceBiometrics` parameter** (default: `false`):
  - `false`: Gracefully degrades if biometrics unavailable
  - `true`: Strictly requires device security (PIN/pattern/biometric), throws exception if unavailable

#### Biometric Authentication

Flutter Secure Storage supports biometric authentication (fingerprint, face recognition, etc.) on Android API 23+.

##### Required Permissions

To use biometric authentication, add the following permission to your `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC"/>
```

For devices running Android 9.0 (API 28) and above, `USE_BIOMETRIC` is the recommended permission.

For backward compatibility with devices running Android 6.0 - 8.1 (API 23-27), you may also need:

```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT"/>
```

##### Using Biometric Authentication

You can enable biometric authentication using the `AndroidOptions.biometric()` constructor:

```dart
// Optional biometric authentication (graceful degradation)
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions.biometric(
    enforceBiometrics: false, // Default - works without biometrics
    biometricPromptTitle: 'Unlock to access your data',
    biometricPromptSubtitle: 'Use fingerprint or face unlock',
  ),
);

// Strict biometric enforcement (requires device security)
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions.biometric(
    enforceBiometrics: true, // Requires biometric/PIN/pattern
    biometricPromptTitle: 'Biometric authentication required',
  ),
);
```

**Note:** When `enforceBiometrics: true`, the app will throw an exception if the device has no PIN, pattern, password, or biometric enrolled.

##### Requirements

- **API Level**: Android 6.0 (API 23) minimum for basic encryption
- **API Level**: Android 9.0 (API 28) minimum for enforced biometric authentication
- **Device Security**: Device must have a PIN, pattern, password, or biometric enrolled (when using `enforceBiometrics: true`)
- **Permissions**: `USE_BIOMETRIC` permission in AndroidManifest.xml

#### Migration from Version 9.x

Version 10 automatically migrates data from older cipher algorithms when `migrateOnAlgorithmChange: true` (enabled by default). If you were using `encryptedSharedPreferences` in version 9, the data will be automatically migrated to the new cipher implementation.

To disable automatic migration:

```dart
final storage = FlutterSecureStorage(
  aOptions: AndroidOptions(
    migrateOnAlgorithmChange: false,
  ),
);
```

### macOS & iOS
#### Secure Enclave (iOS/macOS)

You can opt-in to hardware-backed protection using the Secure Enclave by enabling `useSecureEnclave` in `AppleOptions` (iOS/macOS). When enabled, values are encrypted with a per-item AES key that is wrapped by an Enclave-backed private key. Access control prompts (Face ID/Touch ID/passcode) are enforced according to your `accessControlFlags`.

Example:

```dart
final storage = FlutterSecureStorage();

await storage.write(
  key: 'token',
  value: 'secret',
  iOptions: IOSOptions(
    useSecureEnclave: true,
    accessControlFlags: const [
      AccessControlFlag.userPresence, // require Face ID/Touch ID or passcode
    ],
  ),
  mOptions: MacOsOptions(
    useSecureEnclave: true,
    accessControlFlags: const [AccessControlFlag.userPresence],
  ),
);
```

Notes:
- If Secure Enclave is unavailable (simulator or devices without Enclave), the plugin gracefully falls back to storing the value using standard Keychain with your configured access control flags.
- `synchronizable` is ignored for Enclave-backed flows (items are device-bound).
- On macOS, `kSecUseDataProtectionKeychain` remains enabled when available.

You also need to add Keychain Sharing as capability to your macOS runner. To achieve this, please add the following in *both* your `macos/Runner/DebugProfile.entitlements` *and* `macos/Runner/Release.entitlements` for macOS or for iOS `ios/Runner/DebugProfile.entitlements` *and* `ios/Runner/Release.entitlements`.

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

### Web

Flutter Secure Storage uses an experimental implementation using WebCrypto. Use at your own risk at this time. Feedback welcome to improve it. The intent is that the browser is creating the private key, and as a result, the encrypted strings in local_storage are not portable to other browsers or other machines and will only work on the same domain.

**It is VERY important that you have HTTP Strict Forward Secrecy enabled and the proper headers applied to your responses or you could be subject to a javascript hijack.**

Please see:

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
- https://www.netsparker.com/blog/web-security/http-security-headers/

#### application-specific key option

On the web, all keys are stored in LocalStorage. flutter_secure_storage has an option for the web to wrap this stored key with an application-specific key to make it more difficult to analyze.

```dart
final _storage = const FlutterSecureStorage(
  webOptions: WebOptions(
    wrapKey: '${your_application_specific_key}',
    wrapKeyIv: '${your_application_specific_iv}',
  ),
);
```

### Windows

You need the C++ ATL libraries installed along with the rest of Visual Studio Build Tools. Download them from [here](https://visualstudio.microsoft.com/downloads/?q=build+tools) and make sure the C++ ATL under optional is installed as well.

### Linux

You need `libsecret-1-dev` on your machine to build the project, and `libsecret-1-0` to run the application (add it as a dependency after packaging your app). If you using snapcraft to build the project use the following

```yaml
parts:
  uet-lms:
    source: .
    plugin: flutter
    flutter-target: lib/main.dart
    build-packages:
      - libsecret-1-dev
    stage-packages:
      - libsecret-1-0
```

Apart from `libsecret` you also need a keyring service, for that you need either [`gnome-keyring`](https://wiki.gnome.org/Projects/GnomeKeyring) (for Gnome users) or [`kwalletmanager`](https://wiki.archlinux.org/title/KDE_Wallet) (for KDE users) or other light provider like [`secret-service`](https://github.com/yousefvand/secret-service).

## Integration Tests

To run the integration tests, navigate to the `example` directory and execute the following command:

`flutter drive --target=test_driver/app.dart`

This will launch the integration tests specified in the `test_driver` directory.

## Contributing

We welcome contributions to this project! To set up your workspace after cloning the repository, follow these steps:

1. Fetch the Flutter dependencies:
   `flutter pub get`

2. Activate `melos`:
   `dart pub global activate melos`

3. (Optional) Add pub executables to your path:
   `export PATH="$PATH":"$HOME/.pub-cache/bin"`

4. Bootstrap the workspace with `melos`:
   `melos bootstrap`

This will prepare the project for development by linking and configuring all required dependencies.

## API Reference

For a complete list of available methods and configuration options, refer to the [API documentation](https://pub.dev/documentation/flutter_secure_storage/latest/).

## License

This project is licensed under the BSD 3 License. See the [LICENSE](LICENSE) file for details.
