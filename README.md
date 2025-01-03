# flutter_secure_storage

[![Pub](https://img.shields.io/pub/v/flutter_secure_storage.svg)](https://pub.dev/packages/flutter_secure_storage)
[![style: lint](https://img.shields.io/badge/style-lint-4BC0F5.svg)](https://pub.dev/packages/lint)
[![flutter_secure_storage](https://github.com/mogol/flutter_secure_storage/actions/workflows/flutter.yml/badge.svg)](https://github.com/mogol/flutter_secure_storage/actions/workflows/flutter.yml)
[![flutter_secure_storage](https://github.com/mogol/flutter_secure_storage/actions/workflows/flutter_drive.yml/badge.svg)](https://github.com/mogol/flutter_secure_storage/actions/workflows/flutter_drive.yml)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/juliansteenbakker)](https://github.com/sponsors/juliansteenbakker)

A Flutter plugin to securely store sensitive data in a key-value pair format using platform-specific secure storage solutions. It supports Android, iOS, macOS, Windows, and Linux.

---

## Features

- **Secure Data Storage**: Uses Keychain for iOS, Encrypted Shared Preferences via Tink for Android, and secure mechanisms on other supported platforms.
- **Encryption**: Encrypts data before storing it in the underlying storage system.
- **Cross-Platform**: Works seamlessly across multiple platforms.
- **Customizable Options**: Set accessibility attributes, key expiration, and more.

---

## Important notice for Web
flutter_secure_storage only works on HTTPS or localhost environments. [Please see this issue for more information.](https://github.com/mogol/flutter_secure_storage/issues/320#issuecomment-976308930)

### WASM support
You can opt-in into the new WASM compatible version of flutter_secure_storage_web by adding the following override in your pubspec.yaml:

```yaml
dependency_overrides:
  flutter_secure_storage_web: ^2.0.0-beta.2
```

---

## Installation

If not present already, please call WidgetsFlutterBinding.ensureInitialized() in your main before you do anything with the MethodChannel. [Please see this issue  for more info.](https://github.com/mogol/flutter_secure_storage/issues/336)

Add the dependency in your `pubspec.yaml` file:

```
dependencies:
flutter_secure_storage: ^<latest_version>
```

Then run:

`flutter pub get`

---

## Usage

### Import the Package


`import 'package:flutter_secure_storage/flutter_secure_storage.dart';`

### Create an Instance

`final storage = FlutterSecureStorage();`

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

---

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

_Note_ By default Android backups data on Google Drive. It can cause exception java.security.InvalidKeyException:Failed to unwrap key.
You need to

- [disable autobackup](https://developer.android.com/guide/topics/data/autobackup#EnablingAutoBackup), [details](https://github.com/mogol/flutter_secure_storage/issues/13#issuecomment-421083742)
- [exclude sharedprefs](https://developer.android.com/guide/topics/data/autobackup#IncludingFiles) `FlutterSecureStorage` used by the plugin, [details](https://github.com/mogol/flutter_secure_storage/issues/43#issuecomment-471642126)

Add the following to your `android/app/src/main/AndroidManifest.xml`:

<application
android:allowBackup="false"
...>
</application>

### iOS

Set the `Keychain` accessibility options in the `Info.plist` file (if needed):

<key>keychain-access-groups</key>
<array>
<string>$(AppIdentifierPrefix)com.example.flutterSecureStorageExample</string>
</array>

### macOS

You also need to add Keychain Sharing as capability to your macOS runner. To achieve this, please add the following in *both* your `macos/Runner/DebugProfile.entitlements` *and* `macos/Runner/Release.entitlements` (you need to change both files).

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

You need `libsecret-1-dev` and `libjsoncpp-dev` on your machine to build the project, and `libsecret-1-0` and `libjsoncpp1` to run the application (add it as a dependency after packaging your app). If you using snapcraft to build the project use the following

```yaml
parts:
  uet-lms:
    source: .
    plugin: flutter
    flutter-target: lib/main.dart
    build-packages:
      - libsecret-1-dev
      - libjsoncpp-dev
    stage-packages:
      - libsecret-1-0
      - libjsoncpp-dev
```

Apart from `libsecret` you also need a keyring service, for that you need either `gnome-keyring` (for Gnome users) or `ksecretsservice` (for KDE users) or other light provider like [`secret-service`](https://github.com/yousefvand/secret-service).

---

## Integration Tests

To run the integration tests, navigate to the `example` directory and execute the following command:

`flutter drive --target=test_driver/app.dart`

This will launch the integration tests specified in the `test_driver` directory.

---

## Contributing

We welcome contributions to this project! To set up your workspace after cloning the repository, follow these steps:

1. Fetch the Flutter dependencies:
   `flutter pub get`

2. Bootstrap the workspace with `melos`:
   `melos bootstrap`

This will prepare the project for development by linking and configuring all required dependencies.

---

## API Reference

For a complete list of available methods and configuration options, refer to the [API documentation](https://pub.dev/documentation/flutter_secure_storage/latest/).

---

## License

This project is licensed under the BSD 3 License. See the [LICENSE](LICENSE) file for details.
