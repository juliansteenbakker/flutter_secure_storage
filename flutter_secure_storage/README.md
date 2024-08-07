# flutter_secure_storage

## Note: usage of encryptedSharedPreference
When using the `encryptedSharedPreferences` parameter on Android, make sure to pass the option to the
constructor instead of the function like so:
```dart
  AndroidOptions _getAndroidOptions() => const AndroidOptions(
        encryptedSharedPreferences: true,
      );
final storage = FlutterSecureStorage(aOptions: _getAndroidOptions());
```
This will prevent errors due to mixed usage of `encryptedSharedPreferences`.
For more info, [see this issue](https://github.com/mogol/flutter_secure_storage/issues/487#issuecomment-1346244368).

## Info
A Flutter plugin to store data in secure storage:

- [Keychain](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html#//apple_ref/doc/uid/TP30000897-CH203-TP1) is used for iOS
- AES encryption is used for Android. AES secret key is encrypted with RSA and RSA key is stored in [KeyStore](https://developer.android.com/training/articles/keystore.html)
- With V5.0.0 we can use [EncryptedSharedPreferences](https://developer.android.com/topic/security/data) on Android by enabling it in the Android Options like so:
```dart
  AndroidOptions _getAndroidOptions() => const AndroidOptions(
        encryptedSharedPreferences: true,
      );
```
  For more information see the example app.
- [`libsecret`](https://wiki.gnome.org/Projects/Libsecret) is used for Linux.

_Note_ KeyStore was introduced in Android 4.3 (API level 18). The plugin wouldn't work for earlier versions.

## Getting Started

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// Create storage
final storage = FlutterSecureStorage();

// Read value
String value = await storage.read(key: key);

// Read all values
Map<String, String> allValues = await storage.readAll();

// Delete value
await storage.delete(key: key);

// Delete all
await storage.deleteAll();

// Write value
await storage.write(key: key, value: value);

```

This allows us to be able to fetch secure values while the app is backgrounded, by specifying first_unlock or first_unlock_this_device. The default if not specified is unlocked.
An example:

```dart
final options = IOSOptions(accessibility: KeychainAccessibility.first_unlock);
await storage.write(key: key, value: value, iOptions: options);
```

### Configure Android version

In `[project]/android/app/build.gradle` set `minSdkVersion` to >= 18.

```
android {
    ...

    defaultConfig {
        ...
        minSdkVersion 18
        ...
    }

}
```

_Note_ By default Android backups data on Google Drive. It can cause exception java.security.InvalidKeyException:Failed to unwrap key.
You need to

- [disable autobackup](https://developer.android.com/guide/topics/data/autobackup#EnablingAutoBackup), [details](https://github.com/mogol/flutter_secure_storage/issues/13#issuecomment-421083742)
- [exclude sharedprefs](https://developer.android.com/guide/topics/data/autobackup#IncludingFiles) `FlutterSecureStorage` used by the plugin, [details](https://github.com/mogol/flutter_secure_storage/issues/43#issuecomment-471642126)

## Configure Web Version

Flutter Secure Storage uses an experimental implementation using WebCrypto. Use at your own risk at this time. Feedback welcome to improve it. The intent is that the browser is creating the private key, and as a result, the encrypted strings in local_storage are not portable to other browsers or other machines and will only work on the same domain.

**It is VERY important that you have HTTP Strict Forward Secrecy enabled and the proper headers applied to your responses or you could be subject to a javascript hijack.**

Please see:

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
- https://www.netsparker.com/blog/web-security/http-security-headers/

## Configure Linux Version

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

## Configure Windows Version

**Note** The current implementation does not support readAll and deleteAll and is subject to change.

## Configure MacOS Version

You also need to add Keychain Sharing as capability to your macOS runner. To achieve this, please add the following in *both* your `macos/Runner/DebugProfile.entitlements` *and* `macos/Runner/Release.entitlements` (you need to change both files).

```
<key>keychain-access-groups</key>
<array/>
```

## Integration Tests

Run the following command from `example` directory

```
flutter drive --target=test_driver/app.dart
```
