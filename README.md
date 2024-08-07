# flutter_secure_storage
A Flutter plugin to store data in secure storage:

- [Keychain](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html#//apple_ref/doc/uid/TP30000897-CH203-TP1) is used for iOS
- AES encryption is used for Android. AES secret key is encrypted with RSA and RSA key is stored in [KeyStore](https://developer.android.com/training/articles/keystore.html).
  By default following algorithms are used for AES and secret key encryption: AES/CBC/PKCS7Padding and RSA/ECB/PKCS1Padding
  From Android 6 you can use newer, recommended algoritms:
  AES/GCM/NoPadding and RSA/ECB/OAEPWithSHA-256AndMGF1Padding
  You can set them in Android options like so:
```dart
  AndroidOptions _getAndroidOptions() => const AndroidOptions(
         keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
         storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
      );
```
On devices running Android with version less than 6, plugin will fall back to default implementation. You can change the algorithm, even if you already have some encrypted preferences - they will be re-encrypted using selected algorithms.
Choosing algorithm is irrelevant if you are using EncryptedSharedPreferences as described below.
- With v5.0.0 we can use [EncryptedSharedPreferences](https://developer.android.com/topic/security/data) on Android by enabling it in the Android Options like so:
```dart
  AndroidOptions _getAndroidOptions() => const AndroidOptions(
  encryptedSharedPreferences: true,
);
```
For more information see the example app.
- [`libsecret`](https://wiki.gnome.org/Projects/Libsecret) is used for Linux.

_Note_ KeyStore was introduced in Android 4.3 (API level 18). The plugin wouldn't work for earlier versions.
## Important notice for Web
flutter_secure_storage only works on HTTPS or localhost environments. [Please see this issue for more information.](https://github.com/mogol/flutter_secure_storage/issues/320#issuecomment-976308930)

### WASM support
You can opt-in into the new WASM compatible version of flutter_secure_storage_web by adding the following override in your pubspec.yaml:

```yaml
dependency_overrides:
  flutter_secure_storage_web: ^2.0.0-beta.1
```

## Platform Implementation
Please note that this table represents the functions implemented in this repository and it is possible that changes haven't yet been released on pub.dev

|         | read               | write              | delete             | containsKey        | readAll            | deleteAll          | isCupertinoProtectedDataAvailable | onCupertinoProtectedDataAvailabilityChanged |
|---------|--------------------|--------------------|--------------------|--------------------|--------------------|--------------------|-----------------------------------|---------------------------------------------|
| Android | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |                                   |
| iOS     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:                | :white_check_mark:                          |
| Windows | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |                                   |
| Linux   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |                                   |
| macOS   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:                | :white_check_mark: (on macOS 12 and newer)  |
| Web     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |                                   |

## Getting Started

If not present already, please call WidgetsFlutterBinding.ensureInitialized() in your main before you do anything with the MethodChannel. [Please see this issue  for more info.](https://github.com/mogol/flutter_secure_storage/issues/336)

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

### Configure Web Version

Flutter Secure Storage uses an experimental implementation using WebCrypto. Use at your own risk at this time. Feedback welcome to improve it. The intent is that the browser is creating the private key, and as a result, the encrypted strings in local_storage are not portable to other browsers or other machines and will only work on the same domain.

**It is VERY important that you have HTTP Strict Forward Secrecy enabled and the proper headers applied to your responses or you could be subject to a javascript hijack.**

Please see:

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
- https://www.netsparker.com/blog/web-security/http-security-headers/

### Configure Linux Version

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

### Configure MacOS Version

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

### Configure Windows Version

You need the C++ ATL libraries installed along with the rest of Visual Studio Build Tools. Download them from [here](https://visualstudio.microsoft.com/downloads/?q=build+tools) and make sure the C++ ATL under optional is installed as well.

## Integration Tests

Run the following command from `example` directory

```
flutter drive --target=test_driver/app.dart
```

## Contributing

If you want to contribute, you need to initialise the workspace after cloning the repo with `melos` like this:
```
flutter pub get
melos bootstrap
```
After that, everything should be set up and working!
