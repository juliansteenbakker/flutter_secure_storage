## 9.2.3
* [iOS] Fix for issue #711: The specified item already exists in the keychain.

## 9.2.2
[iOS, macOS] Fixed an issue which caused the readAll and deleteAll to not work properly.

## 9.2.1
* Fix async race condition bug in storage operations.
* [macOS] Return nil on macOS if key is not found

## 9.2.0
New Features:
* [iOS, macOS] Reintroduced isProtectedDataAvailable.
* Listener functionality via `FlutterSecureStorage().registerListener()`

Bugs Fixed:
* [iOS] Return nil on iOS read if key is not found
* [macOS] Also set kSecUseDataProtectionKeychain on read for macos.

## 9.1.1
Reverts new feature because of breaking changes.
* [iOS, macOS] Added isProtectedDataAvailable, A boolean value that indicates whether content protection is active.

## 9.1.0
New Features:
* [iOS, macOS] Added isProtectedDataAvailable, A boolean value that indicates whether content protection is active.

Improvements:
* [iOS, macOS] Use accessibility option for all operations
* [iOS, macOS] Added privacy manifest
* [iOS] Fixes error when no item exists
* [Linux] Fixed search with schemas fails in cold keyrings
* [Linux] Fixed erase called on null
* [Android] Fixed native Android stacktraces in PlatformExceptions
* [Android] Fixed exception when reading data after boot

## 9.0.0
Breaking changes:
* [Windows] Migrated to FFI with win32 package.

## 8.1.0
* [Android] Upgraded to Gradle 8.
* [Android] Fixed resetOnError not working.
* [Windows] Changed PathNotFoundException to FileSystemException to be backwards compatible with Flutter SDK 2.12.0.
* [Windows] Applied lint suggestions.
* [Linux] Remove and replace libjsoncpp1 dependency.
* [Linux, macOS, Windows, Web] Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 9.0.0
Breaking changes:
* [Windows] Migrated to FFI with win32 package.

## 8.1.0
* [Android] Upgraded to Gradle 8.
* [Android] Fixed resetOnError not working.
* [Windows] Changed PathNotFoundException to FileSystemException to be backwards compatible with Flutter SDK 2.12.0.
* [Windows] Applied lint suggestions.
* [Linux] Remove and replace libjsoncpp1 dependency.
* [Linux, macOS, Windows, Web] Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 8.0.0
Breaking changes:
* [macOS] The minimum macOS version supported is now 10.14.

Other changes:
* [Android] Fixed an issue when Encrypted Shared Preferences failed, the fallback would not handle the data correctly.
* [Windows] Write encrypted data to files instead of the windows credential system.
* [Linux] Fixed an issue with memory management.

## 7.0.2
[macOS] Fix issue with plugin name.

## 7.0.1
[Android] Reverted double initialization of the SharedPreferences because this will break mixed usage of secureSharedPreference on Android.

## 7.0.0
Breaking changes:
* [macOS] The minimum macOS version supported is now 10.13.

Other changes:
* [Android] Fixed double initialization of the SharedPreferences which caused containsKey and other functions to not work properly.
* [macOS] Upgraded codebase to swift which fixed containsKey always returning true.

## 6.1.0
* [iOS] (From 6.1.0-beta.1) Migrated from objective C to Swift. This also fixes issues with containsKey and possibly other issues.
* [Android] Upgrade security-crypto from 1.1.0-alpha03 to 1.1.0-alpha04
* [Android] Fix deprecation warnings.
* [All] Migrated from flutter_lints to lint and applied suggestions.

## 6.1.0-beta.1
* [iOS] Migrated from objective C to Swift. This also fixes issues with containsKey and possibly other issues.

## 6.0.0
* [Android] Upgrade to Android SDK 33.

## 5.1.2
This version reverts some breaking changes of update 5.1.0.
These changes will become available in version 6.0.0
* [Android] Revert upgrade to Android SDK 33.

## 5.1.1
* Example app dependencies updated
* Updated homepage

## 5.1.0
* [Android] You can now select your own key prefix or database name.
* [Android] Upgraded to Android SDK 33.
* [Android] You can now select the keyCipherAlgorithm and storageCipherAlgorithm.
* [Linux] Fixed an issue where no error was being reported if there was something wrong accessing the secret service.
* [macOS] Fixed an memory-leak.
* [macOS] You can now select the same options as for iOS.

## 5.0.2
* [Android] Fixed bug where sharedPreference object was not yet initialized.

## 5.0.1
* [Android] Added java 8 requirement for gradle build.

## 5.0.0
First stable release of flutter_secure_storage for multi-platform!
Please see all beta release notes for changes.

This first release also fixes several stability issues on Android regarding encrypted shared
preferences.

## [5.0.0-beta.5]
* [Linux, iOS & macOS] Add containsKey function.
* [Linux] Fix for use of undeclared identifier 'flutter_secure_storage_linux_plugin_register_with_registrar'

## [5.0.0-beta.4]
* [Windows] Fixed application crashing when key doesn't exists.
* [Web] Added prefix to local storage key when deleting, fixing items that wouldn't delete.

## [5.0.0-beta.3]
* [Android] Add possibility to reset data when an error occurs.
* [Windows] Add readAll, deleteAll and containsKey functions.
* [All] Refactor option defaults.

## [5.0.0-beta.2]
* [Android] Improved EncryptedSharedPreferences by not loading unused Cipher.
* [Android] Removed deprecated classes
* [Web] Improved containsKey function

## [5.0.0-beta.1]
Initial BETA support for macOS, web & Windows. Development is still ongoing so expect some functions to not work correctly!
Please read the readme.md for information about every platform.

* Migrated to a federated project structure. [#254](https://github.com/mogol/flutter_secure_storage/pull/257). Thanks [jhancock4d](https://github.com/jhancock4d)
* Added support for encrypted shared preferences on Android. [#259](https://github.com/mogol/flutter_secure_storage/pull/259)

## [4.2.1]
* Added kSecAttrSynchronizable support by setting IOSOptions.synchronizable  [#51](https://github.com/mogol/flutter_secure_storage/issues/51)
* Changed deprecated jcenter to mavenCentral [#246](https://github.com/mogol/flutter_secure_storage/pull/246)

## [4.2.0]
* Remove Strongbox for Android [225](https://github.com/mogol/flutter_secure_storage/pull/225). Thanks [JordyLangen](https://github.com/JordyLangen).

## [4.1.0]
* Add support for Linux [185](https://github.com/mogol/flutter_secure_storage/pull/185). Thanks [talhabalaj](https://github.com/talhabalaj)
* Improve first-time read speed on Android by not creating cipher when key is not present. Thanks [PieterAelse](https://github.com/PieterAelse)
* Make it possible to customize iOS account name(kSecAttrService). Thanks [klyver](https://github.com/klyver)

## [4.0.0]
* Introduce null-safety. Thanks [Steve Alexander](https://github.com/SteveAlexander)

## [3.3.5]
* Fix thread safety issues in android code to close [161](https://github.com/mogol/flutter_secure_storage/issues/161). Thanks [koskimas](https://github.com/koskimas)

## [3.3.4]
* Fix Android hanging UI on StorageCipher initialization [#116](https://github.com/mogol/flutter_secure_storage/issues/116) by [morrica](https://github.com/morrica)
* Fix crash only observed for v2 apps [#124](https://github.com/mogol/flutter_secure_storage/pull/124) by [lidongze91](https://github.com/lidongze91)
* Fix crash when generating keys in android with RTL locales [#132](https://github.com/mogol/flutter_secure_storage/pull/132) by [iassal](https://github.com/iassal)
* Fix returning the error as String rather than Exception [#134](https://github.com/mogol/flutter_secure_storage/issues/134) by [wytesk133](https://github.com/wytesk133)s
* Fix Android crash onDetachedFromEngine when init fails [#144](https://github.com/mogol/flutter_secure_storage/issues/144) by [iassal](https://github.com/iassal)
* Handle null value at write function [#95](https://github.com/mogol/flutter_secure_storage/issues/95) by [ewertonrp](https://github.com/ewertonrp)
*  Add support for containsKey [#139](https://github.com/mogol/flutter_secure_storage/issues/139) by [iassal](https://github.com/iassal)

## [3.3.3]
* Fix compatibility with non-AndroidX project. [AndroidX Migration](https://flutter.dev/docs/development/androidx-migration) is recommended.

## [3.3.2]
* Migrate to Android v2 embedder.
* Adds support for specifying [iOS Keychain Item Accessibility](https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility?language=objc).

## [3.3.1+2]
* Fix iOS build warning [Issue 30](https://github.com/mogol/flutter_secure_storage/issues/30)

## [3.3.1+1]
* Fix Android Manifest error [Issue 77](https://github.com/mogol/flutter_secure_storage/issues/77) and [Issue 79](https://github.com/mogol/flutter_secure_storage/issues/79). Thanks [nate-eisner](https://github.com/nate-eisner).

## [3.3.1]
* Fix crash without [iOSOptions](https://github.com/mogol/flutter_secure_storage/issues/73).

## [3.3.0]
* Added groupId for iOS keychain sharing. Thanks [Maleandr](https://github.com/Maleandr).
* Fix Gradle version in `gradle-wrapper.properties`. Thanks [blasten](https://github.com/blasten).
* Added minimum sdk requirement on AndroidManifest. Thanks [lidongze91](https://github.com/lidongze91).

## [3.2.1]
* Fix Android 9.0 Pie [KeyStore exception](https://github.com/mogol/flutter_secure_storage/issues/46).

## [3.2.0]
* **Breaking change**. Migrate from the deprecated original Android Support Library to AndroidX. This shouldn't result in any functional changes, but it requires any Android apps using this plugin to [also migrate](https://developer.android.com/jetpack/androidx/migrate) if they're using the original support library. Thanks [I-am-original](https://github.com/I-am-original).
* Enable StrongBox on Android devices that support it. Thanks [bbedward](https://github.com/bbedward).

## [3.1.3]
* Fix Android 9.0 Pie KeyStore exception. Thanks [hacker1024](https://github.com/hacker1024)

## [3.1.2]
* Added recreating secretKey if its decoding failed. Fix for [unwrap key](https://github.com/mogol/flutter_secure_storage/issues/13). Thanks [hnvn](https://github.com/hnvn).

## [3.1.1]
* Suppress warning about unchecked operations when compiling for Android.

## [3.1.0]
* Added `readAll` and `deleteAll`.

## [3.0.0]
* **Breaking change**. Changed payloads encryption for Android from RSA to AES, AES secret key is encrypted with RSA.

## [2.0.0]````
* **Breaking change**. Changed key alias to fix Android 4.4.2 issue. The plugin isn't able to get previous stored data.

## [1.0.0]
* Bump version

## [0.0.1]

* Initial release
