## 3.0.1
- Fixed `deleteKeyring` storing the string `"null"` instead of an empty JSON object `{}`.
- Fixed non-UTF-8 error messages from libsecret causing a `FormatException` on the Dart side; messages are now sanitised before being sent through the method channel.
- Fixed locked or unavailable keyring now surfacing as a catchable `PlatformException` with code `KeyringLocked`.
- Fixed JSON parse errors and other C++ exceptions now surfacing as a `PlatformException` with code `StorageError` instead of sending malformed bytes through the channel.
- Updated README with installation instructions for apt, dnf, pacman, Flatpak, and Snapcraft.

## [4.0.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_linux-v3.0.1...flutter_secure_storage_linux-v4.0.0) (2026-07-24)


### ⚠ BREAKING CHANGES

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+

### Bug Fixes

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+ ([87198bc](https://github.com/juliansteenbakker/flutter_secure_storage/commit/87198bc22050f5050a90c427f89039156d69690f))
* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))

## 3.0.0
- Fixed whitespace deprecation warning.
- Reverted json.dump with indentations due to problems. If still needed, pin version to 2.x

## 2.0.1
Adds application ID to cmake file

## 2.0.0
- This plugin requires a minimum dart sdk of 3.3.0 or higher and a minimum flutter version of 3.19.0.
- Updated documentation

## 1.2.3
- Adds application ID to cmake file

## 1.2.2
- Fix json.dump with indentations 

## 1.2.1
- Fixed search with schemas fails in cold keyrings
- Fixed erase called on null

## 1.2.0
- Remove and replace libjsoncpp1 dependency
- Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 1.1.3
Fixed a memory management issue

## 1.1.2
Updated flutter_secure_storage_platform_interface to latest version.

## 1.1.1
Fixed an issue where no error was being reported if there was something wrong accessing the secret service.

## 1.1.0
Add containsKey function.

## 1.0.0
- Initial Linux implementation
- Removed unused Flutter test and effective_dart dependency
