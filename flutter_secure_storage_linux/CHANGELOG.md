# Changelog

## [4.0.0-beta.1](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_linux-v3.0.3...flutter_secure_storage_linux-v4.0.0-beta.1) (2026-09-11)


### ⚠ BREAKING CHANGES

* **linux:** previously affected installs stored secrets under whatever incorrect xdg:schema value they happened to compute (stable per app build, but not the intended one). Reads and writes now use the correct "<application id>/FlutterSecureStorage" schema name. The first read after upgrading automatically migrates matching secrets found under any other schema value forward into the correct one; legacy items are left in place, nothing is deleted.

### Bug Fixes

* **linux:** stop the xdg:schema attribute from going stale after relabeling ([#1249](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1249)) ([105f323](https://github.com/juliansteenbakker/flutter_secure_storage/commit/105f323e2bf1c59e36d8780eec31bed4af9a5847))

## [3.0.3](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_linux-v3.0.2...flutter_secure_storage_linux-v3.0.3) (2026-09-11)


### Bug Fixes

* **linux:** skip D-Bus keyring warmup when sandboxed ([#1223](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1223)) ([1e625c9](https://github.com/juliansteenbakker/flutter_secure_storage/commit/1e625c9718b0d301039c3456bf97bbbfbc020ea3))

## [3.0.2](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_linux-v3.0.1...flutter_secure_storage_linux-v3.0.2) (2026-08-06)


### Bug Fixes

* handle missing default keyring on linux ([b39c7c1](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b39c7c1db6c1fe651367031c9d0033d590784de0))
* **linux:** fail closed on orphaned keyring data ([2e720ff](https://github.com/juliansteenbakker/flutter_secure_storage/commit/2e720ff7e6b956a5d1197a5077bb8be39a5d5632))
* **linux:** return structured libsecret error codes ([4691b83](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4691b838519ae91383618120d82fd97a60a35493))

## 3.0.1
- Fixed `deleteKeyring` storing the string `"null"` instead of an empty JSON object `{}`.
- Fixed non-UTF-8 error messages from libsecret causing a `FormatException` on the Dart side; messages are now sanitised before being sent through the method channel.
- Fixed locked or unavailable keyring now surfacing as a catchable `PlatformException` with code `KeyringLocked`.
- Fixed JSON parse errors and other C++ exceptions now surfacing as a `PlatformException` with code `StorageError` instead of sending malformed bytes through the channel.
- Updated README with installation instructions for apt, dnf, pacman, Flatpak, and Snapcraft.

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
