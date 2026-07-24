## 4.2.2
Fixed `deleteAll` and `containsKey` not acquiring the mutex lock, which could cause data races under concurrent access.

## [5.0.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_windows-v4.2.2...flutter_secure_storage_windows-v5.0.0) (2026-07-24)


### ⚠ BREAKING CHANGES

* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40

### Features

* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40 ([e62e90f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e62e90f4f656f4bd7d1e88cfd6f987b94171d161))


### Bug Fixes

* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))

## 4.2.1
Fix concurrent read/write operations causing data loss or a `PathAccessException` on Windows (issue #634).

## 4.2.0
Fix DPAPI FFI calls for compatibility with `win32` 6.0.0.

## 4.1.0
Upgrades deprecated member usage of win32.

## 4.0.0
- This plugin requires a minimum dart sdk of 3.3.0 or higher and a minimum flutter version of 3.19.0.
- Migrated to new analyzer and clean-up code.
- Migrates to `win32` version 5.5.4 to support Dart 3.4 / Flutter 3.22.0.

## 3.1.2
Reverts onCupertinoProtectedDataAvailabilityChanged and isCupertinoProtectedDataAvailable.

## 3.1.1
Updated flutter_secure_storage_platform_interface to latest version.

## 3.1.0
Fixed CompanyName and CompanyProduct on Windows are ignored when the lang-charset in the Runner.rc file is not 040904e4

## 3.0.0
- Migrated to win32 package replacing C.
- Changed PathNotFoundException to FileSystemException to be backwards compatible with Flutter SDK 2.12.0
- Applied lint suggestions

## 2.1.1
Revert changes made in version 2.1.0 due to breaking changes.
These changes will be republished under a new major version number 3.0.0.

## 2.1.0
- Changed PathNotFoundException to FileSystemException to be backwards compatible with Flutter SDK 2.12.0
- Applied lint suggestions

## 2.0.0
Write encrypted data to files instead of the windows credential system.

## 1.1.3
Updated flutter_secure_storage_platform_interface to latest version.

## 1.1.2
- Silently ignore errors when deleting keys that don't exist

## 1.1.1
- Fix application crash when key doesn't exists.

## 1.1.0
Features
- Add readAll, deleteAll and containsKey functions.

Bugfixes
- Fix implementation of delete operation to allow null value.

## 1.0.0
- Initial Windows implementation
