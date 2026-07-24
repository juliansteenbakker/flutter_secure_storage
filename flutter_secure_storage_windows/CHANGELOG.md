## 4.2.2
Fixed `deleteAll` and `containsKey` not acquiring the mutex lock, which could cause data races under concurrent access.

## [5.0.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_windows-v4.2.2...flutter_secure_storage_windows-v5.0.0) (2026-07-24)


### ⚠ BREAKING CHANGES

* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40

### Features

* native tests for windows ([b9ab979](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b9ab979acecf95e592443ced34c946f8ca648f87))
* native tests for windows ([112e15f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/112e15f2475a2f7db16aa2c4934934a20b622561))
* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40 ([e62e90f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e62e90f4f656f4bd7d1e88cfd6f987b94171d161))


### Bug Fixes

* concurrent operations ([cd2ec24](https://github.com/juliansteenbakker/flutter_secure_storage/commit/cd2ec24628013cb7c5619b0c4608df296b4284b2))
* increase coverage on windows ([d5c4e0a](https://github.com/juliansteenbakker/flutter_secure_storage/commit/d5c4e0abf30b467cbb9381b24636380b988db26f))
* lint ([d2ca5b4](https://github.com/juliansteenbakker/flutter_secure_storage/commit/d2ca5b4ec188d14caec5b15f37c3bed52293d7da))
* lint ([f0a47cd](https://github.com/juliansteenbakker/flutter_secure_storage/commit/f0a47cd401b59f2d12706eacc4a34ec734a7dfc3))
* lock on deleteAll and containsKey ([306f761](https://github.com/juliansteenbakker/flutter_secure_storage/commit/306f7610593f67b736151d9de4dbdf76b719366b))
* lock on deleteAll and containsKey ([5b772f3](https://github.com/juliansteenbakker/flutter_secure_storage/commit/5b772f39b1ced4bd3eb62169e8d0a2795136e8b1))
* more tests ([09ddc01](https://github.com/juliansteenbakker/flutter_secure_storage/commit/09ddc011828b3f843f5dabb57f23544bf11e8d96))
* native test build issues ([df5eb7d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/df5eb7d453799f7459456d54a6985ddf9b007006))
* native tests ([c26e003](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c26e003a41e793f2216291cd3680e30f0f66de23))
* regenerate cmakelists for windows ([0aa65ad](https://github.com/juliansteenbakker/flutter_secure_storage/commit/0aa65ad46c485d8313b50db86bd8c09795cfcc1d))
* unit tests for windows ([b5db170](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b5db170f05c5e3429107f3e6a134b219fba175de))
* update DPAPI FFI calls for win32 6.0.0 compatibility ([51f377a](https://github.com/juliansteenbakker/flutter_secure_storage/commit/51f377a32ad2996df328c8dc0adf2d026213c94b))
* update DPAPI FFI calls for win32 6.0.0 compatibility ([cf024d9](https://github.com/juliansteenbakker/flutter_secure_storage/commit/cf024d9f81949e82db3009f5e5ab48d4664f1aaa))
* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))
* windows concurrent operations ([00480bb](https://github.com/juliansteenbakker/flutter_secure_storage/commit/00480bbe4e7ad26ba65c27785bdd8a9f0d541875))

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
