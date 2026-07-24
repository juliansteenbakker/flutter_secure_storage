## 2.1.1
- Fix potential key skipping in `readAll` when storage is modified concurrently during async decryption by collecting keys synchronously before awaiting.

## [3.0.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_web-v2.1.1...flutter_secure_storage_web-v3.0.0) (2026-07-24)


### ⚠ BREAKING CHANGES

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+

### Bug Fixes

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+ ([87198bc](https://github.com/juliansteenbakker/flutter_secure_storage/commit/87198bc22050f5050a90c427f89039156d69690f))
* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))

## 2.1.0
- Updated code style
- Add check for secure context, since operations are only allowed with secure context.

## 2.0.0
Stable release containing all changes from beta releases, which are:
- This plugin requires a minimum dart sdk of 3.3.0 or higher and a minimum flutter version of 3.19.0.
- Migrate away from `html` to `web`
- Remove `js` in favor of using js-interop
- Update web dependency support to support <2.0.0 instead of <1.0.0.

Other changes:
- Migrated from lint to very_good_analysis and clean-up code.

## 2.0.0-beta.2
Update web dependency support to support <2.0.0 instead of <1.0.0.

## 2.0.0-beta.1
- Migrate away from `html` to `web`
- Remove `js` in favor of using js-interop

## 1.2.1
Reverts onCupertinoProtectedDataAvailabilityChanged and isCupertinoProtectedDataAvailable.

## 1.2.0
Updated flutter_secure_storage_platform_interface to latest version.

## 1.2.0
Updated flutter_secure_storage_platform_interface to latest version.

## 1.1.2
- Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 1.1.1
Updated flutter_secure_storage_platform_interface to latest version.

## 1.1.0
- Migrated from flutter_lints to lint and applied suggestions.
- Remove pubspec.lock according to https://dart.dev/guides/libraries/private-files#pubspeclock

## 1.0.2
- Fix issue with delete key

## 1.0.1
- Fix issue with containsKey

## 1.0.0
- Initial Release of Web Implementation
- Migrated to flutter_lints
