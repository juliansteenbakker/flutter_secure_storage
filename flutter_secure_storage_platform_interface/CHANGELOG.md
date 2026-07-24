## 2.0.2
Remove redundant `./` prefix from part directives.

## [3.0.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_platform_interface-v2.0.2...flutter_secure_storage_platform_interface-v3.0.0) (2026-07-24)


### ⚠ BREAKING CHANGES

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+

### Bug Fixes

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+ ([87198bc](https://github.com/juliansteenbakker/flutter_secure_storage/commit/87198bc22050f5050a90c427f89039156d69690f))
* **darwin:** restore access to items written before 0.3.0's SecAccess… ([4523503](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4523503b3b4e86264252aed7024604a83d5f9399))
* remove redundant ./ prefix from part directives ([cc7018d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/cc7018d15eae56b389348d73f788ae1a03c606c6))
* remove redundant ./ prefix from part directives ([bc15a90](https://github.com/juliansteenbakker/flutter_secure_storage/commit/bc15a90ff36a3c67f87cae57bf0a9ef94051a7f1))
* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))

## 2.0.1
Remove dart:io to support WASM build of web.

## 2.0.0
- This plugin requires a minimum dart sdk of 3.3.0 or higher and a minimum flutter version of 3.19.0.
- Migrated to new analyzer and clean-up code.

## 1.1.2
Adds onCupertinoProtectedDataAvailabilityChanged and isCupertinoProtectedDataAvailable via MethodChannelFlutterSecureStorage to prevent breaking changes.

## 1.1.1
Reverts onCupertinoProtectedDataAvailabilityChanged and isCupertinoProtectedDataAvailable.

## 1.1.0
Adds onCupertinoProtectedDataAvailabilityChanged and isCupertinoProtectedDataAvailable.

## 1.0.2
- Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 1.0.1
- Migrated from flutter_lints to lint and applied suggestions.
- Remove pubspec.lock according to https://dart.dev/guides/libraries/private-files#pubspeclock

## 1.0.0
- Initial release. Contains the interface and an implementation based on method channels.
- Changed effective_dart to flutter_lints
