# Changelog

## [2.1.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_platform_interface-v2.0.3...flutter_secure_storage_platform_interface-v2.1.0) (2026-09-09)


### Features

* add checkUpgradeStatus() to report data lost on a direct major upgrade ([#1243](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1243)) ([fc716ea](https://github.com/juliansteenbakker/flutter_secure_storage/commit/fc716ea7b3973db985d953776107b44b5984f591))

## [2.0.3](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_platform_interface-v2.0.2...flutter_secure_storage_platform_interface-v2.0.3) (2026-08-05)


### Bug Fixes

* remove redundant ./ prefix from part directives ([cc7018d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/cc7018d15eae56b389348d73f788ae1a03c606c6))

## 2.0.2
Remove redundant `./` prefix from part directives.

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
