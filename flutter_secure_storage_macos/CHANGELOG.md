## 3.1.2
Fixed an issue which caused the readAll and deleteAll to not work properly.

## 3.1.1
Fixed an issue which caused a platform exception when the key does not exists in the keychain.

## 3.1.0
New Features:
* Added isProtectedDataAvailable, A Boolean value that indicates whether content protection is active.

Improvements:
* Use accessibility option for all operations
* Added privacy manifest

## 3.0.1
Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 3.0.0
Changed minimum macOS version from 10.13 to 10.14 to mach latest Flutter version.

## 2.0.1
Fixed build error.

## 2.0.1
Fixed an issue with the plugin name.

## 2.0.0
- Changed minimum macOS version from 10.11 to 10.13 to mach min Flutter version.
- Upgraded codebase to swift
- Fixed containsKey always returning true

## 1.1.2
Updated flutter_secure_storage_platform_interface to latest version.

## 1.1.1
Fixes a memory leak in the keychain

## 1.1.0
Add containsKey function

## 1.0.0
- Initial macOS implementation
- Removed unused Flutter test and effective_dart dependency