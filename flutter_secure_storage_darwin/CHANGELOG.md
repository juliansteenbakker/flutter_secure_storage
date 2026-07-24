## 0.4.1
- Fixed items written by versions prior to 0.3.0 becoming unreadable (and subsequent writes failing with `errSecDuplicateItem`) when no `accessControlFlags` are set. The 0.3.0 fix for `kSecAttrSynchronizable` being dropped caused `read`, `readAll` and `containsKey` to stop querying the legacy `kSecAttrAccessControl` storage envelope that those items were written under; they now fall back to it automatically. ([#1158](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1158))

## [1.0.0](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage_darwin-v0.4.1...flutter_secure_storage_darwin-v1.0.0) (2026-07-24)


### ⚠ BREAKING CHANGES

* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40

### Features

* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40 ([e62e90f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e62e90f4f656f4bd7d1e88cfd6f987b94171d161))


### Bug Fixes

* align macOS options keys in darwin plugin ([4d501dd](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4d501ddc56b1ad18b3a43841e94cacbe4fb78979))
* align macOS options keys in darwin plugin ([4689ae5](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4689ae5c7d11c83f9253d16d47325fc5effb0899))
* **darwin:** restore access to items written before 0.3.0's SecAccess… ([4523503](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4523503b3b4e86264252aed7024604a83d5f9399))
* **darwin:** restore access to items written before 0.3.0's SecAccessControl envelope change ([2323266](https://github.com/juliansteenbakker/flutter_secure_storage/commit/2323266c5703deb85b7ecc08b4d6219c5581cd6d)), closes [#1158](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1158)
* ios 12 build ([564d35d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/564d35d5460603bbf818e154e0e55e747cad8ab9))
* kSecAttrSynchronizable silently dropped when no access control flags are set ([bd52c9c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/bd52c9c77c98fdc9e11fb77d595797f10de4164c))
* kSecAttrSynchronizable silently dropped when no access control flags are set ([b3e0147](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b3e01473a8f84a92bcdcdb7d60c533d1b6882297))
* lint tips ([6b59cc2](https://github.com/juliansteenbakker/flutter_secure_storage/commit/6b59cc284276056f1cb5b17ecb0c9f18828e6123))
* macos plugin registration ([4c4424c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4c4424c2a9307c2e3e2fc387c88e61bb5574b0dd))
* missing changelog entries ([1dcad37](https://github.com/juliansteenbakker/flutter_secure_storage/commit/1dcad379fe0fc22ed331118fe875ab26d724d116))
* native tests ([c26e003](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c26e003a41e793f2216291cd3680e30f0f66de23))
* only add kSecUseDataProtectionKeychain if param is set to true ([7633b98](https://github.com/juliansteenbakker/flutter_secure_storage/commit/7633b983d7c8bd6b1913652ad321aa1ed6ae712e))
* only add kSecUseDataProtectionKeychain if param is set to true ([70559ab](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70559abcc2837e4ec96ee507d983cbfc7bf83eda))
* raised minimum iOS deployment target from 12.0 to 13.0 to fix Sw… ([bef0a85](https://github.com/juliansteenbakker/flutter_secure_storage/commit/bef0a852d94457d1170bb8b442ddd9ed33fd0a30))
* raised minimum iOS deployment target from 12.0 to 13.0 to fix Swift compiler errors when building with Swift Package Manager ([e3da0b6](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e3da0b61b07498070e60645b519a5f5b14762d7e))
* remove warning on privacy manifest ([4a46329](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4a463298db3809c73a3ae22429705a53a4824325))
* remove warning on privacy manifest ([9df8f7c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/9df8f7c1b88c3c2ee19ccc6df369c67023b28ec9))
* revert build to ios 12, exclude secure enclave for ios 12, add ios 12 ci check ([7522eb0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/7522eb0fe8dec67361748207097ae23b3ef893dd))
* secStoreAvailabilitySink not called ([8b37ddd](https://github.com/juliansteenbakker/flutter_secure_storage/commit/8b37ddd0ccef3d7623e3ff3798797e3ed117b126))
* tests for secStoreAvailabilitySink visibility ([c22a7e0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c22a7e08ccc5a4b71b19aabf7dce96f608015b9d))
* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))

## 0.4.0
- Raised minimum iOS deployment target from 12.0 to 13.0 to fix Swift compiler errors when building with Swift Package Manager. CryptoKit (used for Secure Enclave support) requires iOS 13.0+.

## 0.3.2
- Fixed `secStoreAvailabilitySink` not being called when protected data availability changes.
- Fixed `kSecUseDataProtectionKeychain` being added to Keychain queries unconditionally; it is now only set when `useDataProtectionKeychain` is explicitly enabled.

## 0.3.1
- Fixed iOS build by updating availability annotation for Secure Enclave methods from `iOS 11.3` to `iOS 13.0`.

## 0.3.0
- Added `useSecureEnclave` support for iOS and macOS to store encryption keys in the device's Secure Enclave for hardware-backed security.
- Use shared `LAContext` to reuse biometric authentication across Secure Enclave operations, avoiding double authentication prompts.
- Secure Enclave keys now use hardcoded `.privateKeyUsage` access control, preventing "ACL operation is not allowed" errors.

**Fixes:**
- Fixed `kSecAttrSynchronizable` being silently dropped when no access control flags are set.
- Fixed `readAll` to correctly return Secure Enclave items.
- Fixed macOS options keys alignment with iOS options.
- Added plain-text fallback when a Secure Enclave wrapped key is missing.

## 0.2.0
- Remove keys regardless of synchronizable state or accessibility constraints.

## 0.1.1
 - Fix warnings with Privacy Manifest

## 0.1.0
This package combines flutter_secure_storage_macos together with the ios part of flutter_secure_storage.

Other changes:
- Code has been rebuild from the ground up
- Lots of missing attributes have been added to the IOSOptions and MacOsOptions classes.
