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
