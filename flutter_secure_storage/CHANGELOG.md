## 11.0.0-beta.1

**Breaking changes**

items deprecated in v10 have been removed. 
Any data saved using deprecated algorithms or features will be unusable after this upgrade. If you used a version prior to v10, upgrade to v10 first so existing data is migrated.

### Android

- Removed `KeyCipherAlgorithm.RSA_ECB_PKCS1Padding`. Upgrade to v10 first so existing data is migrated to `RSA_ECB_OAEPwithSHA_256andMGF1Padding` before upgrading to v11.
- Removed `StorageCipherAlgorithm.AES_CBC_PKCS7Padding`. Upgrade to v10 first so existing data is migrated to `AES_GCM_NoPadding` before upgrading to v11.
- Removed `encryptedSharedPreferences` parameter from `AndroidOptions` and `AndroidOptions.biometric`. The Jetpack Security (EncryptedSharedPreferences) backend is no longer supported; any remaining data was automatically migrated to custom cipher storage in v10.
- Removed `sharedPreferencesName` from `AndroidOptions`. Use `storageNamespace` instead for full namespace isolation.
- Raised `minSdk` to 24 and `compileSdk` to 37. Flutter 3.35 raised its own Android minimum to API 24, making API 23 support unverifiable with any supported Flutter version. The legacy AES-CBC cipher path that supported API 21-22 has been removed.

## [12.0.0-beta.1](https://github.com/juliansteenbakker/flutter_secure_storage/compare/flutter_secure_storage-v11.0.0-beta.1...flutter_secure_storage-v12.0.0-beta.1) (2026-07-24)


### ⚠ BREAKING CHANGES

* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+
* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40

### Features

* add AndroidBiometricType option to restrict authentication to strong biometrics only ([301194f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/301194ff2d9eb7312b091d3caf76b1c5888664e7))
* add requireBiometricConfirmation option to AndroidOptions ([7f5f7de](https://github.com/juliansteenbakker/flutter_secure_storage/commit/7f5f7de0ea98a6482c02e768faf7c82c2e5b959b))
* add requireBiometricConfirmation option to AndroidOptions ([97be582](https://github.com/juliansteenbakker/flutter_secure_storage/commit/97be58254a3125c7e4c4d340de505a609674b5d6))
* agp 9 for example app ([4ed9f7c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4ed9f7c7166dc3e4db2d237dedb96d0309417d31))
* android rewrite containing secure ciphers, biometric support and migration tools ([7bb2540](https://github.com/juliansteenbakker/flutter_secure_storage/commit/7bb254034dd2d139bff4939a20da95f634668e73))
* linux native tests ([e3521ee](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e3521eea3426229dc84805cbcdb463866006fefd))
* linux native tests ([24a0d6c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/24a0d6cf7d4a2f6ccf1c4eeddd1a9cf4b79db500))
* migrate to agp 9 ([e0ca0ac](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e0ca0acabf626440aaea0112eab83009e3960b45))
* migrate to agp 9 ([b96bb88](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b96bb880dec666ef0a97125c7db25ed5dd1fae9f))
* native android tests ([b885cb6](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b885cb668c6b4cc045fcae0881409a4bfc573e49))
* native tests ([d7958e1](https://github.com/juliansteenbakker/flutter_secure_storage/commit/d7958e136f920377ce68977955281eac6e62ef6b))
* native tests for windows ([b9ab979](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b9ab979acecf95e592443ced34c946f8ca648f87))
* native tests for windows ([112e15f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/112e15f2475a2f7db16aa2c4934934a20b622561))
* remove v10 deprecated members, upgrade win32 to 6.0, darwin to 0.40 ([e62e90f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e62e90f4f656f4bd7d1e88cfd6f987b94171d161))
* robolectric for native android testing ([de76b73](https://github.com/juliansteenbakker/flutter_secure_storage/commit/de76b73cdc0bb6fbf0a5f71d3fbd3b4dbaf14540))
* tests for web ([38b6bce](https://github.com/juliansteenbakker/flutter_secure_storage/commit/38b6bce154d78d8abe277e736f034a3a3224fd00))
* tests for web ([fd6517e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/fd6517e9093d83dbef3b8fcea0397681efd39af4))
* v11 remove deprecated members ([01e1e99](https://github.com/juliansteenbakker/flutter_secure_storage/commit/01e1e9983bc63dd43d41f862cebbdff72c4ee690))


### Bug Fixes

* add check for migration of encrypted shared prefs ([4a04d4f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4a04d4f396d3195888ba7d25860ae9ce63c91041))
* add delete key functions for reset ([2604603](https://github.com/juliansteenbakker/flutter_secure_storage/commit/2604603afdfa7585c4b80a6da21e7f79b214a781))
* add release note ([55dd5a7](https://github.com/juliansteenbakker/flutter_secure_storage/commit/55dd5a7c16f222208a06314825d20941f5485eb2))
* added changelog entries ([6b9e8f4](https://github.com/juliansteenbakker/flutter_secure_storage/commit/6b9e8f44db1d369036188d4d41549486b926a1cf))
* align android default to the flutter one ([688caba](https://github.com/juliansteenbakker/flutter_secure_storage/commit/688cabafb5ccbd945bd3b07e9be6354d88c28a6c))
* align android default to the flutter one ([9019fc9](https://github.com/juliansteenbakker/flutter_secure_storage/commit/9019fc96a7372bde7fe344fd57621e4a2206a753))
* analyzer issues for deprecated member usage ([1c6a63a](https://github.com/juliansteenbakker/flutter_secure_storage/commit/1c6a63ad4a21c44d56f4c0920583a0c0f3005d5b))
* **android:** align biometric prompt option keys ([69ac97f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/69ac97f92b7a3532766d939fdd3d3dd02be8e4e3))
* **android:** align biometric prompt option keys ([a5945fa](https://github.com/juliansteenbakker/flutter_secure_storage/commit/a5945fa6456c1a330010e221f5cf6304d4b3a43a))
* **android:** guard MethodRunner payload to prevent NPE crash ([4184030](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4184030f33ecc3808a45b71697ca3be3b43bd1b6))
* **android:** isolate FlutterSecureStorage instances per sharedPreferencesName ([63a9d3b](https://github.com/juliansteenbakker/flutter_secure_storage/commit/63a9d3b067cf8d1ef3090062515a82253802976c))
* **android:** raise minSdk to 24, overhaul CI and workspace for Flutter 3.35+ ([87198bc](https://github.com/juliansteenbakker/flutter_secure_storage/commit/87198bc22050f5050a90c427f89039156d69690f))
* api to 23 again ([78da24b](https://github.com/juliansteenbakker/flutter_secure_storage/commit/78da24b789f10d7439f3796140bd94ccb7993cba))
* api to 23 again ([f562156](https://github.com/juliansteenbakker/flutter_secure_storage/commit/f562156afec730eea3e0a9f400989e89b60dccb2))
* badge ([35da5ae](https://github.com/juliansteenbakker/flutter_secure_storage/commit/35da5ae16dcfc76edfcb24de092a9ed4f151f52e))
* better mapping of legacy names ([e07a365](https://github.com/juliansteenbakker/flutter_secure_storage/commit/e07a36507484ecaf1275e7139173b18f2cfafef4))
* biometric permission for example app ([4589c07](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4589c07317d44da18d2d2ebc337dafeacd8b3c10))
* biometrics when no security is setup ([29887fe](https://github.com/juliansteenbakker/flutter_secure_storage/commit/29887fe7c8b48d48e8426e026fbbd5a812f7b5fe))
* change initialize method visibility from protected to public ([efb60b2](https://github.com/juliansteenbakker/flutter_secure_storage/commit/efb60b2597b1ca400e87d2c316fb467f95976835))
* codecov rules ([b68458f](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b68458fd1433e329660202e7850af2cc9fba5819))
* continue on android isolate storage instances per shared preferences names by making key unique ([3562f28](https://github.com/juliansteenbakker/flutter_secure_storage/commit/3562f2872a11209d25063f2e91465c73f2e56238))
* correct notation for minSdk, bump versions ([ce9f0ad](https://github.com/juliansteenbakker/flutter_secure_storage/commit/ce9f0ada7c7fd13beb1846f8c4b26dca0ddfd3cf))
* crash on biometric failure ([7859abd](https://github.com/juliansteenbakker/flutter_secure_storage/commit/7859abda0b2528fc710b06d8391411fbf9511fc1))
* crash on biometric failure ([5805ed0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/5805ed0b286dd542f3186601bfd5539993b7c19e))
* **darwin:** restore access to items written before 0.3.0's SecAccess… ([4523503](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4523503b3b4e86264252aed7024604a83d5f9399))
* default resetOnError = true, ([8a669e6](https://github.com/juliansteenbakker/flutter_secure_storage/commit/8a669e68e79b61a4de67e9fc1040a0feeca9e03e))
* defer preferences assignment until cipher initialization succeeds ([0b9ed95](https://github.com/juliansteenbakker/flutter_secure_storage/commit/0b9ed95a19a072bb5c3e3cb18f53fdc77c6a93a7))
* deprecation warnings ([f3ca199](https://github.com/juliansteenbakker/flutter_secure_storage/commit/f3ca199959c29817c9f581486bc012a797b40210))
* doc for changes ([7e81db4](https://github.com/juliansteenbakker/flutter_secure_storage/commit/7e81db4bcf3918143a7c73aafd3a04726e9e299f))
* doc naming ([b9c7ff2](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b9c7ff255039d1d916c9ddbe80f37ab1234c1bbe))
* example app on sdk 23 ([f87a9a9](https://github.com/juliansteenbakker/flutter_secure_storage/commit/f87a9a989cce01e199bb99a5e81221725ebfa32f))
* format ([a73d59d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/a73d59d9075fef8794bc10bb5b1acd32be2c62a9))
* formating ([4e9ba05](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4e9ba05031ca836b07885daaf43c247f56268a40))
* integration test for algorithm migration ([c7809d0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c7809d0bccb9bd154c03334e8e25e698e6ce5d00))
* integration test for migration path ([995f717](https://github.com/juliansteenbakker/flutter_secure_storage/commit/995f7179074efb522be2f70e4ec9da79edacbf53))
* introduce namespaced config source ([1d32af1](https://github.com/juliansteenbakker/flutter_secure_storage/commit/1d32af19abb1cf7aecd984468fd55c75a5319e4d))
* Keep old migration as fallback when migrateWithBackup=false ([414812a](https://github.com/juliansteenbakker/flutter_secure_storage/commit/414812a5b16ef70070ba53ae749a567e959da867))
* lint issues ([88f45f0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/88f45f051fc3c558dfebf471398fbad26cbebb28))
* linux doc typo, add more details section ([25ac868](https://github.com/juliansteenbakker/flutter_secure_storage/commit/25ac8688c2042bf9af2ac1abb023ffba48f8e037))
* linux locked keyring ([d5ab2cb](https://github.com/juliansteenbakker/flutter_secure_storage/commit/d5ab2cbce4a8f7b0ac26edda5772ec9f54930793))
* lock on deleteAll and containsKey ([d70cef0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/d70cef0a270408bfb9cb53ffe521e0deddc11c8a))
* macos plugin registration ([4c4424c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4c4424c2a9307c2e3e2fc387c88e61bb5574b0dd))
* make key alias configurable ([b39214d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b39214d938fdcdafd529090edc7b92a72f7d7c41))
* merge conflicts with develop ([c1445d2](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c1445d26b032e456b657645a4cd658acc915281c))
* merge conflicts with develop, migrate to NamespacedConfigSource ([476aabe](https://github.com/juliansteenbakker/flutter_secure_storage/commit/476aabe16b51016bf4dfa7fcdc31f870b720cfa8))
* migration from 9.2.4 non shared preferences ([8fdf841](https://github.com/juliansteenbakker/flutter_secure_storage/commit/8fdf8415e68e7a1483dca761319cd083d611c222))
* migration from 9.2.4 non shared preferences with custom cipher ([c7378c3](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c7378c3dc893493c71c09cff20329948c8df2774))
* min sdk ([d5239f8](https://github.com/juliansteenbakker/flutter_secure_storage/commit/d5239f86cb8d09c3546ec0fa08c422ad9fedaec5))
* missing changelog entries ([1dcad37](https://github.com/juliansteenbakker/flutter_secure_storage/commit/1dcad379fe0fc22ed331118fe875ab26d724d116))
* missing tests for migration backup ([c573dbf](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c573dbf09319aebfad65bbcf403c1554e1cced01))
* missing tests, explain exclusion on some classes ([1f29b5c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/1f29b5c51c15c6a82bab1e1c8d9d631cfe4d8a05))
* native test build issues ([df5eb7d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/df5eb7d453799f7459456d54a6985ddf9b007006))
* native tests ([c26e003](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c26e003a41e793f2216291cd3680e30f0f66de23))
* ndk version for ([096ede1](https://github.com/juliansteenbakker/flutter_secure_storage/commit/096ede1241494e6fb46b5274455ddb64d393ef4e))
* overwriting config after initialization ([db46556](https://github.com/juliansteenbakker/flutter_secure_storage/commit/db465560aa8c65c61859e6f463c237baeb010642))
* pin very_good_analysis for breaking changes ([593383b](https://github.com/juliansteenbakker/flutter_secure_storage/commit/593383bf3f585e3d50b099727db506bdcb83abd5))
* pin very_good_analysis for breaking changes ([90c37a3](https://github.com/juliansteenbakker/flutter_secure_storage/commit/90c37a317e9cbefc46104554fbbd536d4ba62370))
* preservedCount was incremented by iterating dataSource entries, but when dataSource is empty the count stays 0 even though _MIGRATED markers exist in configSource, causing keyStorage to be incorrectly deleted ([cc0d932](https://github.com/juliansteenbakker/flutter_secure_storage/commit/cc0d9323fa0f4d755e139ada45f697371122e307))
* race condition in test ([8d82d9d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/8d82d9db453dcc413f40c2e70f5105fbd58f5d5c))
* regenerate example app for windows ([62561dc](https://github.com/juliansteenbakker/flutter_secure_storage/commit/62561dc940ecc35c9ef7945668cd9f9bedb82e59))
* release of v10.1.0 ([997c9c0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/997c9c0c7e4d62a6140a671599eea38d62e02ead))
* remaining uncovered lines ([589b805](https://github.com/juliansteenbakker/flutter_secure_storage/commit/589b8058df68ec42cd702cebb567cc144f8d4f3d))
* remaining uncovered lines ([63ffef2](https://github.com/juliansteenbakker/flutter_secure_storage/commit/63ffef20b9b9c9e531dae1aac56991becf10cbeb))
* remove all deprecated members, update tests accordingly ([a114531](https://github.com/juliansteenbakker/flutter_secure_storage/commit/a1145311e49d7ea7306db9b07bde9669d3174fff))
* remove deprecated andorid unit tests ([8be6f26](https://github.com/juliansteenbakker/flutter_secure_storage/commit/8be6f265f403bab44c9c50f387128852541b8458))
* remove redundant ./ prefix from part directives ([cc7018d](https://github.com/juliansteenbakker/flutter_secure_storage/commit/cc7018d15eae56b389348d73f788ae1a03c606c6))
* remove redundant ./ prefix from part directives ([bc15a90](https://github.com/juliansteenbakker/flutter_secure_storage/commit/bc15a90ff36a3c67f87cae57bf0a9ef94051a7f1))
* reset stale cipher IV when biometric auth fails or is cancelled ([c557a53](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c557a5341be7c3e70d832e81422512e91d3b5b57))
* revert flutter_secure_storage_windows to 4.1.0, so users with dart sdk &lt; 3.10.0 are not affected ([5b56420](https://github.com/juliansteenbakker/flutter_secure_storage/commit/5b564203c50c3f6b33989a536b19266d96dfe062))
* revert gradle 9 to 8 ([f08fed0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/f08fed066b0f4391505cd9a117decb7c5ad7a6ec))
* revert updated darwin package for backwards compatibility ([3fc4c53](https://github.com/juliansteenbakker/flutter_secure_storage/commit/3fc4c53ecffd7bc1f977bc5d76f0f3fb33eb3228))
* set min sdk according to flutter ([4ff2b34](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4ff2b34702b8d8bfcde0753d5bf9df1920f1020f))
* storage cipher and key cipher pairing ([9729cba](https://github.com/juliansteenbakker/flutter_secure_storage/commit/9729cbaab77ee1ab1560b19305ac0b41dae5cb5d))
* tests for migration backup ([4d474f9](https://github.com/juliansteenbakker/flutter_secure_storage/commit/4d474f988ab61b3376b91e03dd78b52209bfc714))
* tests for missing lines ([9d8809b](https://github.com/juliansteenbakker/flutter_secure_storage/commit/9d8809b6dd8bfc08d55c8a0c9260c1ebc0ecf0d0))
* tests for new name prefix ([a5274ee](https://github.com/juliansteenbakker/flutter_secure_storage/commit/a5274ee1e963e1e68b5dbdbd0a96d6ef42a02ada))
* tests for new name prefix ([aabe72c](https://github.com/juliansteenbakker/flutter_secure_storage/commit/aabe72c77b3c8d533130a864aa41682f33fda66a))
* tests for new name prefix ([9a061d9](https://github.com/juliansteenbakker/flutter_secure_storage/commit/9a061d99a54be20ad2373f1dc9f302264d728724))
* tests for new name prefix ([22bcdf2](https://github.com/juliansteenbakker/flutter_secure_storage/commit/22bcdf219482ef32443571e77241b88bf178e4d7))
* tests for secStoreAvailabilitySink visibility ([c22a7e0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/c22a7e08ccc5a4b71b19aabf7dce96f608015b9d))
* tests for secure enclave, doc clarification ([100ba67](https://github.com/juliansteenbakker/flutter_secure_storage/commit/100ba67525cb31ec20d62748cbffdb519ca5c849))
* tests not passing due to missing parameter ([b6ca528](https://github.com/juliansteenbakker/flutter_secure_storage/commit/b6ca5287581964673f87c8bccfb4ddef797ffe73))
* typo, add more details section, ([0061a48](https://github.com/juliansteenbakker/flutter_secure_storage/commit/0061a482df0f47888022039cdaaba700d5c57343))
* update biometric by using custom cipher ([32b563e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/32b563e4b468245936f6282cf0587a7904051158))
* update DPAPI FFI calls for win32 6.0.0 compatibility ([51f377a](https://github.com/juliansteenbakker/flutter_secure_storage/commit/51f377a32ad2996df328c8dc0adf2d026213c94b))
* update ndk ([fede473](https://github.com/juliansteenbakker/flutter_secure_storage/commit/fede47364856b76451927e51f0267bee35441262))
* upgrade agp, gradle, example minSdk ([a6b1a77](https://github.com/juliansteenbakker/flutter_secure_storage/commit/a6b1a777ca497240b1ea1f92268c5a22e4072e7d))
* upgrade agp, gradle, example minSdk ([16229da](https://github.com/juliansteenbakker/flutter_secure_storage/commit/16229da9dcacc6d4d0212779913113d3a2a5e690))
* web tests running on android ([f6818a0](https://github.com/juliansteenbakker/flutter_secure_storage/commit/f6818a0b89bacf077daa1793ebd3d8f26550279c))
* win32 upgrade & other improvements ([70e983e](https://github.com/juliansteenbakker/flutter_secure_storage/commit/70e983e1d3dfed1ca42eebc601fb273ca3c27288))

## 10.3.1

### Android
- Fixed `AEADBadTagException` when biometric authentication is cancelled on first launch: a stale IV is now cleared and the cipher re-initialised in encrypt mode so the next authentication attempt succeeds.
- Fixed `NullPointerException` when retrying an operation after a cancelled biometric prompt: `preferences` is now only assigned once cipher initialisation completes successfully, allowing a clean retry.

## 10.3.0

### Android
- Added `AndroidBiometricType` enum and `biometricType` option to `AndroidOptions` to control which authentication methods are accepted during biometric prompts (requires `KeyCipherAlgorithm.AES_GCM_NoPadding`).
  - `AndroidBiometricType.biometricOrDeviceCredential` (default) accepts Class 3 biometrics or device credentials (PIN/pattern/password), preserving previous behaviour.
  - `AndroidBiometricType.strongBiometricOnly` restricts authentication to Class 3 (strong) biometrics only; device credentials are explicitly rejected.
- Fully enforced on Android 11+ (API 30+) via `setAllowedAuthenticators` on `BiometricPrompt` and `setUserAuthenticationParameters` on the KeyStore key. On earlier API levels the system may still permit device credentials.
- Added `biometricPromptNegativeButton` option to `AndroidOptions` to customise the dismiss button label on the biometric prompt. Required when using `strongBiometricOnly` or on Android 10 and lower.

### iOS / macOS
- Fixed `secStoreAvailabilitySink` not being called when protected data availability changes.
- Fixed `kSecUseDataProtectionKeychain` being added to Keychain queries unconditionally; it is now only set when `useDataProtectionKeychain` is explicitly enabled.

### Windows
- Fixed `deleteAll` and `containsKey` not acquiring the mutex lock, which could cause data races under concurrent access.
  If you are on Dart >=3.10.0, this fix is applied automatically. Otherwise, pin `flutter_secure_storage_windows: ^4.2.2` in your `pubspec.yaml` to opt in and make sure your constraint is set for minimum of Dart >=3.10.0.

### Linux
- Fixed `deleteKeyring` storing the string `"null"` instead of an empty JSON object `{}`.
- Fixed non-UTF-8 error messages from libsecret causing a `FormatException` on the Dart side; messages are now sanitised before being sent through the method channel.
- Fixed locked or unavailable keyring now surfacing as a catchable `PlatformException` with code `KeyringLocked`.
- Fixed JSON parse errors and other C++ exceptions now surfacing as a `PlatformException` with code `StorageError` instead of sending malformed bytes through the channel.
## 10.2.0

### Android
- Deprecated `KeyCipherAlgorithm.RSA_ECB_PKCS1Padding`. Existing data is automatically migrated to the default `RSA_ECB_OAEPwithSHA_256andMGF1Padding` when `migrateOnAlgorithmChange` is true.
- Deprecated `StorageCipherAlgorithm.AES_CBC_PKCS7Padding`. Existing data is automatically migrated to the default `AES_GCM_NoPadding` when `migrateOnAlgorithmChange` is true.
- Fixed Gradle space-assignment warnings in `build.gradle`.

### iOS / macOS
- Fixed iOS build by updating availability annotation for Secure Enclave methods from `iOS 11.3` to `iOS 13.0`.

### Windows
- Fixed compatibility with `win32` 6.0.0 in `flutter_secure_storage_windows 4.2.0`.
  If you are on Dart >=3.10.0, this fix is applied automatically. Otherwise, pin `flutter_secure_storage_windows: ^4.2.0` in your `pubspec.yaml` to opt in and make sure your constraint is set for minimum of Dart >=3.10.0.

## 10.1.0

### Windows
- Updated `flutter_secure_storage_windows` to 4.2.0 with compatibility fixes for `win32` 6.0.0.

### Android
- Added `storageNamespace` option to `AndroidOptions` for full namespace isolation across storage instances (SharedPreferences, KeyStore aliases, config/key storage). Use this instead of `sharedPreferencesName` when running multiple `FlutterSecureStorage` instances with different cipher configurations.
- Deprecated `sharedPreferencesName` in favor of `storageNamespace`, which provides complete isolation rather than data-only isolation.
- Added `migrateWithBackup` option to `AndroidOptions` for crash-resistant migration. When enabled, backup copies of encrypted data are created before migration starts, allowing recovery if migration fails or the app crashes mid-migration. Works in conjunction with `migrateOnAlgorithmChange`.
- Made `KeyCipherAlgorithm` and `StorageCipherAlgorithm` public enums.

**Fixes:**
- Fixed crash on biometric failure (not error).
- Fixed null safety issue in `MethodRunner` that could cause a crash on Android.
- Fixed config being overwritten on initialization.
- Fixed default Android key cipher not aligning with the Flutter default.

### iOS / macOS
- Added `useSecureEnclave` option to `IOSOptions` and `MacOsOptions` to store keys in the device's Secure Enclave for hardware-backed security.

**Fixes:**
- Fixed `kSecAttrSynchronizable` being silently dropped when no access control flags are set.
- Fixed `readAll` not returning Secure Enclave items correctly.

## 10.0.0
This major release brings significant security improvements, platform updates, and modernization across all supported platforms.

### Android
Due to the deprecation of Jetpack Security library, the Android implementation has been largely rewritten with custom secure ciphers, enhanced biometrics support, and migration tools.

**Breaking Changes:**
- `AndroidOptions().encryptedSharedPreferences` is now deprecated due to Jetpack Crypto package deprecation
  - Migration will automatically happen due to `migrateOnAlgorithmChange: true`, which can also be set to false if not wanted.
- ResetOnError will now automatically be true, because most errors are unrecoverable due to key storage problems. It can still be disabled with `resetOnError: false`
- Default key cipher changed to `RSA_ECB_OAEPwithSHA_256andMGF1Padding`
- Default storage cipher changed to `AES_GCM_NoPadding`
- Minimum Android SDK changed from 19 to 23
- Target SDK updated to 36
- Migrated from deprecated Jetpack Crypto library to custom cipher implementation (Tink doesn't support biometrics)
- Migrated to Java Version 17

**New Features:**
- New named constructors: `AndroidOptions()`, `AndroidOptions.biometric()`
- `AndroidOptions().migrateOnAlgorithmChange` automatically migrates data to new ciphers when enabled
- Improved biometric authentication with graceful degradation when device has no security setup
- Migration tools for transitioning from deprecated encryptedSharedPreferences
- Enhanced error handling with proper exception messages for biometric unavailability

**Fixes:**
- Fixed biometric authentication on devices without security (PIN/pattern/password) - now gracefully degrades when `enforceBiometrics=false`
- Fixed storage cipher and key cipher pairing validation
- Fixed migration checks for encrypted shared preferences
- Fixed biometric permission handling
- Fixed exception when reading data after boot

**Other Changes:**
- Updated Gradle, Kotlin, and Tink dependencies
- Refactored custom cipher implementations for better maintainability
- Added delete key functions for proper reset handling
- Migrated to new analyzer and code cleanup

### iOS / macOS (darwin)
- Merged iOS and macOS implementations into unified `flutter_secure_storage_darwin` package
- Added support for Swift Package Manager
- Remove keys regardless of synchronizable state or accessibility constraints
- Change minimum iOS version from 9 to 12
- Change minimum macOS version to 10.14
- Use serial queue for execution of keychain operations
- Added privacy manifest
- Refactored code and added missing options to IOSOptions and MacOSOptions
- Fixed warnings with Privacy Manifest
- Fixed delete and deleteAll when synchronizable is set
- Fixed migration when value is saved while key already exists with different accessibility option
- Use accessibility option for all operations
- Migrated to new analyzer and code cleanup

### Web
- Web is now compatible with WASM
- Updated code style and migrated to very_good_analysis
- Add check for secure context (operations only allowed with secure context)
- Remove dart:io to support WASM build
- Migrated away from `html` to `web` package
- Removed `js` in favor of using js-interop
- Added `useSessionStorage` parameter to WebOptions for saving in session storage instead of local storage
- Updated web dependency support to <2.0.0
- Migrated to new analyzer and code cleanup

### Windows
- Upgrades deprecated member usage of win32
- Migrated to `win32` version 5.5.4 to support Dart 3.4 / Flutter 3.22.0
- Migrated to new analyzer and code cleanup
- Write encrypted data to files instead of the Windows credential system

### Linux
- Fixed whitespace deprecation warning
- Reverted json.dump with indentations due to problems
- Fixed search with schemas fails in cold keyrings
- Fixed erase called on null
- Fixed memory management issue
- Remove and replace libjsoncpp1 dependency
- Migrated to new analyzer and code cleanup

### Platform Interface
- Remove dart:io to support WASM build of web
- Migrated to new analyzer and code cleanup

### General Improvements
- Listener functionality via `FlutterSecureStorage().registerListener()`
- All platforms updated to support Dart SDK <4.0.0
- Comprehensive test coverage improvements
- Documentation updates across all platforms

## 10.0.0-beta.5
Due to security issues regarding the handling of biometrics in v10.0.0-beta.4, together with the deprecation
of Jetpack Security library, it took me some time to find a secure alternative. My apologies for the delay.

The Android part has been largely rewritten, reintroducing the customer cipher construction from before,
but with secure ciphers, biometrics support, updated default ciphers and migration tools.

**Breaking Changes:**
- `AndroidOptions().encryptedSharedPreferences` is now deprecated due to Jetpack Crypto package being deprecated
  For now you can still use deprecated encryptedSharedPreferences by setting `encryptedSharedPreferences: true` 
  and `migrateOnAlgorithmChange: false`. If `encryptedSharedPreferences` is `true` and `migrateOnAlgorithmChange`
  is `true`, data will be automatically migrated to the new cipher, and encryptedSharedPreferences
  cannot be used anymore.
- Google recommends using Tink library, but Tink does not support biometrics, so custom ciphers have been reintroduced
- Default key cipher changed to `RSA_ECB_OAEPwithSHA_256andMGF1Padding`
- Default storage cipher changed to `AES_GCM_NoPadding`

**New Features:**
- New named constructors: `AndroidOptions()`, `AndroidOptions.biometric()`
- `AndroidOptions().migrateOnAlgorithmChange` automatically migrates data to new ciphers when enabled
- Improved biometric authentication with graceful degradation when device has no security setup
- Migration tools for transitioning from deprecated encryptedSharedPreferences
- Enhanced error handling with proper exception messages for biometric unavailability

**Key Fixes:**
- Fixed biometric authentication on devices without security (PIN/pattern/password) - now gracefully degrades when `enforceBiometrics=false`
- Fixed storage cipher and key cipher pairing validation
- Fixed migration checks for encrypted shared preferences
- Fixed biometric permission handling
- Fixed default `resetOnError` behavior (now defaults to `true`)

**Other Changes:**
- Target SDK 36
- Updated Gradle, Kotlin, and Tink dependencies
- Updated minimum SDK according to Flutter requirements
- Refactored custom cipher implementations for better maintainability
- Added delete key functions for proper reset handling

## 10.0.0-beta.4
* [Apple] Merged ios and macos implementation into a new package flutter_secure_storage_darwin
* [Apple] Refactored code and added missing options
* [Apple] Added support for swift package manager
* [Web] Update flutter_secure_storage_platform_interface to be compatible with WASM.

## 10.0.0-beta.3
* [iOS] Fix delete and deleteAll when synchronizable is set.
* [iOS] Update migration when value is saved while key already exists with different accessibility option. 
* [Android] Fix deprecation warning.

## 10.0.0-beta.2
* [Web] Update flutter_secure_storage_platform_interface to be compatible with WASM.

## 10.0.0-beta.1
This new major release has some big changes. This plugin requires a minimum dart sdk of 3.3.0 or higher
and a minimum flutter version of 3.19.0.

[Android]
- By default, encryptedSharedPreferences will be enabled, and cannot be disabled. If there is still 
  data saved by previous versions using encryptedSharedPreferences = false, it will be automatically
  transferred to encryptedSharedPreferences.
- Migrated from deprecated Jetpack Crypto library to Google Tink Crypto library.
- Migrated to Android SDK 35
- Migrated to Java Version 17
- Minimum Android SDK is changed from 19 to 23.
- Migrated to new analyzer and clean-up code.
- Lots of minor code improvements

[iOS]
- Change minimum iOS version from 9 to 12
- Use serial queue for execution of iOS keychain operations
- Migrated to new analyzer and clean-up code.

[Web]
- Web is now migrated to be compatible with WASM.
- The parameter useSessionStorage is added to WebOptions, which you can use to save in session storage
  instead of local storage.
- Migrated to new analyzer and clean-up code.

[Windows]
- Migrates to `win32` version 5.5.4 to support Dart 3.4 / Flutter 3.22.0.
- Migrated to new analyzer and clean-up code.

[Platform Interface]
- Migrated to new analyzer and clean-up code.

## 9.2.4
* [Android] Fix errors when building for release by upgrading Tink to 1.9.0.
* [iOS] Fix delete and deleteAll when synchronizable is set.
* [iOS] Update migration when value is saved while key already exists with different accessibility option.

## 9.2.3
* [iOS] Fix for issue #711: The specified item already exists in the keychain.
* [Linux] Fix json.dump with indentations.
* [Web] Update web dependency support to support <2.0.0 instead of <1.0.0.
* [Web] Add wrapKey and wrapKeyIv parameters to webOptions. See readme for more information.
* [macOS] Added useDataProtectionKeyChain parameter.

## 9.2.2
[iOS, macOS] Fixed an issue which caused the readAll and deleteAll to not work properly.

## 9.2.1
* Fix async race condition bug in storage operations.
* [macOS] Return nil on macOS if key is not found

## 9.2.0
New Features:
* [iOS, macOS] Reintroduced isProtectedDataAvailable.
* Listener functionality via `FlutterSecureStorage().registerListener()`

Bugs Fixed:
* [iOS] Return nil on iOS read if key is not found
* [macOS] Also set kSecUseDataProtectionKeychain on read for macos.

## 9.1.1
Reverts new feature because of breaking changes.
* [iOS, macOS] Added isProtectedDataAvailable, A boolean value that indicates whether content protection is active.

## 9.1.0
New Features:
* [iOS, macOS] Added isProtectedDataAvailable, A boolean value that indicates whether content protection is active.

Improvements:
* [iOS, macOS] Use accessibility option for all operations
* [iOS, macOS] Added privacy manifest
* [iOS] Fixes error when no item exists
* [Linux] Fixed search with schemas fails in cold keyrings
* [Linux] Fixed erase called on null
* [Android] Fixed native Android stacktraces in PlatformExceptions
* [Android] Fixed exception when reading data after boot

## 9.0.0
Breaking changes:
* [Windows] Migrated to FFI with win32 package.

## 8.1.0
* [Android] Upgraded to Gradle 8.
* [Android] Fixed resetOnError not working.
* [Windows] Changed PathNotFoundException to FileSystemException to be backwards compatible with Flutter SDK 2.12.0.
* [Windows] Applied lint suggestions.
* [Linux] Remove and replace libjsoncpp1 dependency.
* [Linux, macOS, Windows, Web] Update Dart SDK Constraint to support <4.0.0 instead of <3.0.0.

## 8.0.0
Breaking changes:
* [macOS] The minimum macOS version supported is now 10.14.

Other changes:
* [Android] Fixed an issue when Encrypted Shared Preferences failed, the fallback would not handle the data correctly.
* [Windows] Write encrypted data to files instead of the windows credential system.
* [Linux] Fixed an issue with memory management.

## 7.0.2
[macOS] Fix issue with plugin name.

## 7.0.1
[Android] Reverted double initialization of the SharedPreferences because this will break mixed usage of secureSharedPreference on Android.

## 7.0.0
Breaking changes:
* [macOS] The minimum macOS version supported is now 10.13.

Other changes:
* [Android] Fixed double initialization of the SharedPreferences which caused containsKey and other functions to not work properly.
* [macOS] Upgraded codebase to swift which fixed containsKey always returning true.

## 6.1.0
* [iOS] (From 6.1.0-beta.1) Migrated from objective C to Swift. This also fixes issues with containsKey and possibly other issues.
* [Android] Upgrade security-crypto from 1.1.0-alpha03 to 1.1.0-alpha04
* [Android] Fix deprecation warnings.
* [All] Migrated from flutter_lints to lint and applied suggestions.

## 6.1.0-beta.1
* [iOS] Migrated from objective C to Swift. This also fixes issues with containsKey and possibly other issues.

## 6.0.0
* [Android] Upgrade to Android SDK 33.

## 5.1.2
This version reverts some breaking changes of update 5.1.0.
These changes will become available in version 6.0.0
* [Android] Revert upgrade to Android SDK 33.

## 5.1.1
* Example app dependencies updated
* Updated homepage

## 5.1.0
* [Android] You can now select your own key prefix or database name.
* [Android] Upgraded to Android SDK 33.
* [Android] You can now select the keyCipherAlgorithm and storageCipherAlgorithm.
* [Linux] Fixed an issue where no error was being reported if there was something wrong accessing the secret service.
* [macOS] Fixed an memory-leak.
* [macOS] You can now select the same options as for iOS.

## 5.0.2
* [Android] Fixed bug where sharedPreference object was not yet initialized.

## 5.0.1
* [Android] Added java 8 requirement for gradle build.

## 5.0.0
First stable release of flutter_secure_storage for multi-platform!
Please see all beta release notes for changes.

This first release also fixes several stability issues on Android regarding encrypted shared
preferences.

## [5.0.0-beta.5]
* [Linux, iOS & macOS] Add containsKey function.
* [Linux] Fix for use of undeclared identifier 'flutter_secure_storage_linux_plugin_register_with_registrar'

## [5.0.0-beta.4]
* [Windows] Fixed application crashing when key doesn't exists.
* [Web] Added prefix to local storage key when deleting, fixing items that wouldn't delete.

## [5.0.0-beta.3]
* [Android] Add possibility to reset data when an error occurs.
* [Windows] Add readAll, deleteAll and containsKey functions.
* [All] Refactor option defaults.

## [5.0.0-beta.2]
* [Android] Improved EncryptedSharedPreferences by not loading unused Cipher.
* [Android] Removed deprecated classes
* [Web] Improved containsKey function

## [5.0.0-beta.1]
Initial BETA support for macOS, web & Windows. Development is still ongoing so expect some functions to not work correctly!
Please read the readme.md for information about every platform.

* Migrated to a federated project structure. [#254](https://github.com/mogol/flutter_secure_storage/pull/257). Thanks [jhancock4d](https://github.com/jhancock4d)
* Added support for encrypted shared preferences on Android. [#259](https://github.com/mogol/flutter_secure_storage/pull/259)

## [4.2.1]
* Added kSecAttrSynchronizable support by setting IOSOptions.synchronizable  [#51](https://github.com/mogol/flutter_secure_storage/issues/51)
* Changed deprecated jcenter to mavenCentral [#246](https://github.com/mogol/flutter_secure_storage/pull/246)

## [4.2.0]
* Remove Strongbox for Android [225](https://github.com/mogol/flutter_secure_storage/pull/225). Thanks [JordyLangen](https://github.com/JordyLangen).

## [4.1.0]
* Add support for Linux [185](https://github.com/mogol/flutter_secure_storage/pull/185). Thanks [talhabalaj](https://github.com/talhabalaj)
* Improve first-time read speed on Android by not creating cipher when key is not present. Thanks [PieterAelse](https://github.com/PieterAelse)
* Make it possible to customize iOS account name(kSecAttrService). Thanks [klyver](https://github.com/klyver)

## [4.0.0]
* Introduce null-safety. Thanks [Steve Alexander](https://github.com/SteveAlexander)

## [3.3.5]
* Fix thread safety issues in android code to close [161](https://github.com/mogol/flutter_secure_storage/issues/161). Thanks [koskimas](https://github.com/koskimas)

## [3.3.4]
* Fix Android hanging UI on StorageCipher initialization [#116](https://github.com/mogol/flutter_secure_storage/issues/116) by [morrica](https://github.com/morrica)
* Fix crash only observed for v2 apps [#124](https://github.com/mogol/flutter_secure_storage/pull/124) by [lidongze91](https://github.com/lidongze91)
* Fix crash when generating keys in android with RTL locales [#132](https://github.com/mogol/flutter_secure_storage/pull/132) by [iassal](https://github.com/iassal)
* Fix returning the error as String rather than Exception [#134](https://github.com/mogol/flutter_secure_storage/issues/134) by [wytesk133](https://github.com/wytesk133)s
* Fix Android crash onDetachedFromEngine when init fails [#144](https://github.com/mogol/flutter_secure_storage/issues/144) by [iassal](https://github.com/iassal)
* Handle null value at write function [#95](https://github.com/mogol/flutter_secure_storage/issues/95) by [ewertonrp](https://github.com/ewertonrp)
*  Add support for containsKey [#139](https://github.com/mogol/flutter_secure_storage/issues/139) by [iassal](https://github.com/iassal)

## [3.3.3]
* Fix compatibility with non-AndroidX project. [AndroidX Migration](https://flutter.dev/docs/development/androidx-migration) is recommended.

## [3.3.2]
* Migrate to Android v2 embedder.
* Adds support for specifying [iOS Keychain Item Accessibility](https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility?language=objc).

## [3.3.1+2]
* Fix iOS build warning [Issue 30](https://github.com/mogol/flutter_secure_storage/issues/30)

## [3.3.1+1]
* Fix Android Manifest error [Issue 77](https://github.com/mogol/flutter_secure_storage/issues/77) and [Issue 79](https://github.com/mogol/flutter_secure_storage/issues/79). Thanks [nate-eisner](https://github.com/nate-eisner).

## [3.3.1]
* Fix crash without [iOSOptions](https://github.com/mogol/flutter_secure_storage/issues/73).

## [3.3.0]
* Added groupId for iOS keychain sharing. Thanks [Maleandr](https://github.com/Maleandr).
* Fix Gradle version in `gradle-wrapper.properties`. Thanks [blasten](https://github.com/blasten).
* Added minimum sdk requirement on AndroidManifest. Thanks [lidongze91](https://github.com/lidongze91).

## [3.2.1]
* Fix Android 9.0 Pie [KeyStore exception](https://github.com/mogol/flutter_secure_storage/issues/46).

## [3.2.0]
* **Breaking change**. Migrate from the deprecated original Android Support Library to AndroidX. This shouldn't result in any functional changes, but it requires any Android apps using this plugin to [also migrate](https://developer.android.com/jetpack/androidx/migrate) if they're using the original support library. Thanks [I-am-original](https://github.com/I-am-original).
* Enable StrongBox on Android devices that support it. Thanks [bbedward](https://github.com/bbedward).

## [3.1.3]
* Fix Android 9.0 Pie KeyStore exception. Thanks [hacker1024](https://github.com/hacker1024)

## [3.1.2]
* Added recreating secretKey if its decoding failed. Fix for [unwrap key](https://github.com/mogol/flutter_secure_storage/issues/13). Thanks [hnvn](https://github.com/hnvn).

## [3.1.1]
* Suppress warning about unchecked operations when compiling for Android.

## [3.1.0]
* Added `readAll` and `deleteAll`.

## [3.0.0]
* **Breaking change**. Changed payloads encryption for Android from RSA to AES, AES secret key is encrypted with RSA.

## [2.0.0]````
* **Breaking change**. Changed key alias to fix Android 4.4.2 issue. The plugin isn't able to get previous stored data.

## [1.0.0]
* Bump version

## [0.0.1]

* Initial release
