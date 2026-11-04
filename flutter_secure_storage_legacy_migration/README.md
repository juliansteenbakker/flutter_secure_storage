# flutter_secure_storage_legacy_migration

Optional Android migration support for apps that upgrade directly from
`flutter_secure_storage` 9 or earlier to version 11. Version 11 no longer
contains the RSA PKCS#1, AES CBC, or Jetpack EncryptedSharedPreferences readers.
This package carries the version 10 Android migration implementation in a
separate Java namespace so it can be installed alongside version 11.

## Usage

Android API 24 or later is required, matching version 11 of the main plugin.
Add both packages to the app:

```yaml
dependencies:
  flutter_secure_storage: ^11.2.0
  flutter_secure_storage_legacy_migration: ^0.1.0
```

Call the migrator before **any** ordinary secure-storage read or write,
including calls made by other packages and background Flutter engines:

```dart
import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_secure_storage_legacy_migration/flutter_secure_storage_legacy_migration.dart';

Future<void> initializeStorage() async {
  WidgetsFlutterBinding.ensureInitialized();
  await FlutterSecureStorageLegacyMigration.migrateIfNeeded(
    options: const AndroidOptions(migrateWithBackup: true),
  );
  // The app can now use FlutterSecureStorage.
}
```

Pass the same Android storage namespace and key prefix used by the app's
`FlutterSecureStorage` instance. The migrator checks the version 11
`checkUpgradeStatus()` report first. It invokes the legacy reader for data
using removed ciphers, missing algorithm markers, or the removed Jetpack
backend. It also checks for legacy Jetpack entries when version 11 reports
that newer entries are readable. If both storage formats share one preferences
file, it first migrates custom entries to the selected cipher, then decrypts
Jetpack entries through a filtered view and re-encrypts them with that cipher.
Existing custom entries take precedence over duplicate Jetpack values. Jetpack
originals remain intact until native reads and the version 11 check succeed.
Custom ciphertext backups are stored in a separate preferences file using exact
original key names. User keys ending in `_BACKUP` are ordinary keys. Older
in-place backups are recognized only with persisted migration state; an ambiguous
interrupted backup creation is preserved and reported rather than guessed.
Cleanup verifies a persisted digest before removing those originals, so an
interrupted migration can retry without deleting unverified data. Completeness checks
use the selected key prefix and original key names, including backup entries,
rather than the inspector's
file-wide Jetpack count. Verification receipts are isolated by prefix. A cipher change is rejected before
changing keys or algorithm markers if other custom prefixes share those markers.
Such stores require a migration covering all dependent prefixes before upgrading;
Jetpack entries under other prefixes are preserved independently.

For biometric storage, an `authenticationRequired` report does not indicate
corruption. If no legacy work is pending, the migrator returns without prompting.
PKCS1-to-biometric migration first saves a verified OAEP/GCM checkpoint, so
cancelling authentication leaves readable credentials for a retry. For stores
without `storageNamespace`, other stores sharing the legacy RSA alias must
complete their standard OAEP migration before that alias can become biometric.
The migrator refuses to replace a shared RSA key while another legacy store may
still need it, preserving both stores for retry.

Pending migration uses the native authentication flow and verifies every value
with the authenticated cipher, including when resuming interrupted cleanup.
Below API 28, optional biometric migration uses the initialized unauthenticated
cipher; enforced biometrics returns an unsupported-authentication error.
Cancellation or failed verification preserves
legacy data and propagates the error.
If migration fails, the call throws so the app can stop before touching the
legacy data with version 11.
An app can offer a separate, explicitly confirmed recovery action through
`FlutterSecureStorageLegacyMigration.resetStorage()`. It clears the selected
Android secure-storage namespace, its wrapped keys, and migration backup
without reading encrypted entries. All values in that namespace are lost, so
retry migration first and require the user to confirm the reset. For stores without
`storageNamespace`, global wrapped keys and RSA aliases are retained if another
preferences file may depend on them or ownership cannot be checked. Isolated
namespaces and default stores without siblings can clear their own keys.

This package does not run automatically when installed and has no effect on
iOS, macOS, web, Windows, or Linux. It is unnecessary for users whose data was
already migrated by version 10. Keep it as a dependency until older installs
can no longer upgrade directly to your version 11 app.

The native legacy implementation is based on `flutter_secure_storage` 10.3.4
and carries its BSD-3-Clause license. It is deliberately isolated from the
version 11 plugin classes and method channel.
