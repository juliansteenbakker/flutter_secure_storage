A Linux implementation of [`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage) using the XDG Desktop [Secret Portal API](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html) (`org.freedesktop.portal.Secret`).

## Usage

Register this implementation when the application should use the XDG Desktop
Secret Portal API (`org.freedesktop.portal.Secret`), such as when running in a
sandboxed environment (e.g., Flatpak or Snap).

```dart
import 'package:flutter_secure_storage_linux_portal/flutter_secure_storage_linux_portal.dart';

FlutterSecureStorageLinuxPortal.registerWith();
```

## File Path

Stores the secrets encrypted in [a file](https://pub.dev/packages/xdg_secret_portal_store#storage-format):

`$XDG_DATA_HOME/$APPLICATION_ID/xdg_secret_portal_store/secrets.json`.

## Cryptography

For [security details](https://pub.dev/packages/xdg_secret_portal_store#cryptography).
