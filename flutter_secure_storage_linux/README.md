# flutter_secure_storage_linux

This is the platform-specific implementation of `flutter_secure_storage` for Linux.

## Features

- Secure storage using `org.freedesktop.secrets` (over D-Bus).
- Compatible with various Linux keyring services like GNOME Keyring and KDE KWallet.

## Migration from the old schema

In order to fix [#1181](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1181),
the updated implementation automatically migrates the old data when appropriate.

The old secrets are not automatically deleted by default to refrain from destructive changes,
so you need to explicitly opt in to remove:

```dart
import 'package:flutter_secure_storage_linux/flutter_secure_storage_linux.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
// ···

final secureStorageImplementation = FlutterSecureStoragePlatform.instance;
if (secureStorageImplementation is FlutterSecureStorageLinux) {
  secureStorageImplementation.deleteLegacyData = true;
}
```

To opt out of migrating the old data:

```dart
// Opting out of auto migration for newer apps avoids an additional lookup.
secureStorageImplementation.migrateLegacyData = false;
```

## Configuration

A running keyring service is required at runtime. This is typically already provided by the desktop environment:

- **GNOME / Ubuntu:** [`gnome-keyring`](https://wiki.gnome.org/Projects/GnomeKeyring) — usually active by default in a GNOME session.
- **KDE:** [`kwallet`](https://wiki.archlinux.org/title/KDE_Wallet) — enabled via KDE Wallet Manager.
- **Other / lightweight:** [`secret-service`](https://github.com/yousefvand/secret-service)
- **Headless / CI:** start `gnome-keyring-daemon` with an unlocked keyring:
  ```bash
  eval $(dbus-launch --sh-syntax)
  echo "" | gnome-keyring-daemon --unlock --daemonize --components=secrets
  ```

## Running the tests

### Native tests (C++ / GoogleTest)

The native tests exercise the `SecretStorage` layer directly against a real keyring. Build the example app first to compile the test binary, then run via CTest:

```bash
# 1. Start a keyring daemon (skip if already running in a desktop session)
eval $(dbus-launch --sh-syntax)
echo "" | gnome-keyring-daemon --unlock --daemonize --components=secrets

# 2. Build (compiles the test binary alongside the app)
cd flutter_secure_storage/example
flutter build linux --debug

# 3. Run
cd build/linux/x64/debug/plugins/flutter_secure_storage_linux
ctest --output-on-failure
```

### Integration tests

```bash
cd flutter_secure_storage/example
xvfb-run flutter test integration_test/linux_test.dart -d linux
```

## Usage

Refer to the main [flutter_secure_storage README](../README.md) for common usage instructions.

## License

This project is licensed under the BSD 3 License. See the [LICENSE](../LICENSE) file for details.
