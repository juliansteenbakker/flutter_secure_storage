# flutter_secure_storage_linux

This is the platform-specific implementation of `flutter_secure_storage` for Linux.

## Features

- Secure storage using `libsecret` library.
- Compatible with various Linux keyring services like GNOME Keyring and KDE KWallet.

## Build dependencies

Install the required development libraries before building:

```bash
sudo apt-get install libsecret-1-dev
```

> **Note:** `libjsoncpp-dev` is no longer required. The plugin uses a bundled header-only JSON library.

Runtime dependencies (`libsecret-1-0`) are typically pre-installed on most Linux desktops.

## Configuration

A running keyring service is required at runtime:

- **GNOME / Ubuntu:** [`gnome-keyring`](https://wiki.gnome.org/Projects/GnomeKeyring) — usually active by default in a GNOME session.
- **KDE:** [`kwallet`](https://wiki.archlinux.org/title/KDE_Wallet) — enabled via KDE Wallet Manager.
- **Headless / CI:** start `gnome-keyring-daemon` with an unlocked keyring:
  ```bash
  eval $(dbus-launch --sh-syntax)
  echo "" | gnome-keyring-daemon --unlock --daemonize --components=secrets
  ```

## Known issues

### Flutter installed via snap on Ubuntu 22.04+

Building with the Flutter snap may produce linker errors like:

```
undefined reference to `g_task_set_static_name'
undefined reference to `g_once_init_enter_pointer'
```

This is caused by a version mismatch between the GLib bundled in the Flutter snap and the system `libsecret`, which is compiled against a newer GLib. The plugin shared library links fine, but executables (including native test binaries) may fail to link.

**Workaround:** install Flutter via the [official tar archive](https://docs.flutter.dev/get-started/install/linux) instead of snap, so the toolchain uses the system linker and libraries consistently.

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
