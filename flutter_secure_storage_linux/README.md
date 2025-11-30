# flutter_secure_storage_linux

This is the platform-specific implementation of `flutter_secure_storage` for Linux.

## Features

- Secure storage using `libsecret` library.
- Compatible with various Linux keyring services like Gnome Keyring and KDE KWalletManager.

## Installation

Ensure you have the required dependencies installed: `libsecret-1-dev` and `libjsoncpp-dev`.

## Configuration

1. Install a keyring service such as [`gnome-keyring`](https://wiki.gnome.org/Projects/GnomeKeyring) or [`kwalletmanager`](https://wiki.archlinux.org/title/KDE_Wallet).
2. Ensure your application includes runtime dependencies like `libsecret-1-0` and `libjsoncpp1`.

## Usage

Refer to the main [flutter_secure_storage README](../README.md) for common usage instructions.

## License

This project is licensed under the BSD 3 License. See the [LICENSE](../LICENSE) file for details.
