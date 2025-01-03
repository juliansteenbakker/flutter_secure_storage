# flutter_secure_storage_android_ios

This is the platform-specific implementation of `flutter_secure_storage` for Android and iOS.

---

## Features

- Secure storage using Keychain (iOS) and Encrypted Shared Preferences with Tink (Android).
- Platform-specific options for encryption and accessibility.

---

## Installation

Add the dependency in your `pubspec.yaml` and run `flutter pub get`.

---

## Configuration

### Android

1. Disable Google Drive backups to avoid key-related exceptions:
    - Add the required settings in your `AndroidManifest.xml`.

2. Exclude shared preferences used by the plugin:
    - Follow the linked documentation for further details.

### iOS

1. Set Keychain accessibility options:
    - Modify your `Info.plist` file with the necessary configurations.

---

## Usage

Refer to the main [flutter_secure_storage README](../README.md) for common usage instructions.

---

## License

This project is licensed under the BSD 3 License. See the [LICENSE](../LICENSE) file for details.
