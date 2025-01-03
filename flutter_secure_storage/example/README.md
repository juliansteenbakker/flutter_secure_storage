# flutter_secure_storage Example App

This is the example application for demonstrating the use of `flutter_secure_storage` on iOS and Android platforms.

---

## About

The example app showcases how to securely store and retrieve sensitive data using the `flutter_secure_storage` plugin. It provides a simple interface to demonstrate:

- Writing data to secure storage.
- Reading data from secure storage.
- Checking for key existence.
- Deleting specific keys or clearing all stored data.

---

## Running the Example App

To run the example app:

1. Navigate to the `example` directory.
2. Install the dependencies using `flutter pub get`.
3. Run the app using `flutter run`.

Ensure that you have an emulator or a physical device configured for iOS or Android.

---

## Integration Tests

To run the integration tests, execute the following command:

`flutter drive --target=test_driver/app.dart`

This will launch the integration tests specified in the `test_driver` directory.

---

## Features Demonstrated

1. **Write Data**:
   Enter a key-value pair to securely store data.

2. **Read Data**:
   Retrieve a value by entering the corresponding key.

3. **Check Key Existence**:
   Check if a specific key exists in secure storage.

4. **Delete Data**:
   Remove data for a specific key or clear all stored data.

---

## Prerequisites

### Android

- Ensure that the Android emulator or device has proper configurations for running Flutter applications.
- Keychain and secure storage are configured automatically during the app build.

### iOS

- Use a physical device or simulator running iOS 11.0 or later.
- Ensure Keychain sharing is properly configured in the iOS project settings.

---

## Modifications

You can modify the example code to test different scenarios or configurations, such as custom accessibility options or key expiration on iOS and Android.

---

## Contributing

Feedback and contributions are welcome to improve the example app.
