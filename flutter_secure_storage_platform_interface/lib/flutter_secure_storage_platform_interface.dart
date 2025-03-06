library;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

part './src/method_channel_flutter_secure_storage.dart';
part './src/options.dart';

/// The interface that implementations of flutter_secure_storage must implement.
///
/// Platform implementations should extend this class rather than implement it
/// as `flutter_secure_storage` does not consider newly added methods to be
/// breaking changes. Extending this class (using `extends`) ensures that the
/// subclass will get the default implementation, while
/// platform implementations that `implements` this interface will be broken by
/// newly added [FlutterSecureStoragePlatform] methods.
abstract class FlutterSecureStoragePlatform extends PlatformInterface {
  /// Initiates the FlutterSecureStoragePlatform class
  FlutterSecureStoragePlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterSecureStoragePlatform _instance =
      MethodChannelFlutterSecureStorage();

  /// Gets the current instance of the platform interface.
  static FlutterSecureStoragePlatform get instance => _instance;

  /// Sets a new instance of the platform interface.
  ///
  /// Parameters:
  /// - [instance]: The new implementation of `FlutterSecureStoragePlatform`.
  ///
  /// Throws:
  /// - A verification error if the provided instance does not match the
  /// required token.
  static set instance(FlutterSecureStoragePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Writes a key-value pair to secure storage.
  ///
  /// Parameters:
  /// - [key]: The key to identify the stored value.
  /// - [value]: The value to store.
  /// - [options]: A map of platform-specific options for the write operation.
  ///
  /// Returns:
  /// - A [Future] that completes when the write operation finishes.
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  });

  /// Reads a value from secure storage by its key.
  ///
  /// Parameters:
  /// - [key]: The key of the value to retrieve.
  /// - [options]: A map of platform-specific options for the read operation.
  ///
  /// Returns:
  /// - A [Future] that resolves to the value associated with the key, or `null`
  ///   if the key does not exist.
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  });

  /// Checks whether a key exists in secure storage.
  ///
  /// Parameters:
  /// - [key]: The key to check for existence.
  /// - [options]: A map of platform-specific options for the operation.
  ///
  /// Returns:
  /// - A [Future] that resolves to `true` if the key exists, or `false`
  /// otherwise.
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  });

  /// Deletes a key-value pair from secure storage.
  ///
  /// Parameters:
  /// - [key]: The key to delete.
  /// - [options]: A map of platform-specific options for the delete operation.
  ///
  /// Returns:
  /// - A [Future] that completes when the delete operation finishes.
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  });

  /// Reads all key-value pairs from secure storage.
  ///
  /// Parameters:
  /// - [options]: A map of platform-specific options for the read-all
  /// operation.
  ///
  /// Returns:
  /// - A [Future] that resolves to a map containing all key-value pairs in
  /// storage.
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  });

  /// Deletes all key-value pairs from secure storage.
  ///
  /// Parameters:
  /// - [options]: A map of platform-specific options for the delete-all
  /// operation.
  ///
  /// Returns:
  /// - A [Future] that completes when the delete-all operation finishes.
  Future<void> deleteAll({
    required Map<String, String> options,
  });

  /// Checks if the android device supports secure hardware-backed storage.
  ///
  /// Returns:
  /// - A [Future] that resolves to `true` if the device supports secure
  /// hardware-backed storage, or `false` otherwise.
  Future<bool> isStrongBoxSupported() {
    throw UnsupportedError(
      'isStrongBoxSupported() is not available on this platform',
    );
  }
}
