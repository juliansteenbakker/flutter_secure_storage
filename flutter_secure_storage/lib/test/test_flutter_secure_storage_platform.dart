import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';

/// The `TestFlutterSecureStoragePlatform` class is a test implementation of
/// the `FlutterSecureStoragePlatform` interface, allowing for in-memory storage
/// of key-value pairs for testing purposes.
class TestFlutterSecureStoragePlatform extends FlutterSecureStoragePlatform {
  /// Creates an instance of `TestFlutterSecureStoragePlatform` with an
  /// in-memory data store.
  ///
  /// Parameters:
  /// - [data]: A map representing the in-memory storage for key-value pairs.
  TestFlutterSecureStoragePlatform(this.data);

  /// The in-memory data store used for storing key-value pairs.
  final Map<String, String> data;

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async =>
      data.containsKey(key);

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async =>
      data.remove(key);

  @override
  Future<void> deleteAll({required Map<String, String> options}) async =>
      data.clear();

  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async =>
      data[key];

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async =>
      data;

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async =>
      data[key] = value;

  @override
  Future<bool> isStrongBoxSupported({
    required Map<String, String> options,
  }) async =>
      true;
}
