import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';

class TestFlutterSecureStoragePlatform extends FlutterSecureStoragePlatform {
  final Map<String, String> data;

  TestFlutterSecureStoragePlatform(this.data);

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

// @override
// Future<bool> isCupertinoProtectedDataAvailable() => Future.value(true);
//
// @override
// Stream<bool> get onCupertinoProtectedDataAvailabilityChanged =>
//     Stream.value(true);
}
