library flutter_secure_storage_platform_interface;

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

part './src/method_channel_flutter_secure_storage.dart';
part './src/options.dart';

/// The interface that implementations of flutter_secure_storage must implement.
///
/// Platform implementations should extend this class rather than implement it as `flutter_secure_storage`
/// does not consider newly added methods to be breaking changes. Extending this class
/// (using `extends`) ensures that the subclass will get the default implementation, while
/// platform implementations that `implements` this interface will be broken by newly added
/// [FlutterSecureStoragePlatform] methods.
abstract class FlutterSecureStoragePlatform extends PlatformInterface {
  FlutterSecureStoragePlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterSecureStoragePlatform _instance =
      MethodChannelFlutterSecureStorage();

  static FlutterSecureStoragePlatform get instance => _instance;

  static set instance(FlutterSecureStoragePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  });

  Future<String?> read({
    required String key,
    required Map<String, String> options,
  });

  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  });

  Future<void> delete({
    required String key,
    required Map<String, String> options,
  });

  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  });

  Future<void> deleteAll({
    required Map<String, String> options,
  });
}
