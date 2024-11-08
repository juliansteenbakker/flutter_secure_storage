import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:mockito/mockito.dart';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockMethodChannel extends Mock implements MethodChannel {}

class MockFlutterSecureStoragePlatform extends Mock
    with MockPlatformInterfaceMixin
    implements FlutterSecureStoragePlatform {}

class ImplementsFlutterSecureStoragePlatform extends Mock
    implements FlutterSecureStoragePlatform {}

class ExtendsFlutterSecureStoragePlatform extends FlutterSecureStoragePlatform {
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) =>
      Future.value(true);

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) =>
      Future<void>.value();

  @override
  Future<void> deleteAll({required Map<String, String> options}) =>
      Future<void>.value();

  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) =>
      Future<String?>.value();

  @override
  Future<Map<String, String>> readAll({required Map<String, String> options}) =>
      Future.value(<String, String>{});

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) =>
      Future<void>.value();

  // @override
  // Future<bool> isCupertinoProtectedDataAvailable() => Future.value(true);
  //
  // @override
  // Stream<bool> get onCupertinoProtectedDataAvailabilityChanged =>
  //     Stream.value(true);
}
