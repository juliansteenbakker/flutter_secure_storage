part of '../flutter_secure_storage_platform_interface.dart';

const MethodChannel _channel =
    MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

const EventChannel _eventChannel =
    EventChannel('plugins.it_nomads.com/flutter_secure_storage/events');

/// The `MethodChannelFlutterSecureStorage` class implements the
/// `FlutterSecureStoragePlatform` interface using method channels to
/// communicate with native platform code.
class MethodChannelFlutterSecureStorage extends FlutterSecureStoragePlatform {
  /// A stream that emits updates when the availability of Cupertino protected
  /// data changes. It is only relevant on iOS and macOS platforms.
  ///
  /// Returns:
  /// - A [Stream] of boolean values indicating the availability of protected
  ///   data.
  Stream<bool> get onCupertinoProtectedDataAvailabilityChanged => _eventChannel
      .receiveBroadcastStream()
      .where((event) => event is bool)
      .map((event) => event as bool);

  /// Checks if Cupertino protected data is currently available on the device.
  /// It is only supported on iOS and macOS platforms.
  ///
  /// Returns:
  /// - A [Future] resolving to:
  ///   - `true` if protected data is available.
  ///   - `false` if protected data is not available.
  ///   - `null` if the platform does not support this functionality.
  Future<bool?> isCupertinoProtectedDataAvailable() async {
    if (kIsWeb ||
        !(defaultTargetPlatform == TargetPlatform.iOS ||
            defaultTargetPlatform == TargetPlatform.macOS)) {
      return null;
    }
    return (await _channel.invokeMethod<bool>('isProtectedDataAvailable')) ??
        false;
  }

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async =>
      (await _channel.invokeMethod<bool>(
        'containsKey',
        {
          'key': key,
          'options': options,
        },
      ))!;

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) =>
      _channel.invokeMethod<void>(
        'delete',
        {
          'key': key,
          'options': options,
        },
      );

  @override
  Future<void> deleteAll({
    required Map<String, String> options,
  }) =>
      _channel.invokeMethod<void>(
        'deleteAll',
        {
          'options': options,
        },
      );

  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) =>
      _channel.invokeMethod<String?>(
        'read',
        {
          'key': key,
          'options': options,
        },
      );

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    final results = await _channel.invokeMethod<Map<Object?, Object?>>(
      'readAll',
      {
        'options': options,
      },
    );

    return results?.cast<String, String>() ?? <String, String>{};
  }

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) =>
      _channel.invokeMethod<void>('write', {
        'key': key,
        'value': value,
        'options': options,
      });

  @override
  Future<bool> isStrongBoxSupported() async {
    if (defaultTargetPlatform != TargetPlatform.android) {
      throw UnsupportedError('StrongBox is only supported on Android.');
    }
    return (await _channel
            .invokeMethod<bool>('isStrongBoxSupported', {'key': ''})) ??
        false;
  }
}
