import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';

import 'flutter_secure_storage_platform_interface_mock.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('flutter_secure_storage_platform', () {
    test('$MethodChannelFlutterSecureStorage() is the default instance', () {
      expect(
        FlutterSecureStoragePlatform.instance,
        isInstanceOf<MethodChannelFlutterSecureStorage>(),
      );
    });

    test('Cannot be implemented with `implements`', () {
      expect(
        () {
          FlutterSecureStoragePlatform.instance =
              ImplementsFlutterSecureStoragePlatform();
        },
        throwsA(isInstanceOf<AssertionError>()),
      );
    });

    test('Can be mocked with `implements`', () {
      final mock = MockFlutterSecureStoragePlatform();
      FlutterSecureStoragePlatform.instance = mock;
    });

    test('Can be extended', () {
      FlutterSecureStoragePlatform.instance =
          ExtendsFlutterSecureStoragePlatform();
    });
  });

  group('MethodChannelFutterSecureStorage', () {
    const channel =
        MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

    final log = <MethodCall>[];

    Future<bool?>? handler(MethodCall methodCall) async {
      log.add(methodCall);

      if (methodCall.method == 'containsKey') {
        return true;
      } else if (methodCall.method == 'isProtectedDataAvailable') {
        return true;
      }

      return null;
    }

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, handler);

    final storage = MethodChannelFlutterSecureStorage();
    const options = <String, String>{};
    const key = 'test_key';

    tearDown(() {
      log.clear();
    });

    test('read', () async {
      await storage.read(key: key, options: options);

      expect(
        log,
        <Matcher>[
          isMethodCall(
            'read',
            arguments: <String, Object>{
              'key': key,
              'options': options,
            },
          ),
        ],
      );
    });

    test('write', () async {
      await storage.write(key: key, value: 'test', options: options);
      expect(
        log,
        <Matcher>[
          isMethodCall(
            'write',
            arguments: <String, Object>{
              'key': key,
              'value': 'test',
              'options': options,
            },
          ),
        ],
      );
    });

    test('containsKey', () async {
      await storage.write(key: key, value: 'test', options: options);

      final result = await storage.containsKey(key: key, options: options);

      expect(result, true);
    });

    test('delete', () async {
      await storage.write(key: key, value: 'test', options: options);
      await storage.delete(key: key, options: options);
      expect(
        log,
        <Matcher>[
          isMethodCall(
            'write',
            arguments: <String, Object>{
              'key': key,
              'value': 'test',
              'options': options,
            },
          ),
          isMethodCall(
            'delete',
            arguments: <String, Object>{
              'key': key,
              'options': options,
            },
          ),
        ],
      );
    });

    test('deleteAll', () async {
      await storage.deleteAll(options: options);
      expect(
        log,
        <Matcher>[
          isMethodCall(
            'deleteAll',
            arguments: <String, Object>{
              'options': options,
            },
          ),
        ],
      );
    });

    test('readAll', () async {
      await storage.write(key: key, value: 'test', options: options);

      await storage.readAll(options: options);

      expect(
        log,
        <Matcher>[
          isMethodCall(
            'write',
            arguments: <String, Object>{
              'key': key,
              'value': 'test',
              'options': options,
            },
          ),
          isMethodCall(
            'readAll',
            arguments: <String, Object>{
              'options': options,
            },
          ),
        ],
      );
    });

    // test('isProtectedDataAvailable', () async {
    //   final result = await storage.isCupertinoProtectedDataAvailable();
    //
    //   expect(result, true);
    // });
  });
}
