import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

void main() {
  group('FlutterSecureStorage Tests', () {
    late FlutterSecureStorage storage;

    setUp(() {
      // Initialize the storage and set mock initial values
      storage = const FlutterSecureStorage();
      FlutterSecureStorage.setMockInitialValues({});
    });

    tearDown(() {
      storage.unregisterAllListeners();
    });

    test('Write and read an int value', () async {
      await storage.write(key: 'intKey', value: 42);
      final result = await storage.read(key: 'intKey');
      expect(result, equals(42));
    });

    test('Write and read a double value', () async {
      await storage.write(key: 'doubleKey', value: 3.14);
      final result = await storage.read(key: 'doubleKey');
      expect(result, equals(3.14));
    });

    test('Write and read a String value', () async {
      await storage.write(key: 'stringKey', value: 'Hello, World!');
      final result = await storage.read(key: 'stringKey');
      expect(result, equals('Hello, World!'));
    });

    test('Write and read a bool value', () async {
      await storage.write(key: 'boolKey', value: true);
      final result = await storage.read(key: 'boolKey');
      expect(result, equals(true));
    });

    test('Write and read a List value', () async {
      await storage.write(key: 'listKey', value: [1, 2, 3]);
      final result = await storage.read(key: 'listKey');
      expect(result, equals([1, 2, 3]));
    });

    test('Write and read a Map value', () async {
      await storage.write(key: 'mapKey', value: {'a': 1, 'b': 2});
      final result = await storage.read(key: 'mapKey');
      expect(result, equals({'a': 1, 'b': 2}));
    });

    test('Ensure backward compatibility with plain strings', () async {
      // Simulate existing data stored as a plain string
      FlutterSecureStorage.setMockInitialValues({'plainKey': 'plainValue'});
      final result = await storage.read(key: 'plainKey');
      expect(result, equals('plainValue'));
    });

    test('Delete a value', () async {
      await storage.write(key: 'deleteKey', value: 'toBeDeleted');
      await storage.delete(key: 'deleteKey');
      final result = await storage.read(key: 'deleteKey');
      expect(result, isNull);
    });

    test('Read all values', () async {
      await storage.write(key: 'intKey', value: 42);
      await storage.write(key: 'stringKey', value: 'Hello');

      final allValues = await storage.readAll();
      expect(allValues['intKey'], equals(42));
      expect(allValues['stringKey'], equals('Hello'));
    });

    test('Listener is called on value change', () async {
      dynamic listenerValue;
      storage.registerListener(
        key: 'testKey',
        listener: (value) {
          listenerValue = value;
        },
      );

      await storage.write(key: 'testKey', value: 'newValue');
      expect(listenerValue, equals('newValue'));

      await storage.delete(key: 'testKey');
      expect(listenerValue, isNull);
    });

    test('Write and read null value', () async {
      await storage.write(key: 'nullKey', value: null);
      final result = await storage.read(key: 'nullKey');
      expect(result, isNull);
    });

    test('Attempt to read non-existent key', () async {
      final result = await storage.read(key: 'nonExistentKey');
      expect(result, isNull);
    });

    test('Contains key test', () async {
      await storage.write(key: 'existsKey', value: 'I exist');
      final exists = await storage.containsKey(key: 'existsKey');
      expect(exists, isTrue);

      final notExists = await storage.containsKey(key: 'noKey');
      expect(notExists, isFalse);
    });

    test('Delete all values', () async {
      await storage.write(key: 'key1', value: 'value1');
      await storage.write(key: 'key2', value: 'value2');

      await storage.deleteAll();

      final allValues = await storage.readAll();
      expect(allValues, isEmpty);
    });
  });
}
