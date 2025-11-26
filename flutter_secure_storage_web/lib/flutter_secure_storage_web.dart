/// Web library for flutter_secure_storage
library;

import 'dart:convert';
import 'dart:js_interop' as js_interop;
import 'dart:js_interop_unsafe' as js_interop;

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:web/web.dart' as web;

/// Web implementation of FlutterSecureStorage
class FlutterSecureStorageWeb extends FlutterSecureStoragePlatform {
  static const _publicKey = 'publicKey';
  static const _wrapKey = 'wrapKey';
  static const _wrapKeyIv = 'wrapKeyIv';
  static const _useSessionStorage = 'useSessionStorage';

  /// Registrar for FlutterSecureStorageWeb
  static void registerWith(Registrar registrar) {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageWeb();
  }

  web.Crypto get _crypto {
    if (web.window.isSecureContext) {
      return web.window.crypto;
    }

    throw UnsupportedError(
      'FlutterSecureStorageWeb only works in secure contexts '
      'Refer to the documentation for more information: '
      'https://pub.dev/packages/flutter_secure_storage#configure-web-version',
    );
  }

  web.Storage _getStorage(Map<String, String> options) {
    return options[_useSessionStorage] == 'true'
        ? web.window.sessionStorage
        : web.window.localStorage;
  }

  /// Returns true if the storage contains the given [key].
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) =>
      Future.value(
        _getStorage(options).has('${options[_publicKey]!}.$key'),
      );

  /// Deletes associated value for the given [key].
  ///
  /// If the given [key] does not exist, nothing will happen.
  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async {
    _getStorage(options).removeItem('${options[_publicKey]!}.$key');
  }

  /// Deletes all keys with associated values.
  @override
  Future<void> deleteAll({
    required Map<String, String> options,
  }) async {
    final storage = _getStorage(options);
    final publicKey = options[_publicKey]!;
    final keys = [publicKey];
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (!key.startsWith('$publicKey.')) {
        continue;
      }

      keys.add(key);
    }

    for (final key in keys) {
      storage.removeItem(key);
    }
  }

  /// Reads and decrypts the value for the given [key].
  ///
  /// Returns null if the key does not exist or if decryption fails.
  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    final value = _getStorage(options).getItem('${options[_publicKey]!}.$key');

    return _decryptValue(value, options);
  }

  /// Decrypts and returns all keys with associated values.
  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    final storage = _getStorage(options);
    final map = <String, String>{};
    final prefix = '${options[_publicKey]!}.';
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (!key.startsWith(prefix)) {
        continue;
      }

      final value = await _decryptValue(storage.getItem(key), options);

      if (value == null) {
        continue;
      }

      map[key.substring(prefix.length)] = value;
    }

    return map;
  }

  js_interop.JSAny _getAlgorithm(Uint8List iv) {
    return {'name': 'AES-GCM', 'length': 256, 'iv': iv}.jsify()!;
  }

  Future<web.CryptoKey> _getEncryptionKey(
    js_interop.JSAny algorithm,
    Map<String, String> options,
  ) async {
    final storage = _getStorage(options);
    late web.CryptoKey encryptionKey;
    final key = options[_publicKey]!;
    final useWrapKey = options[_wrapKey]?.isNotEmpty ?? false;

    if (storage.has(key)) {
      final jwk = base64Decode(storage.getItem(key)!);

      if (useWrapKey) {
        final unwrappingKey = await _getWrapKey(options);
        final unwrapAlgorithm = _getWrapAlgorithm(options);
        encryptionKey = await _crypto.subtle
            .unwrapKey(
              'raw',
              jwk.toJS,
              unwrappingKey,
              unwrapAlgorithm,
              algorithm,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart;
      } else {
        encryptionKey = await _crypto.subtle
            .importKey(
              'raw',
              jwk.toJS,
              algorithm,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart;
      }
    } else {
      encryptionKey = (await _crypto.subtle
          .generateKey(algorithm, true, ['encrypt', 'decrypt'].toJS)
          .toDart)! as web.CryptoKey;

      final js_interop.JSAny? jsonWebKey;
      if (useWrapKey) {
        final wrappingKey = await _getWrapKey(options);
        final wrapAlgorithm = _getWrapAlgorithm(options);
        jsonWebKey = await _crypto.subtle
            .wrapKey(
              'raw',
              encryptionKey,
              wrappingKey,
              wrapAlgorithm,
            )
            .toDart;
      } else {
        jsonWebKey =
            await _crypto.subtle.exportKey('raw', encryptionKey).toDart;
      }

      storage.setItem(
        key,
        base64Encode(
          (jsonWebKey! as js_interop.JSArrayBuffer).toDart.asUint8List(),
        ),
      );
    }

    return encryptionKey;
  }

  Future<web.CryptoKey> _getWrapKey(Map<String, String> options) async {
    final wrapKey = base64Decode(options[_wrapKey]!);
    final algorithm = _getWrapAlgorithm(options);
    return _crypto.subtle
        .importKey(
          'raw',
          wrapKey.toJS,
          algorithm,
          true,
          ['wrapKey', 'unwrapKey'].toJS,
        )
        .toDart;
  }

  js_interop.JSAny _getWrapAlgorithm(Map<String, String> options) {
    final iv = base64Decode(options[_wrapKeyIv]!);
    return _getAlgorithm(iv);
  }

  /// Encrypts and saves the [key] with the given [value].
  ///
  /// If the key was already in the storage, its associated value is changed.
  /// If the value is null, deletes associated value for the given [key].
  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async {
    final iv =
        (_crypto.getRandomValues(Uint8List(12).toJS) as js_interop.JSUint8Array)
            .toDart;

    final algorithm = _getAlgorithm(iv);

    final encryptionKey = await _getEncryptionKey(algorithm, options);

    final encryptedContent = (await _crypto.subtle
        .encrypt(
          algorithm,
          encryptionKey,
          Uint8List.fromList(
            utf8.encode(value),
          ).toJS,
        )
        .toDart)! as js_interop.JSArrayBuffer;

    final encoded = '${base64Encode(iv)}.'
        '${base64Encode(encryptedContent.toDart.asUint8List())}';

    _getStorage(options).setItem('${options[_publicKey]!}.$key', encoded);
  }

  Future<String?> _decryptValue(
    String? cypherText,
    Map<String, String> options,
  ) async {
    if (cypherText != null) {
      try {
        final parts = cypherText.split('.');

        final iv = base64Decode(parts[0]);
        final algorithm = _getAlgorithm(iv);

        final decryptionKey = await _getEncryptionKey(algorithm, options);

        final value = base64Decode(parts[1]);

        final decryptedContent = await _crypto.subtle
            .decrypt(
              _getAlgorithm(iv),
              decryptionKey,
              Uint8List.fromList(value).toJS,
            )
            .toDart;

        final plainText = utf8.decode(
          (decryptedContent! as js_interop.JSArrayBuffer).toDart.asUint8List(),
        );

        return plainText;
      } on Exception catch (e, s) {
        if (kDebugMode) {
          print(e);
          debugPrintStack(stackTrace: s);
        }
      }
    }

    return null;
  }
}

extension on List<String> {
  js_interop.JSArray<js_interop.JSString> get toJS => [
        ...map((e) => e.toJS),
      ].toJS;
}
