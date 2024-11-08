/// Web library for flutter_secure_storage
library flutter_secure_storage_web;

import 'dart:convert';
import 'dart:js_interop' as js_interop;
import 'dart:js_interop_unsafe' as js_interop;
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:web/web.dart' as web;

/// Web implementation of FlutterSecureStorage
class FlutterSecureStorageWeb extends FlutterSecureStoragePlatform {
  static const _publicKey = 'publicKey';
  static const _wrapKey = 'wrapKey';
  static const _wrapKeyIv = 'wrapKeyIv';

  /// Registrar for FlutterSecureStorageWeb
  static void registerWith(Registrar registrar) {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageWeb();
  }

  /// Returns true if the storage contains the given [key].
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) =>
      Future.value(
        web.window.localStorage.has("${options[_publicKey]!}.$key"),
      );

  /// Deletes associated value for the given [key].
  ///
  /// If the given [key] does not exist, nothing will happen.
  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async {
    web.window.localStorage.removeItem("${options[_publicKey]!}.$key");
  }

  /// Deletes all keys with associated values.
  @override
  Future<void> deleteAll({
    required Map<String, String> options,
  }) async {
    final publicKey = options[_publicKey]!;
    final keys = [publicKey];
    for (int j = 0; j < web.window.localStorage.length; j++) {
      final key = web.window.localStorage.key(j) ?? "";
      if (!key.startsWith('$publicKey.')) {
        continue;
      }

      keys.add(key);
    }

    for (final key in keys) {
      web.window.localStorage.removeItem(key);
    }
  }

  /// Encrypts and saves the [key] with the given [value].
  ///
  /// If the key was already in the storage, its associated value is changed.
  /// If the value is null, deletes associated value for the given [key].
  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    final value = web.window.localStorage["${options[_publicKey]!}.$key"];

    return _decryptValue(value, options);
  }

  /// Decrypts and returns all keys with associated values.
  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    final map = <String, String>{};
    final prefix = "${options[_publicKey]!}.";
    for (int j = 0; j < web.window.localStorage.length; j++) {
      final key = web.window.localStorage.key(j) ?? "";
      if (!key.startsWith(prefix)) {
        continue;
      }

      final value =
          await _decryptValue(web.window.localStorage.getItem(key), options);

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
    late web.CryptoKey encryptionKey;
    final key = options[_publicKey]!;
    final useWrapKey = options[_wrapKey]?.isNotEmpty ?? false;

    if (web.window.localStorage.has(key)) {
      final jwk = base64Decode(web.window.localStorage[key]!);

      if (useWrapKey) {
        final unwrappingKey = await _getWrapKey(options);
        final unwrapAlgorithm = _getWrapAlgorithm(options);
        encryptionKey = await web.window.crypto.subtle
            .unwrapKey(
              "raw",
              jwk.toJS,
              unwrappingKey,
              unwrapAlgorithm,
              algorithm,
              false,
              ["encrypt", "decrypt"].toJS,
            )
            .toDart;
      } else {
        encryptionKey = await web.window.crypto.subtle
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
      encryptionKey = (await web.window.crypto.subtle
          .generateKey(algorithm, true, ["encrypt", "decrypt"].toJS)
          .toDart)! as web.CryptoKey;

      final js_interop.JSAny? jsonWebKey;
      if (useWrapKey) {
        final wrappingKey = await _getWrapKey(options);
        final wrapAlgorithm = _getWrapAlgorithm(options);
        jsonWebKey = await web.window.crypto.subtle
            .wrapKey(
              "raw",
              encryptionKey,
              wrappingKey,
              wrapAlgorithm,
            )
            .toDart;
      } else {
        jsonWebKey = await web.window.crypto.subtle
            .exportKey("raw", encryptionKey)
            .toDart;
      }

      web.window.localStorage[key] = base64Encode(
        (jsonWebKey! as js_interop.JSArrayBuffer).toDart.asUint8List(),
      );
    }

    return encryptionKey;
  }

  Future<web.CryptoKey> _getWrapKey(Map<String, String> options) async {
    final wrapKey = base64Decode(options[_wrapKey]!);
    final algorithm = _getWrapAlgorithm(options);
    return await web.window.crypto.subtle
        .importKey(
          "raw",
          wrapKey.toJS,
          algorithm,
          true,
          ["wrapKey", "unwrapKey"].toJS,
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
    final iv = (web.window.crypto.getRandomValues(Uint8List(12).toJS)
            as js_interop.JSUint8Array)
        .toDart;

    final algorithm = _getAlgorithm(iv);

    final encryptionKey = await _getEncryptionKey(algorithm, options);

    final encryptedContent = (await web.window.crypto.subtle
        .encrypt(
          algorithm,
          encryptionKey,
          Uint8List.fromList(
            utf8.encode(value),
          ).toJS,
        )
        .toDart)! as js_interop.JSArrayBuffer;

    final encoded =
        "${base64Encode(iv)}.${base64Encode(encryptedContent.toDart.asUint8List())}";

    web.window.localStorage["${options[_publicKey]!}.$key"] = encoded;
  }

  Future<String?> _decryptValue(
    String? cypherText,
    Map<String, String> options,
  ) async {
    if (cypherText == null) {
      return null;
    }

    final parts = cypherText.split(".");

    final iv = base64Decode(parts[0]);
    final algorithm = _getAlgorithm(iv);

    final decryptionKey = await _getEncryptionKey(algorithm, options);

    final value = base64Decode(parts[1]);

    final decryptedContent = await web.window.crypto.subtle
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
  }

// @override
// Future<bool> isCupertinoProtectedDataAvailable() => Future.value(false);
//
// @override
// Stream<bool> get onCupertinoProtectedDataAvailabilityChanged =>
//     Stream.empty();
}

extension on List<String> {
  js_interop.JSArray<js_interop.JSString> get toJS => [
        ...map((e) => e.toJS),
      ].toJS;
}
