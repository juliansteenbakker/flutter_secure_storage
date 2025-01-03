part of '../flutter_secure_storage.dart';

/// Specific options for web platform.
class WebOptions extends Options {
  const WebOptions({
    this.dbName = 'FlutterEncryptedStorage',
    this.publicKey = 'FlutterSecureStorage',
    this.wrapKey = '',
    this.wrapKeyIv = '',
    this.useSessionStorage = false,
  });

  static const WebOptions defaultOptions = WebOptions();

  final String dbName;
  final String publicKey;
  final String wrapKey;
  final String wrapKeyIv;
  final bool useSessionStorage;

  @override
  Map<String, String> toMap() => <String, String>{
        'dbName': dbName,
        'publicKey': publicKey,
        'wrapKey': wrapKey,
        'wrapKeyIv': wrapKeyIv,
        'useSessionStorage': useSessionStorage.toString(),
      };
}
