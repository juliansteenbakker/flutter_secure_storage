part of '../flutter_secure_storage.dart';

/// Specific options for web platform.
class WebOptions extends Options {
  const WebOptions({
    this.dbName = 'FlutterEncryptedStorage',
    this.publicKey = 'FlutterSecureStorage',
    this.wrapKey = '',
    this.wrapKeyIv = '',
  });

  static const WebOptions defaultOptions = WebOptions();

  final String dbName;
  final String publicKey;
  final String wrapKey;
  final String wrapKeyIv;

  @override
  Map<String, String> toMap() => <String, String>{
        'dbName': dbName,
        'publicKey': publicKey,
        'wrapKey': wrapKey,
        'wrapKeyIv': wrapKeyIv,
      };
}
