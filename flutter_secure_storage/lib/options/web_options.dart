part of '../flutter_secure_storage.dart';

/// Specific options for web platform.
class WebOptions extends Options {
  const WebOptions({
    this.dbName = 'FlutterEncryptedStorage',
    this.publicKey = 'FlutterSecureStorage',
  });

  static const WebOptions defaultOptions = WebOptions();

  final String dbName;
  final String publicKey;

  @override
  Map<String, String> toMap() => <String, String>{
        'dbName': dbName,
        'publicKey': publicKey,
      };
}
