package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;

import javax.crypto.Cipher;

@FunctionalInterface
interface StorageCipherFunction {
    StorageCipher apply(Context context, KeyCipher keyCipher, Cipher cipher, FlutterSecureStorageConfig config) throws Exception;
}
