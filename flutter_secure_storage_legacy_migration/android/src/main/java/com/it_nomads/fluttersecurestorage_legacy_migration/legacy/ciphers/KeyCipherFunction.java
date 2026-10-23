package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;

@FunctionalInterface
interface KeyCipherFunction {
    KeyCipher apply(Context context, FlutterSecureStorageConfig config) throws Exception;
}
