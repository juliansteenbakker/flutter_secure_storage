package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

@FunctionalInterface
interface KeyCipherFunction {
    KeyCipher apply(Context context, FlutterSecureStorageConfig config) throws Exception;
}
