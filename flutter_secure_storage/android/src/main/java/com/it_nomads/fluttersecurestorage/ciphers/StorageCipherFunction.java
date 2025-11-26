package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import javax.crypto.Cipher;

@FunctionalInterface
interface StorageCipherFunction {
    StorageCipher apply(Context context, KeyCipher keyCipher, Cipher cipher) throws Exception;
}
