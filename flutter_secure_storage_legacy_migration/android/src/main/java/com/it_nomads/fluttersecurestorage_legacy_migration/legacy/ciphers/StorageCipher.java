package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;

public interface StorageCipher {
    byte[] encrypt(byte[] input) throws Exception;

    byte[] decrypt(byte[] input) throws Exception;

    void deleteKey(Context context) throws Exception;

    default boolean sharesKeyStorageWith(StorageCipher other) {
        return true;
    }
}
