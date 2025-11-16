package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

enum StorageCipherAlgorithm {
    AES_CBC_PKCS7Padding(StorageCipherImplementationAES18::new, 1),
    AES_GCM_NoPadding(null, Build.VERSION_CODES.M); // Implementation selected dynamically by factory

    final StorageCipherFunction storageCipher;
    final int minVersionCode;

    StorageCipherAlgorithm(StorageCipherFunction storageCipher, int minVersionCode) {
        this.storageCipher = storageCipher;
        this.minVersionCode = minVersionCode;
    }

    // Migration support: Map legacy name to new value
    public static StorageCipherAlgorithm fromString(String name) {
        if ("AES_GCM_NoPadding_BIOMETRIC".equals(name)) {
            return AES_GCM_NoPadding; // Legacy compatibility
        }
        return valueOf(name);
    }
}
