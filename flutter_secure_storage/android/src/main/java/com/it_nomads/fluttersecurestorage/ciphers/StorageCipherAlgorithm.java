package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

public enum StorageCipherAlgorithm {
    AES_GCM_NoPadding(null, Build.VERSION_CODES.M); // Implementation selected dynamically by factory

    final StorageCipherFunction storageCipher;
    final int minVersionCode;

    StorageCipherAlgorithm(StorageCipherFunction storageCipher, int minVersionCode) {
        this.storageCipher = storageCipher;
        this.minVersionCode = minVersionCode;
    }

    // Migration support: Map legacy names to current values
    public static StorageCipherAlgorithm fromString(String name) {
        if ("AES_GCM_NoPadding_BIOMETRIC".equals(name)) {
            return AES_GCM_NoPadding; // Renamed in v10.1
        }
        if ("AES_CBC_PKCS7Padding".equals(name)) {
            // Removed in v11. Map to GCM so the plugin can initialise; old
            // ciphertext is unreadable and will be cleared by resetOnError.
            return AES_GCM_NoPadding;
        }
        return valueOf(name);
    }
}
