package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(KeyCipherImplementationRSA18::new, 1),
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(KeyCipherImplementationRSAOAEP::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding(KeyCipherImplementationAES23::new, Build.VERSION_CODES.M); // Renamed from AES_GCM_NoPadding_BIOMETRIC
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }

    // Migration support: Map legacy name to new value
    public static KeyCipherAlgorithm fromString(String name) {
        if ("AES_GCM_NoPadding_BIOMETRIC".equals(name)) {
            return AES_GCM_NoPadding; // Legacy compatibility
        }
        return valueOf(name);
    }
}
