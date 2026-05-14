package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

public enum KeyCipherAlgorithm {
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(KeyCipherImplementationRSAOAEP::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding(KeyCipherImplementationAES23::new, Build.VERSION_CODES.M); // Renamed from AES_GCM_NoPadding_BIOMETRIC
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }

    // Migration support: Map legacy names to current values
    public static KeyCipherAlgorithm fromString(String name) {
        if ("AES_GCM_NoPadding_BIOMETRIC".equals(name)) {
            return AES_GCM_NoPadding; // Renamed in v10.1
        }
        if ("RSA_ECB_PKCS1Padding".equals(name)) {
            // Removed in v11. Map to OAEP so the plugin can initialise; old
            // ciphertext is unreadable and will be cleared by resetOnError.
            return RSA_ECB_OAEPwithSHA_256andMGF1Padding;
        }
        return valueOf(name);
    }
}
