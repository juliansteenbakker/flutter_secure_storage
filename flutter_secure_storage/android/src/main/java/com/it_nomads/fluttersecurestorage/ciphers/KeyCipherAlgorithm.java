package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(KeyCipherImplementationRSA18::new, 1),
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(KeyCipherImplementationRSAOAEP::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding_BIOMETRIC(KeyCipherImplementationAES23::new, Build.VERSION_CODES.M);
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }
}
