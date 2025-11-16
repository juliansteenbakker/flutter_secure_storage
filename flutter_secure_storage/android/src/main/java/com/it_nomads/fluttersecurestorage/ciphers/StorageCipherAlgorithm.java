package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

enum StorageCipherAlgorithm {
    AES_CBC_PKCS7Padding(StorageCipherImplementationAES18::new, 1),
    AES_GCM_NoPadding(StorageCipherImplementationGCM::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding_BIOMETRIC(StorageCipherImplementationAES23::new, Build.VERSION_CODES.M);
    final StorageCipherFunction storageCipher;
    final int minVersionCode;

    StorageCipherAlgorithm(StorageCipherFunction storageCipher, int minVersionCode) {
        this.storageCipher = storageCipher;
        this.minVersionCode = minVersionCode;
    }
}
