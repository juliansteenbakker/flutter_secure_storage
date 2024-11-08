package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Map;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(RSACipher18Implementation::new, 1),
    @SuppressWarnings({"UnusedDeclaration"})
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(RSACipherOAEPImplementation::new, Build.VERSION_CODES.M);
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }
}

enum StorageCipherAlgorithm {
    AES_CBC_PKCS7Padding(StorageCipher18Implementation::new, 1),
    @SuppressWarnings({"UnusedDeclaration"})
    AES_GCM_NoPadding(StorageCipherGCMImplementation::new, Build.VERSION_CODES.M);
    final StorageCipherFunction storageCipher;
    final int minVersionCode;

    StorageCipherAlgorithm(StorageCipherFunction storageCipher, int minVersionCode) {
        this.storageCipher = storageCipher;
        this.minVersionCode = minVersionCode;
    }
}

@FunctionalInterface
interface StorageCipherFunction {
    StorageCipher apply(Context context, KeyCipher keyCipher) throws Exception;
}

@FunctionalInterface
interface KeyCipherFunction {
    KeyCipher apply(Context context) throws Exception;
}

public class StorageCipherFactory {
    private static final String ELEMENT_PREFERENCES_ALGORITHM_PREFIX = "FlutterSecureSAlgorithm";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_KEY = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Key";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_STORAGE = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Storage";
    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGORITHM = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding;
    private static final StorageCipherAlgorithm DEFAULT_STORAGE_ALGORITHM = StorageCipherAlgorithm.AES_CBC_PKCS7Padding;

    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;

    public StorageCipherFactory(SharedPreferences source, Map<String, Object> options) {
        savedKeyAlgorithm = KeyCipherAlgorithm.valueOf(source.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, DEFAULT_KEY_ALGORITHM.name()));
        savedStorageAlgorithm = StorageCipherAlgorithm.valueOf(source.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, DEFAULT_STORAGE_ALGORITHM.name()));

        final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "keyCipherAlgorithm", DEFAULT_KEY_ALGORITHM.name()));
        currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;
        final StorageCipherAlgorithm currentStorageAlgorithmTmp = StorageCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "storageCipherAlgorithm", DEFAULT_STORAGE_ALGORITHM.name()));
        currentStorageAlgorithm = (currentStorageAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentStorageAlgorithmTmp : DEFAULT_STORAGE_ALGORITHM;
    }

    private String getFromOptionsWithDefault(Map<String, Object> options, String key, String defaultValue) {
        final Object value = options.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher.apply(context);
        return savedStorageAlgorithm.storageCipher.apply(context, keyCipher);
    }

    public StorageCipher getCurrentStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher.apply(context);
        return currentStorageAlgorithm.storageCipher.apply(context, keyCipher);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }

    public void removeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_KEY);
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_STORAGE);
    }
}
