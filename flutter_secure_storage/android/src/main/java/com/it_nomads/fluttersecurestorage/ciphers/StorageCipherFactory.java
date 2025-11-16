package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import javax.crypto.Cipher;

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

    public StorageCipherFactory(SharedPreferences configSource, String keyCipherAlgorithm, String storageCipherAlgorithm) {
        final String savedKeyCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
        final String savedStorageCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null);

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            savedKeyAlgorithm = KeyCipherAlgorithm.valueOf(keyCipherAlgorithm);
            savedStorageAlgorithm = StorageCipherAlgorithm.valueOf(storageCipherAlgorithm);
        } else {
            savedKeyAlgorithm = KeyCipherAlgorithm.valueOf(savedKeyCipherAlgorithm);
            savedStorageAlgorithm = StorageCipherAlgorithm.valueOf(savedStorageCipherAlgorithm);
        }

        final StorageCipherAlgorithm currentStorageAlgorithmTmp = StorageCipherAlgorithm.valueOf(storageCipherAlgorithm);
        currentStorageAlgorithm = (currentStorageAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentStorageAlgorithmTmp : DEFAULT_STORAGE_ALGORITHM;

        // Conditional auto-pairing for biometric storage
        if (currentStorageAlgorithm == StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC) {
            // Force correct key cipher for biometric storage
            currentKeyAlgorithm = KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC;
        } else {
            // Allow user choice for non-biometric storage
            final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.valueOf(keyCipherAlgorithm);
            currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;
        }

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            final SharedPreferences.Editor source = configSource.edit();
            storeCurrentAlgorithms(source);
            source.apply();
        }

        // Validate combination (safety net in case Flutter asserts are disabled)
        validateCombination(currentKeyAlgorithm, currentStorageAlgorithm);
    }

    /**
     * Validates that the key cipher and storage cipher combination is valid.
     *
     * @throws IllegalArgumentException if the combination is invalid
     */
    private void validateCombination(KeyCipherAlgorithm keyCipher, StorageCipherAlgorithm storageCipher) {
        // Biometric storage MUST use biometric key cipher
        if (storageCipher == StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC
                && keyCipher != KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC) {
            throw new IllegalArgumentException(
                    "Invalid cipher combination: AES_GCM_NoPadding_BIOMETRIC storage requires " +
                            "AES_GCM_NoPadding_BIOMETRIC key cipher. Got: " + keyCipher.name() +
                            ". Use AndroidOptions.biometric() in Flutter."
            );
        }

        // Biometric key cipher MUST be used with biometric storage
        if (keyCipher == KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC
                && storageCipher != StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC) {
            throw new IllegalArgumentException(
                    "Invalid cipher combination: AES_GCM_NoPadding_BIOMETRIC key cipher can only " +
                            "be used with AES_GCM_NoPadding_BIOMETRIC storage. Got: " + storageCipher.name() +
                            ". Use AndroidOptions.biometric() in Flutter."
            );
        }
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    public boolean changedKeyAlgorithm() {
        return savedKeyAlgorithm != currentKeyAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher.apply(context);
        return savedStorageAlgorithm.storageCipher.apply(context, keyCipher, cipher);
    }

    public StorageCipher getCurrentStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher.apply(context);
        return currentStorageAlgorithm.storageCipher.apply(context, keyCipher, cipher);
    }

    public KeyCipher getCurrentKeyCipher(Context context) throws Exception {
        return currentKeyAlgorithm.keyCipher.apply(context);
    }

    public KeyCipher getSavedKeyCipher(Context context) throws Exception {
        return savedKeyAlgorithm.keyCipher.apply(context);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }
}
