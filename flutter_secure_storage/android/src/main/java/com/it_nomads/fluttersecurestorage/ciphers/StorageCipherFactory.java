package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage.NamespacedConfigSource;

import javax.crypto.Cipher;

public class StorageCipherFactory {
    private static final String ELEMENT_PREFERENCES_ALGORITHM_PREFIX = "FlutterSecureSAlgorithm";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_KEY = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Key";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_STORAGE = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Storage";
    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGORITHM = KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding;
    private static final StorageCipherAlgorithm DEFAULT_STORAGE_ALGORITHM = StorageCipherAlgorithm.AES_GCM_NoPadding;

    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;
    private final FlutterSecureStorageConfig config;

    public StorageCipherFactory(NamespacedConfigSource configSource, String keyCipherAlgorithm, String storageCipherAlgorithm, FlutterSecureStorageConfig config) {
        this.config = config;
        final String savedKeyCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
        final String savedStorageCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null);

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            // No algorithm markers exist, treat as a fresh install using current defaults.
            // v11 requires users to have migrated through v10 first; data from v9 or earlier
            // without markers is treated as if it uses the current defaults.
            savedKeyAlgorithm = DEFAULT_KEY_ALGORITHM;
            savedStorageAlgorithm = DEFAULT_STORAGE_ALGORITHM;
        } else {
            savedKeyAlgorithm = KeyCipherAlgorithm.fromString(savedKeyCipherAlgorithm);
            savedStorageAlgorithm = StorageCipherAlgorithm.fromString(savedStorageCipherAlgorithm);
        }

        final StorageCipherAlgorithm currentStorageAlgorithmTmp = StorageCipherAlgorithm.fromString(storageCipherAlgorithm);
        currentStorageAlgorithm = (currentStorageAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentStorageAlgorithmTmp : DEFAULT_STORAGE_ALGORITHM;

        // Set current key algorithm with version check
        final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.fromString(keyCipherAlgorithm);
        currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            // Don't write algorithm markers during migrateWithBackup
            // (the migration flow writes them at step 7 after success).
            if (!config.shouldMigrateWithBackup()) {
                final SharedPreferences.Editor source = configSource.edit();
                storeCurrentAlgorithms(source);
                source.apply();
            }
        }
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    public boolean changedKeyAlgorithm() {
        return savedKeyAlgorithm != currentKeyAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher.apply(context, config);
        return createStorageCipher(context, keyCipher, cipher, savedStorageAlgorithm);
    }

    public StorageCipher getCurrentStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher.apply(context, config);
        return createStorageCipher(context, keyCipher, cipher, currentStorageAlgorithm);
    }

    /**
     * Dynamically selects the appropriate StorageCipher implementation based on
     * the KeyCipher type and StorageCipherAlgorithm.
     */
    /* package */ StorageCipher createStorageCipher(Context context, KeyCipher keyCipher,
                                               Cipher cipher, StorageCipherAlgorithm algorithm) throws Exception {
        // For AES_GCM_NoPadding, choose implementation based on KeyCipher type
        if (algorithm == StorageCipherAlgorithm.AES_GCM_NoPadding) {
            if (isKeyStoreKeyCipher(keyCipher)) {
                // Use KeyStore-based implementation (biometric/PIN auth capable)
                return new StorageCipherImplementationAES23(context, keyCipher, cipher, config);
            } else {
                // Use RSA-wrapped implementation (standard secure storage)
                return new StorageCipherImplementationGCM(context, keyCipher, cipher, config);
            }
        }

        // For other algorithms, use the function from enum
        if (algorithm.storageCipher == null) {
            throw new Exception("No implementation available for algorithm: " + algorithm.name());
        }
        return algorithm.storageCipher.apply(context, keyCipher, cipher, config);
    }

    /**
     * Checks if the KeyCipher uses KeyStore (AES) vs RSA wrapping.
     */
    private boolean isKeyStoreKeyCipher(KeyCipher keyCipher) {
        return keyCipher instanceof KeyCipherImplementationAES23;
    }

    public KeyCipher getCurrentKeyCipher(Context context) throws Exception {
        return currentKeyAlgorithm.keyCipher.apply(context, config);
    }

    public KeyCipher getSavedKeyCipher(Context context) throws Exception {
        return savedKeyAlgorithm.keyCipher.apply(context, config);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }
}
