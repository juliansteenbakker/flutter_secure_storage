package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Map;

import javax.crypto.Cipher;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(RSACipher18Implementation::new, 1),
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(RSACipherOAEPImplementation::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding_BIOMETRIC(AESCipher23Implementation::new, Build.VERSION_CODES.M);
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }
}

enum StorageCipherAlgorithm {
    AES_CBC_PKCS7Padding(StorageCipher18Implementation::new, 1),
    AES_GCM_NoPadding(StorageCipherGCMImplementation::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding_BIOMETRIC(StorageCipher23Implementation::new, Build.VERSION_CODES.M);
    final StorageCipherFunction storageCipher;
    final int minVersionCode;

    StorageCipherAlgorithm(StorageCipherFunction storageCipher, int minVersionCode) {
        this.storageCipher = storageCipher;
        this.minVersionCode = minVersionCode;
    }
}

@FunctionalInterface
interface StorageCipherFunction {
    StorageCipher apply(Context context, KeyCipher keyCipher, Cipher cipher) throws Exception;
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

        final StorageCipherAlgorithm currentStorageAlgorithmTmp = StorageCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "storageCipherAlgorithm", DEFAULT_STORAGE_ALGORITHM.name()));
        currentStorageAlgorithm = (currentStorageAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentStorageAlgorithmTmp : DEFAULT_STORAGE_ALGORITHM;

        // Conditional auto-pairing for biometric storage
        if (currentStorageAlgorithm == StorageCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC) {
            // Force correct key cipher for biometric storage
            currentKeyAlgorithm = KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC;
        } else {
            // Allow user choice for non-biometric storage
            final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "keyCipherAlgorithm", DEFAULT_KEY_ALGORITHM.name()));
            currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;
        }

        // Validate combination (safety net in case Flutter asserts are disabled)
        validateCombination(currentKeyAlgorithm, currentStorageAlgorithm);
    }

    private String getFromOptionsWithDefault(Map<String, Object> options, String key, String defaultValue) {
        final Object value = options.get(key);
        return value != null ? value.toString() : defaultValue;
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

        // Non-biometric storage algorithms require RSA key ciphers (which use wrap/unwrap)
        if ((storageCipher == StorageCipherAlgorithm.AES_CBC_PKCS7Padding
                || storageCipher == StorageCipherAlgorithm.AES_GCM_NoPadding)
                && keyCipher == KeyCipherAlgorithm.AES_GCM_NoPadding_BIOMETRIC) {
            throw new IllegalArgumentException(
                    "Invalid cipher combination: " + storageCipher.name() + " storage requires " +
                            "RSA key cipher (PKCS1 or OAEP), not AES_GCM_NoPadding_BIOMETRIC. " +
                            "Use AndroidOptions.standard() or AndroidOptions.standardSecure() in Flutter."
            );
        }
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
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

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }

    public void removeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_KEY);
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_STORAGE);
    }
}
