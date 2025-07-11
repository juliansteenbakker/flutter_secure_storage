package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Map;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(RSACipher18Implementation::new, 1),
    @SuppressWarnings("UnusedDeclaration")
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(RSACipherOAEPImplementation::new, Build.VERSION_CODES.M);

    final KeyCipherFunction factory;
    final int minSdk;

    KeyCipherAlgorithm(KeyCipherFunction factory, int minSdk) {
        this.factory = factory;
        this.minSdk = minSdk;
    }

    public boolean isSupported() {
        return Build.VERSION.SDK_INT >= minSdk;
    }
}

enum StorageCipherAlgorithm {
    AES_GCM_NoPadding(StorageCipherGCMImplementation::new, Build.VERSION_CODES.M);

    final StorageCipherFunction factory;
    final int minSdk;

    StorageCipherAlgorithm(StorageCipherFunction factory, int minSdk) {
        this.factory = factory;
        this.minSdk = minSdk;
    }

    public boolean isSupported() {
        return Build.VERSION.SDK_INT >= minSdk;
    }
}

@FunctionalInterface
interface KeyCipherFunction {
    KeyCipher apply(Context context) throws Exception;
}

@FunctionalInterface
interface StorageCipherFunction {
    StorageCipher apply(Context context, KeyCipher keyCipher) throws Exception;
}

public class StorageCipherFactory {
    private static final String PREFS_KEY_PREFIX = "FlutterSecureSAlgorithm";
    private static final String PREFS_KEY_KEY_CIPHER = PREFS_KEY_PREFIX + "Key";
    private static final String PREFS_KEY_STORAGE_CIPHER = PREFS_KEY_PREFIX + "Storage";

    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGO = KeyCipherAlgorithm.RSA_ECB_PKCS1Padding;
    private static final StorageCipherAlgorithm DEFAULT_STORAGE_ALGO = StorageCipherAlgorithm.AES_GCM_NoPadding;

    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;

    public StorageCipherFactory(SharedPreferences prefs, Map<String, Object> options) {
        this.savedKeyAlgorithm = parseEnumOrDefault(
                KeyCipherAlgorithm.class,
                prefs.getString(PREFS_KEY_KEY_CIPHER, null),
                DEFAULT_KEY_ALGO
        );

        this.savedStorageAlgorithm = parseEnumOrDefault(
                StorageCipherAlgorithm.class,
                prefs.getString(PREFS_KEY_STORAGE_CIPHER, null),
                DEFAULT_STORAGE_ALGO
        );

        KeyCipherAlgorithm selectedKeyAlgo = parseEnumOrDefault(
                KeyCipherAlgorithm.class,
                getOptionOrDefault(options, "keyCipherAlgorithm", DEFAULT_KEY_ALGO.name()),
                DEFAULT_KEY_ALGO
        );
        this.currentKeyAlgorithm = selectedKeyAlgo.isSupported() ? selectedKeyAlgo : DEFAULT_KEY_ALGO;

        StorageCipherAlgorithm selectedStorageAlgo = parseEnumOrDefault(
                StorageCipherAlgorithm.class,
                getOptionOrDefault(options, "storageCipherAlgorithm", DEFAULT_STORAGE_ALGO.name()),
                DEFAULT_STORAGE_ALGO
        );
        this.currentStorageAlgorithm = selectedStorageAlgo.isSupported() ? selectedStorageAlgo : DEFAULT_STORAGE_ALGO;
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context) throws Exception {
        return createCipher(savedStorageAlgorithm, savedKeyAlgorithm, context, true);
    }

    public StorageCipher getCurrentStorageCipher(Context context) throws Exception {
        return createCipher(currentStorageAlgorithm, currentKeyAlgorithm, context, false);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(PREFS_KEY_KEY_CIPHER, currentKeyAlgorithm.name());
        editor.putString(PREFS_KEY_STORAGE_CIPHER, currentStorageAlgorithm.name());
    }

    public void removeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.remove(PREFS_KEY_KEY_CIPHER);
        editor.remove(PREFS_KEY_STORAGE_CIPHER);
    }

    // --- Helpers ---

    private String getOptionOrDefault(Map<String, Object> options, String key, String fallback) {
        Object value = options.get(key);
        return value != null ? value.toString() : fallback;
    }

    private <T extends Enum<T>> T parseEnumOrDefault(Class<T> enumClass, String name, T defaultValue) {
        if (name == null) return defaultValue;
        try {
            return Enum.valueOf(enumClass, name);
        } catch (IllegalArgumentException e) {
            return defaultValue;
        }
    }

    private StorageCipher createCipher(StorageCipherAlgorithm storageAlgo, KeyCipherAlgorithm keyAlgo, Context context, boolean isSaved) throws Exception {
        try {
            KeyCipher keyCipher = keyAlgo.factory.apply(context);
            return storageAlgo.factory.apply(context, keyCipher);
        } catch (Exception e) {
            String label = isSaved ? "saved" : "current";
            throw new Exception("Failed to initialize " + label + " storage cipher securely", e);
        }
    }
}
