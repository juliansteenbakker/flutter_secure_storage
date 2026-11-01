package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.MigrationBackup;

import java.util.Map;
import java.security.Key;

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
    private final boolean assumedSavedAlgorithms;
    private final FlutterSecureStorageConfig config;

    public StorageCipherFactory(NamespacedConfigSource configSource, String keyCipherAlgorithm, String storageCipherAlgorithm, FlutterSecureStorageConfig config) {
        this.config = config;
        final String savedKeyCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
        final String savedStorageCipherAlgorithm = configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null);
        this.assumedSavedAlgorithms = savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null;

        if (savedKeyCipherAlgorithm == null || savedStorageCipherAlgorithm == null) {
            // Migration from v9.2.4 or v10.0.0-beta.4:
            // No algorithm markers exist in SharedPreferences, which means the data was encrypted
            // with the historical v9.2.4 defaults. We must use these defaults to decrypt the old
            // data, even if the current config specifies different algorithms.
            // After successful decryption, the data will be re-encrypted with current algorithms
            // (if they differ) via the migration flow in handleKeyMismatch().
            savedKeyAlgorithm = DEFAULT_KEY_ALGORITHM;        // RSA_ECB_PKCS1Padding
            savedStorageAlgorithm = DEFAULT_STORAGE_ALGORITHM; // AES_CBC_PKCS7Padding
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

    /** True when there were no markers, so the saved algorithms are a guess. */
    public boolean assumedSavedAlgorithms() {
        return assumedSavedAlgorithms;
    }

    public boolean changedKeyAlgorithm() {
        return savedKeyAlgorithm != currentKeyAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = getSavedKeyCipher(context);
        return createStorageCipher(context, keyCipher, cipher, savedStorageAlgorithm);
    }

    public StorageCipher getCurrentStorageCipher(Context context, Cipher cipher) throws Exception {
        final KeyCipher keyCipher = getCurrentKeyCipher(context);
        return createStorageCipher(context, keyCipher, cipher, currentStorageAlgorithm);
    }

    public StorageCipher getSavedStorageCipherFromBackup(Context context, Cipher cipher,
                                                         SharedPreferences keyStorage) throws Exception {
        Map<String, String> wrappedKeys = LegacyWrappedKeys.read(
                context, config, savedKeyAlgorithm, savedStorageAlgorithm, keyStorage);
        KeyCipher keyCipher = getSavedKeyCipher(context);
        StorageCipher savedCipher;
        if (savedStorageAlgorithm == StorageCipherAlgorithm.AES_CBC_PKCS7Padding) {
            savedCipher = new StorageCipherImplementationAES18(context, keyCipher, cipher, config, wrappedKeys);
        } else if (!isKeyStoreKeyCipher(keyCipher)) {
            savedCipher = savedGcmCipher(context, keyCipher, cipher, wrappedKeys);
        } else {
            throw new IllegalStateException("Backup-only key reads require a non-biometric saved cipher");
        }
        LegacyWrappedKeys.persist(context, config, savedKeyAlgorithm, savedStorageAlgorithm, wrappedKeys);
        return savedCipher;
    }

    private StorageCipher savedGcmCipher(Context context, KeyCipher keyCipher, Cipher cipher,
            Map<String, String> material) throws Exception {
        SharedPreferences data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        String sample = null;
        String prefix = config.getSharedPreferencesKeyPrefix() + "_";
        NamespacedConfigSource source = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
        for (String value : MigrationBackup.getDataBackups(data, source, config.getSharedPreferencesKeyPrefix()).values()) {
            sample = value;
            break;
        }
        if (sample == null) {
            for (Map.Entry<String, ?> entry : data.getAll().entrySet()) {
                if (entry.getKey().startsWith(prefix) && entry.getValue() instanceof String) {
                    sample = (String) entry.getValue();
                    break;
                }
            }
        }
        Exception failure = null;
        String[] slots = {StorageCipherImplementationGCM.WRAPPED_KEY_PREF,
                StorageCipherImplementationGCM.LEGACY_V9_KEY};
        for (String slot : slots) {
            String wrapped = material.get(slot);
            if (wrapped == null) {
                continue;
            }
            try {
                StorageCipher candidate = new StorageCipherImplementationGCM(context, keyCipher,
                        cipher, config, java.util.Collections.singletonMap(slot, wrapped));
                if (sample != null) {
                    candidate.decrypt(Base64.decode(sample, Base64.DEFAULT));
                }
                return candidate;
            } catch (Exception error) {
                failure = error;
            }
        }
        if (failure != null) {
            throw failure;
        }
        throw new IllegalStateException("Missing saved wrapped key");
    }

    public StorageCipher getCurrentStorageCipherForMigration(Context context, Cipher cipher) throws Exception {
        try {
            return getCurrentStorageCipher(context, cipher);
        } catch (Exception currentError) {
            if (!(currentError instanceof java.security.InvalidKeyException)
                    && !(currentError instanceof javax.crypto.BadPaddingException)
                    && !(currentError instanceof javax.crypto.IllegalBlockSizeException)) {
                throw currentError;
            }
            if (currentStorageAlgorithm != StorageCipherAlgorithm.AES_GCM_NoPadding
                    || savedKeyAlgorithm == currentKeyAlgorithm
                    || isKeyStoreKeyCipher(getCurrentKeyCipher(context))) {
                throw currentError;
            }
            SharedPreferences keys = context.getSharedPreferences(
                    config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
            String wrapped = keys.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null);
            if (wrapped == null) {
                wrapped = keys.getString(StorageCipherImplementationGCM.LEGACY_V9_KEY, null);
            }
            if (wrapped == null) {
                throw currentError;
            }
            Key legacyKey = getSavedKeyCipher(context).unwrap(Base64.decode(wrapped, Base64.DEFAULT), "AES");
            if (legacyKey.getEncoded() == null || legacyKey.getEncoded().length != 16) {
                throw currentError;
            }
            LegacyWrappedKeys.preserveLive(context, config, savedKeyAlgorithm,
                    StorageCipherAlgorithm.AES_GCM_NoPadding, keys);
            return new StorageCipherImplementationGCM(context, getCurrentKeyCipher(context),
                    cipher, config, null, false);
        }
    }

    /**
     * Whether the current storage cipher can decrypt the given ciphertext.
     * Always false for KeyStore/biometric ciphers, which need an authenticated
     * cipher.
     */
    public boolean currentCipherDecrypts(Context context, byte[] ciphertext) {
        try {
            getCurrentStorageCipher(context, null).decrypt(ciphertext);
            return true;
        } catch (Throwable t) {
            if (t instanceof VirtualMachineError) {
                throw (VirtualMachineError) t;
            }
            return false;
        }
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

    /**
     * The saved key algorithm resolved at construction time. Prefer this over re-reading
     * readSavedKeyAlgorithm(configSource) afterwards, since the constructor may have already
     * written the current markers there.
     */
    public KeyCipherAlgorithm getSavedKeyAlgorithm() {
        return savedKeyAlgorithm;
    }

    public KeyCipherAlgorithm getCurrentKeyAlgorithm() {
        return currentKeyAlgorithm;
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }

    /** Reads the saved key-cipher marker, or null if none was ever written. */
    public static String readSavedKeyAlgorithm(NamespacedConfigSource configSource) {
        return configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
    }

    /**
     * Copies algorithm markers from the data prefs, where v9 stored them, into
     * the config source, where v10+ looks. No-op if the config source already
     * has markers or the data prefs have none. Returns true if it copied.
     */
    public static boolean adoptLegacyMarkers(NamespacedConfigSource configSource, SharedPreferences dataPrefs) {
        if (configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null) != null
                && configSource.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null) != null) {
            return false;
        }
        final String key = dataPrefs.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, null);
        final String storage = dataPrefs.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, null);
        if (key == null || storage == null) {
            return false;
        }
        configSource.edit()
                .putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, key)
                .putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, storage)
                .apply();
        return true;
    }
}
