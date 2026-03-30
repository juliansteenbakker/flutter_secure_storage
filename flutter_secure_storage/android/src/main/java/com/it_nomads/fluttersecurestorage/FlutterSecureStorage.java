package com.it_nomads.fluttersecurestorage;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import com.it_nomads.fluttersecurestorage.ciphers.KeyCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherFactory;
import com.it_nomads.fluttersecurestorage.crypto.EncryptedSharedPreferences;
import com.it_nomads.fluttersecurestorage.crypto.MasterKey;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

public class FlutterSecureStorage {

    private static final String TAG = "FlutterSecureStorage";
    private static final Charset charset = StandardCharsets.UTF_8;
    private static final String SHARED_PREFERENCES_CONFIG_NAME = "FlutterSecureStorageConfiguration";

    private FlutterSecureStorageConfig config;
    @NonNull
    private final Context context;

    private SharedPreferences preferences;
    private StorageCipher storageCipher;
    private StorageCipherFactory storageCipherFactory;

    public FlutterSecureStorage(Context context) {
        this.context = context.getApplicationContext();
    }

    public String addPrefixToKey(String key) {
        return config.getSharedPreferencesKeyPrefix() + "_" + key;
    }

    public boolean containsKey(String key) {
        return preferences.contains(key);
    }

    public String read(String key) throws Exception {
        try {
            return readUnsafe(key);
        } catch (Exception e) {
            if (handleStorageError("read", key, e)) {
                return readUnsafe(key); // Retry after deleting corrupted data
            }
            throw e;
        }
    }

    private String readUnsafe(String key) throws Exception {
        String rawValue = preferences.getString(key, null);
        if (config.isUseEncryptedSharedPreferences() && !config.shouldMigrateOnAlgorithmChange()) {
            return rawValue;
        }
        return decodeRawValue(rawValue);
    }

    public Map<String, String> readAll() throws Exception {
        try {
            return readAllUnsafe();
        } catch (Exception e) {
            if (handleStorageError("readAll", null, e)) {
                return readAllUnsafe(); // Retry after deleting corrupted data
            }
            throw e;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> readAllUnsafe() throws Exception {
        Map<String, String> raw = (Map<String, String>) preferences.getAll();

        Map<String, String> all = new HashMap<>();
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String keyWithPrefix = entry.getKey();
            if (keyWithPrefix.contains(config.getSharedPreferencesKeyPrefix())) {
                String key = entry.getKey().replaceFirst(config.getSharedPreferencesKeyPrefix() + '_', "");
                if (config.isUseEncryptedSharedPreferences() && !config.shouldMigrateOnAlgorithmChange()) {
                    all.put(key, entry.getValue());
                } else {
                    String rawValue = entry.getValue();
                    String value = decodeRawValue(rawValue);

                    all.put(key, value);
                }
            }
        }
        return all;
    }

    public void write(String key, String value) throws Exception {
        try {
            writeUnsafe(key, value);
        } catch (Exception e) {
            if (handleStorageError("write", key, e)) {
                writeUnsafe(key, value); // Retry after deleting corrupted data
            } else {
                throw e;
            }
        }
    }

    private void writeUnsafe(String key, String value) throws Exception {
        SharedPreferences.Editor editor = preferences.edit();

        if (config.isUseEncryptedSharedPreferences() && !config.shouldMigrateOnAlgorithmChange()) {
            editor.putString(key, value);
        } else {
            byte[] result = storageCipher.encrypt(value.getBytes(charset));
            editor.putString(key, Base64.encodeToString(result, 0));
        }
        editor.apply();
    }

    public void delete(String key) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(key);
        editor.apply();
    }

    public void deleteAll() {
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.apply();
    }

    public void initialize(FlutterSecureStorageConfig config, SecurePreferencesCallback<Void> callback) {
        this.config = config;

        // Use cached preferences if available
        if (preferences != null) {
            callback.onSuccess(null);
            return;
        }

        SharedPreferences nonEncryptedPreferences = context.getSharedPreferences(
                config.getSharedPreferencesName(),
                Context.MODE_PRIVATE
        );

        SharedPreferences configSource = context.getSharedPreferences(
                SHARED_PREFERENCES_CONFIG_NAME,
                Context.MODE_PRIVATE
        );

        Boolean isAlreadyMigrated = getEncryptedPrefsMigrated(configSource);

        // Skip old ESP migration if migrateWithBackup is enabled - ESP migration is now
        // handled by step 6 of the backup-protected migration path
        if (!isAlreadyMigrated && !config.shouldMigrateWithBackup()) {
            try {
                SharedPreferences encryptedPreferences = initializeEncryptedSharedPreferencesManager(context);

                // Check if data exists in EncryptedSharedPreferences (from v9.2.4 or earlier)
                if (hasDataInEncryptedSharedPreferences(encryptedPreferences)) {
                    // EncryptedSharedPreferences (Jetpack Security library, deprecated by Google)
                    Log.w(TAG, "Found data in EncryptedSharedPreferences (deprecated)");
                    Log.w(TAG, "EncryptedSharedPreferences is DEPRECATED and will be removed in a later version");
                    Log.w(TAG, "The Jetpack Security library has been deprecated by Google.");

                    if (!config.shouldMigrateOnAlgorithmChange()) {
                        Log.w(TAG, "Data found in EncryptedSharedPreferences, but migrateOnAlgorithmChange is set to false.");
                        Log.w(TAG, "Set migrateOnAlgorithmChange=true to migrate to custom cipher storage.");

                        // User wants to keep using EncryptedSharedPreferences
                        if (config.isUseEncryptedSharedPreferences()) {
                            Log.i(TAG, "Using EncryptedSharedPreferences (migration disabled).");
                            preferences = encryptedPreferences;
                            callback.onSuccess(null);
                            return;
                        } else {
                            Log.e(TAG, "Data exists in EncryptedSharedPreferences but encryptedSharedPreferences=false and migrateOnAlgorithmChange=false.");
                            Log.e(TAG, "Either set encryptedSharedPreferences=true to use the old data, or set migrateOnAlgorithmChange=true to migrate it.");
                            callback.onError(new Exception("EncryptedSharedPreferences data found but migration is disabled. Set migrateOnAlgorithmChange=true to migrate."));
                            return;
                        }
                    }

                    // Migrate from EncryptedSharedPreferences to custom cipher storage
                    Log.i(TAG, "Migrating data from EncryptedSharedPreferences to custom cipher storage...");
                    if (config.isUseEncryptedSharedPreferences()) {
                        Log.w(TAG, "Your data will be automatically migrated. You can safely remove encryptedSharedPreferences from your config after migration.");
                    }
                    Log.i(TAG, "Migrating data from EncryptedSharedPreferences to selected custom cipher storage...");

                    // Initialize custom cipher for migration target
                    initializeStorageCipher(configSource, new SecurePreferencesCallback<>() {
                        @Override
                        public void onSuccess(Void unused) {
                            try {
                                migrateFromEncryptedSharedPreferences(encryptedPreferences, nonEncryptedPreferences);
                                preferences = nonEncryptedPreferences;
                                Log.i(TAG, "Migration completed successfully. Now using custom cipher storage.");
                                setEncryptedPrefsMigrated(configSource);
                                callback.onSuccess(null);
                            } catch (Exception e) {
                                Log.e(TAG, "Migration failed. Falling back to EncryptedSharedPreferences.", e);
                                preferences = encryptedPreferences;
                                callback.onSuccess(null);
                            }
                        }

                        @Override
                        public void onError(Exception e) {
                            Log.e(TAG, "Cipher initialization failed during migration. Using EncryptedSharedPreferences.", e);
                            preferences = encryptedPreferences;
                            callback.onSuccess(null);
                        }
                    });
                    return;
                } else {
                    // No data in EncryptedSharedPreferences
                    Log.d(TAG, "No data found in EncryptedSharedPreferences.");

                    // If user explicitly wants to use EncryptedSharedPreferences (deprecated)
                    if (config.isUseEncryptedSharedPreferences() && !config.shouldMigrateOnAlgorithmChange()) {
                        Log.w(TAG, "Using EncryptedSharedPreferences (deprecated). Consider migrating to custom ciphers.");
                        preferences = encryptedPreferences;
                        callback.onSuccess(null);
                        return;
                    }

                    // Fall through to use custom ciphers
                }
            } catch (Exception e) {
                Log.e(TAG, "EncryptedSharedPreferences initialization failed. Falling back to custom ciphers.", e);
                // Fall through to use custom ciphers
            }
        }

        // Use custom cipher storage (default path for new installs or after migration)
        if (preferences == null) {
            if (config.isUseEncryptedSharedPreferences() && isAlreadyMigrated) {
                Log.i(TAG, "Data already migrated, encryptedSharedPreferences ignored and can be safely removed.");
            }
            preferences = nonEncryptedPreferences;
            initializeStorageCipher(configSource, callback);
        }
    }

    private void initializeStorageCipher(SharedPreferences configSource, SecurePreferencesCallback<Void> callback) {
        try {
            storageCipherFactory = new StorageCipherFactory(configSource, config.getPrefOptionKeyCipherAlgorithm(), config.getPrefOptionStorageCipherAlgorithm(), config);

            if (storageCipherFactory.requiresReEncryption()) {
                Log.w(TAG, "Algorithm changed detected.");
                handleKeyMismatch(configSource, callback, null, "Algorithm changed detected");
                return;
            }

            // Check if the current algorithm requires biometric authentication
            Cipher cipher = storageCipherFactory.getCurrentKeyCipher(context).getCipher(context);
            boolean enforceRequired = config.getEnforceBiometrics();
            boolean deviceHasSecurity = isDeviceSecure();

            // Skip authentication if:
            // 1. Cipher is null (RSA algorithms), OR
            // 2. Android < P (no BiometricPrompt), OR
            // 3. Enforcement disabled AND device has no security
            if (cipher == null
                    || Build.VERSION.SDK_INT < Build.VERSION_CODES.P
                    || (!enforceRequired && !deviceHasSecurity)) {
                // No biometric authentication needed - use non-authenticated cipher
                // For AES_GCM_NoPadding_BIOMETRIC, cipher is already initialized from KeyStore
                // with setUserAuthenticationRequired(false) when device has no security
                storageCipher = storageCipherFactory.getCurrentStorageCipher(context, cipher);
                callback.onSuccess(null);
                return;
            }

            // Biometric authentication required (AES_GCM_NoPadding_BIOMETRIC)
            authenticateUser(cipher, new SecurePreferencesCallback<>() {
                @Override
                public void onSuccess(BiometricPrompt.AuthenticationResult result) {
                    try {
                        storageCipher = storageCipherFactory.getCurrentStorageCipher(context, result.getCryptoObject().getCipher());
                        Log.d(TAG, "Biometric authentication succeeded");
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to initialize storage cipher after authentication", e);
                        callback.onError(e);
                    }
                    callback.onSuccess(null);
                }

                @Override
                public void onError(Exception e) {
                    callback.onError(e);
                }
            });
        } catch (javax.crypto.BadPaddingException e) {
            // Wrong key/padding for cipher, typically after algorithm change
            handleKeyMismatch(configSource, callback, e, "Bad padding, wrong key for cipher algorithm");
        } catch (java.security.InvalidKeyException e) {
            // Key type doesn't match cipher requirements, typically after algorithm change
            handleKeyMismatch(configSource, callback, e, "Invalid key, key type incompatible with cipher");
        } catch (javax.crypto.IllegalBlockSizeException e) {
            // Wrong cipher mode or block size, typically after algorithm change
            handleKeyMismatch(configSource, callback, e, "Illegal block size, wrong cipher configuration");
        } catch (java.security.NoSuchAlgorithmException e) {
            // Algorithm not available on this device, cannot recover
            Log.e(TAG, "Cryptographic algorithm not available on this device", e);
            callback.onError(new Exception("Required cryptographic algorithm not supported by device.", e));
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize storage cipher", e);
            callback.onError(e);
        }
    }

    /**
     * Migrates data from old cipher algorithm to new cipher algorithm.
     * Handles both biometric and non-biometric migration paths.
     *
     * @param configSource SharedPreferences for algorithm configuration
     * @param dataSource SharedPreferences containing encrypted data
     * @param callback Callback to notify of success/failure
     */
    private void migrateData(SharedPreferences configSource, SharedPreferences dataSource,
                            SecurePreferencesCallback<Void> callback) {
        Log.i(TAG, "Starting data migration from saved to current cipher algorithms...");

        try {
            // Determine if this is a biometric migration
            String savedStorageAlg = storageCipherFactory.getSavedKeyCipher(context).toString();
            String currentStorageAlg = config.getPrefOptionStorageCipherAlgorithm();

            boolean fromBiometric = isBiometricAlgorithm(savedStorageAlg);
            boolean toBiometric = isBiometricAlgorithm(currentStorageAlg);

            if (fromBiometric || toBiometric) {
                Log.i(TAG, "Detected biometric migration: FROM=" + savedStorageAlg + ", TO=" + currentStorageAlg);
                migrateBiometric(configSource, dataSource, fromBiometric, toBiometric, callback);
            } else {
                Log.i(TAG, "Detected non-biometric migration: FROM=" + savedStorageAlg + ", TO=" + currentStorageAlg);
                // Route to backup-protected migration if flag is enabled
                if (config.shouldMigrateWithBackup()) {
                    Log.i(TAG, "Using migration WITH BACKUP protection");
                    migrateNonBiometricWithBackup(configSource, dataSource, callback);
                } else {
                    migrateNonBiometric(configSource, dataSource, callback);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to start migration", e);
            callback.onError(new Exception("Migration initialization failed", e));
        }
    }

    /**
     * Decrypts all encrypted data using the saved (old) cipher.
     *
     * @param dataSource SharedPreferences containing encrypted data
     * @param savedStorageCipher The old storage cipher to decrypt with
     * @return Map of decrypted key-value pairs
     */
    private Map<String, String> decryptAllWithSavedCipher(SharedPreferences dataSource,
                                                          StorageCipher savedStorageCipher) throws Exception {
        Map<String, String> decryptedCache = new HashMap<>();
        int count = 0;

        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof String && key.contains(config.getSharedPreferencesKeyPrefix())) {
                try {
                    // Decode and decrypt with old cipher
                    byte[] encryptedData = Base64.decode((String) value, 0);
                    byte[] decryptedData = savedStorageCipher.decrypt(encryptedData);
                    String plainValue = new String(decryptedData, charset);

                    decryptedCache.put(key, plainValue);
                    count++;
                } catch (Exception e) {
                    Log.e(TAG, "Failed to decrypt key: " + key, e);
                    throw new Exception("Failed to decrypt existing data with saved cipher for key: " + key, e);
                }
            }
        }

        Log.d(TAG, "Successfully decrypted " + count + " items with saved cipher");
        return decryptedCache;
    }

    /**
     * Encrypts all data using the current (new) cipher and writes to SharedPreferences.
     *
     * @param cache Map of plaintext key-value pairs to encrypt
     * @param dataTarget SharedPreferences to write encrypted data
     * @param currentStorageCipher The new storage cipher to encrypt with
     */
    private void encryptAllWithCurrentCipher(Map<String, String> cache, SharedPreferences dataTarget,
                                            StorageCipher currentStorageCipher) throws Exception {
        SharedPreferences.Editor editor = dataTarget.edit();
        int count = 0;

        for (Map.Entry<String, String> entry : cache.entrySet()) {
            try {
                byte[] encryptedData = currentStorageCipher.encrypt(entry.getValue().getBytes(charset));
                String encodedValue = Base64.encodeToString(encryptedData, 0);
                editor.putString(entry.getKey(), encodedValue);
                count++;
            } catch (Exception e) {
                Log.e(TAG, "Failed to encrypt key: " + entry.getKey(), e);
                throw new Exception("Failed to encrypt data with current cipher for key: " + entry.getKey(), e);
            }
        }

        // Use commit() instead of apply() to guarantee data is written to disk
        // before returning. This prevents data loss if the app is force-killed
        // immediately after migration (e.g., on slow eMMC storage devices).
        boolean success = editor.commit();
        if (!success) {
            throw new Exception("Failed to commit encrypted data to disk - storage may be full or unavailable");
        }
        Log.d(TAG, "Successfully encrypted and committed " + count + " items with current cipher to disk");
    }

    /**
     * Encrypts all entries in cache with the current cipher, tracking per-key progress in configSource.
     * On retry after a crash mid-step, keys already marked <key>_MIGRATED in configSource are skipped
     * (they were already written to dataTarget). After each successful key write, a _MIGRATED marker
     * is stored in configSource so a subsequent retry knows to skip it.
     *
     * Markers are stored in configSource (not dataSource) so they don't interfere with real user data.
     * Step 7 cleans up all _MIGRATED markers after full migration completes.
     */
    private void encryptAllWithCurrentCipherTracked(Map<String, String> cache, SharedPreferences dataTarget,
                                                    SharedPreferences configSource,
                                                    StorageCipher currentStorageCipher,
                                                    String keyPrefix) throws Exception {
        int count = 0;
        int skipped = 0;

        for (Map.Entry<String, String> entry : cache.entrySet()) {
            String key = entry.getKey();
            String migratedMarker = key + "_MIGRATED";

            // Skip keys already successfully written on a previous (crashed) run
            if (configSource.contains(migratedMarker)) {
                skipped++;
                Log.d(TAG, "Skipping already-migrated key: " + key);
                continue;
            }

            try {
                byte[] encryptedData = currentStorageCipher.encrypt(entry.getValue().getBytes(charset));
                String encodedValue = Base64.encodeToString(encryptedData, 0);

                // Write encrypted value then mark as migrated — both committed atomically
                SharedPreferences.Editor dataEditor = dataTarget.edit();
                dataEditor.putString(key, encodedValue);
                if (!dataEditor.commit()) {
                    throw new Exception("Failed to commit encrypted data for key: " + key);
                }

                configSource.edit().putBoolean(migratedMarker, true).commit();
                count++;
            } catch (Exception e) {
                Log.e(TAG, "Failed to encrypt key: " + key, e);
                throw new Exception("Failed to encrypt data with current cipher for key: " + key, e);
            }
        }

        Log.d(TAG, "Encrypted " + count + " items (skipped " + skipped + " already-migrated) with current cipher");
    }

    /**
     * Checks if a storage cipher algorithm name indicates biometric authentication.
     */
    private boolean isBiometricAlgorithm(String algorithmName) {
        return algorithmName != null && algorithmName.contains("BIOMETRIC");
    }

    /**
     * Migrates data between non-biometric cipher algorithms.
     * Handles migrations like RSA_PKCS1→RSA_OAEP or AES_CBC→AES_GCM.
     * No user authentication required.
     *
     * @param configSource SharedPreferences for algorithm configuration
     * @param dataSource SharedPreferences containing encrypted data
     * @param callback Callback to notify of success/failure
     */
    private void migrateNonBiometric(SharedPreferences configSource, SharedPreferences dataSource,
                                    SecurePreferencesCallback<Void> callback) {
        Log.i(TAG, "Starting non-biometric migration (no authentication required)...");

        try {
            // Step 1: Get saved cipher (old algorithm, no auth needed)
            Log.d(TAG, "Step 1/6: Initializing saved cipher...");
            StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, null);

            // Step 2: Decrypt all data with old cipher
            Log.d(TAG, "Step 2/6: Decrypting all data with saved cipher...");
            Map<String, String> decryptedCache = decryptAllWithSavedCipher(dataSource, savedCipher);

            // Step 3: Delete OLD RSA key from Android KeyStore
            // Critical: Must delete before creating new RSA key to avoid key collision
            Log.d(TAG, "Step 3/6: Deleting old RSA key from Android KeyStore...");
            if (storageCipherFactory.changedKeyAlgorithm()) {
                try {
                    KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                    savedKeyCipher.deleteKey();

                    savedCipher.deleteKey(context);
                    Log.d(TAG, "Old key deleted from KeyStore");
                } catch (Exception deleteError) {
                    Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                }
            }

            // Step 4: Update algorithm markers to current
            Log.d(TAG, "Step 4/6: Updating algorithm markers to current...");
            updateAlgorithmMarkers(configSource);

            // Step 5: Get current cipher (will create fresh keys with new algorithm)
            Log.d(TAG, "Step 5/6: Initializing current cipher with fresh AES key...");
            StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, null);

            if (decryptedCache.isEmpty()) {
                Log.i(TAG, "Step 6/6: No data to migrate, continuing...");
            } else {
                // Step 6: Encrypt all data with new cipher
                Log.d(TAG, "Step 6/6: Encrypting all data with current cipher...");
                encryptAllWithCurrentCipher(decryptedCache, dataSource, currentCipher);
            }

            // Update storageCipher to current
            storageCipher = currentCipher;

            Log.i(TAG, "Non-biometric migration completed successfully! Migrated " + decryptedCache.size() + " items.");
            callback.onSuccess(null);

        } catch (Exception e) {
            Log.e(TAG, "Non-biometric migration failed", e);
            callback.onError(new Exception("Non-biometric migration failed", e));
        }
    }

    /**
     * Updates algorithm markers in config to match current cipher algorithms.
     */
    private void updateAlgorithmMarkers(SharedPreferences configSource) {
        SharedPreferences.Editor editor = configSource.edit();
        storageCipherFactory.storeCurrentAlgorithms(editor);
        editor.commit();
        Log.d(TAG, "Algorithm markers updated to current");
    }

    /**
     * Migrates data involving biometric authentication.
     * Handles three scenarios:
     *  1. FROM biometric → TO non-biometric: Auth with OLD cipher
     *  2. FROM non-biometric → TO biometric: Auth with NEW cipher
     *  3. FROM biometric → TO biometric: Auth with both ciphers
     *
     * @param configSource SharedPreferences for algorithm configuration
     * @param dataSource SharedPreferences containing encrypted data
     * @param fromBiometric True if migrating FROM a biometric algorithm
     * @param toBiometric True if migrating TO a biometric algorithm
     * @param callback Callback to notify of success/failure
     */
    private void migrateBiometric(SharedPreferences configSource, SharedPreferences dataSource,
                                 boolean fromBiometric, boolean toBiometric,
                                 SecurePreferencesCallback<Void> callback) {
        Log.i(TAG, "Starting biometric migration (authentication required)...");
        Log.i(TAG, "Migration direction: FROM biometric=" + fromBiometric + ", TO biometric=" + toBiometric);

        try {
            // Route to backup-protected biometric migrations if flag is enabled
            boolean useBackup = config.shouldMigrateWithBackup();
            if (useBackup) {
                Log.i(TAG, "Using biometric migration WITH BACKUP protection");
            }

            if (fromBiometric && !toBiometric) {
                Log.i(TAG, "You will be prompted to authenticate with your OLD biometric settings to decrypt existing data.");
                if (useBackup) {
                    migrateFromBiometricToNonBiometricWithBackup(configSource, dataSource, callback);
                } else {
                    migrateFromBiometricToNonBiometric(configSource, dataSource, callback);
                }
            } else if (!fromBiometric && toBiometric) {
                Log.i(TAG, "You will be prompted to authenticate with your NEW biometric settings to encrypt data.");
                if (useBackup) {
                    migrateFromNonBiometricToBiometricWithBackup(configSource, dataSource, callback);
                } else {
                    migrateFromNonBiometricToBiometric(configSource, dataSource, callback);
                }
            } else {
                Log.i(TAG, "You will be prompted to authenticate twice (once for decrypt, once for encrypt).");
                if (useBackup) {
                    migrateBiometricToBiometricWithBackup(configSource, dataSource, callback);
                } else {
                    migrateBiometricToBiometric(configSource, dataSource, callback);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Biometric migration failed", e);
            callback.onError(new Exception("Biometric migration failed", e));
        }
    }

    /**
     * Migrates FROM biometric → TO non-biometric.
     * Requires authentication with OLD biometric cipher to decrypt.
     */
    private void migrateFromBiometricToNonBiometric(SharedPreferences configSource, SharedPreferences dataSource,
                                                    SecurePreferencesCallback<Void> callback) {
        try {
            // Step 1: Get OLD biometric cipher (requires authentication)
            Log.d(TAG, "Step 1/6: Getting saved biometric cipher...");
            KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
            Cipher oldKeyCipher = savedKeyCipher.getCipher(context);

            if (oldKeyCipher == null) {
                throw new Exception("Failed to get saved biometric cipher");
            }

            Log.i(TAG, "Authenticating with OLD biometric cipher to decrypt data...");

            // Authenticate with OLD cipher
            authenticateUser(oldKeyCipher, new SecurePreferencesCallback<>() {
                @Override
                public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                    try {
                        // Step 2: Decrypt with OLD biometric cipher
                        Log.d(TAG, "Step 2/6: Decrypting all data with saved biometric cipher...");
                        StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, oldKeyCipher);
                        Map<String, String> decryptedCache = decryptAllWithSavedCipher(dataSource, savedCipher);

                        // Step 3: Delete OLD biometric AES key from Android KeyStore
                        // Critical: Must delete before creating new RSA key to avoid key type collision
                        Log.d(TAG, "Step 3/6: Deleting old biometric AES key from Android KeyStore...");
                        if (storageCipherFactory.changedKeyAlgorithm()) {
                            try {
                                KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                                savedKeyCipher.deleteKey();

                                savedCipher.deleteKey(context);
                                Log.d(TAG, "Old key deleted from KeyStore");
                            } catch (Exception deleteError) {
                                Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                            }
                        }

                        // Step 4: Update algorithm markers to current
                        Log.d(TAG, "Step 4/6: Updating algorithm markers to current...");
                        updateAlgorithmMarkers(configSource);

                        // Step 5: Get NEW non-biometric cipher (no auth)
                        // Will create fresh RSA key in KeyStore
                        Log.d(TAG, "Step 5/6: Initializing current non-biometric cipher...");
                        StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, null);

                        // Step 6: Encrypt all data with NEW cipher
                        Log.d(TAG, "Step 6/6: Encrypting all data with current cipher...");
                        encryptAllWithCurrentCipher(decryptedCache, dataSource, currentCipher);

                        storageCipher = currentCipher;

                        Log.i(TAG, "Biometric→Non-biometric migration completed! Data no longer requires biometric authentication.");
                        callback.onSuccess(null);
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to complete migration after authentication", e);
                        callback.onError(e);
                    }
                }

                @Override
                public void onError(Exception e) {
                    Log.e(TAG, "Biometric authentication failed for migration", e);
                    callback.onError(new Exception("Migration cancelled: Biometric authentication failed", e));
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize biometric migration", e);
            callback.onError(e);
        }
    }

    /**
     * Migrates FROM non-biometric → TO biometric.
     * Requires authentication with NEW biometric cipher to encrypt.
     */
    private void migrateFromNonBiometricToBiometric(SharedPreferences configSource, SharedPreferences dataSource,
                                                    SecurePreferencesCallback<Void> callback) {
        try {
            // Step 1: Decrypt with OLD non-biometric cipher (no auth)
            Log.d(TAG, "Step 1/6: Decrypting all data with saved non-biometric cipher...");
            StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, null);
            Map<String, String> decryptedCache = decryptAllWithSavedCipher(dataSource, savedCipher);

            // Step 2: Delete OLD RSA key from Android KeyStore
            // Critical: Must delete before creating new biometric AES key to avoid key type collision
            Log.d(TAG, "Step 2/6: Deleting old RSA key from Android KeyStore...");
            if (storageCipherFactory.changedKeyAlgorithm()) {
                try {
                    KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                    savedKeyCipher.deleteKey();

                    savedCipher.deleteKey(context);
                    Log.d(TAG, "Old key deleted from KeyStore");
                } catch (Exception deleteError) {
                    Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                }
            }

            // Step 3: Update algorithm markers to current
            Log.d(TAG, "Step 3/6: Updating algorithm markers to current...");
            updateAlgorithmMarkers(configSource);
            
            // Step 4: Get NEW biometric cipher (requires authentication)
            // Will create fresh biometric AES key in KeyStore
            Log.d(TAG, "Step 4/6: Getting current biometric cipher...");
            KeyCipher currentKeyCipher = storageCipherFactory.getCurrentKeyCipher(context);
            Cipher newCipher = currentKeyCipher.getCipher(context);

            if (newCipher == null) {
                throw new Exception("Failed to get current biometric cipher");
            }

            Log.i(TAG, "Authenticating with NEW biometric cipher to encrypt data...");

            // Authenticate with NEW cipher
            final Map<String, String> cachedData = decryptedCache; // Make final for lambda
            authenticateUser(newCipher, new SecurePreferencesCallback<>() {
                @Override
                public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                    try {
                        // Step 5: Initialize current biometric cipher
                        Log.d(TAG, "Step 5/6: Initializing current biometric cipher...");
                        StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, newCipher);

                        // Step 6: Encrypt all data with NEW biometric cipher
                        Log.d(TAG, "Step 6/6: Encrypting all data with current biometric cipher...");
                        encryptAllWithCurrentCipher(cachedData, dataSource, currentCipher);

                        storageCipher = currentCipher;

                        Log.i(TAG, "Non-biometric→Biometric migration completed! Data now requires biometric authentication.");
                        callback.onSuccess(null);
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to complete migration after authentication", e);
                        callback.onError(e);
                    }
                }

                @Override
                public void onError(Exception e) {
                    Log.e(TAG, "Biometric authentication failed for migration", e);
                    callback.onError(new Exception("Migration cancelled: Biometric authentication failed", e));
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize biometric migration", e);
            callback.onError(e);
        }
    }

    /**
     * Migrates FROM biometric → TO biometric (changing biometric algorithms).
     * Requires authentication with both OLD and NEW biometric ciphers.
     */
    private void migrateBiometricToBiometric(SharedPreferences configSource, SharedPreferences dataSource,
                                            SecurePreferencesCallback<Void> callback) {
        try {
            // Step 1: Get OLD biometric cipher
            Log.d(TAG, "Step 1/7: Getting saved biometric cipher...");
            KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
            Cipher oldCipher = savedKeyCipher.getCipher(context);

            if (oldCipher == null) {
                throw new Exception("Failed to get saved biometric cipher");
            }

            Log.i(TAG, "Authenticating with OLD biometric cipher to decrypt data...");

            // First authentication: OLD cipher
            authenticateUser(oldCipher, new SecurePreferencesCallback<>() {
                @Override
                public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                    try {
                        // Step 2: Decrypt with OLD biometric cipher
                        Log.d(TAG, "Step 2/7: Decrypting all data with saved biometric cipher...");
                        StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, oldCipher);
                        Map<String, String> decryptedCache = decryptAllWithSavedCipher(dataSource, savedCipher);

                        // Step 3: Delete OLD biometric AES key from Android KeyStore
                        // Critical: Must delete before creating new biometric AES key to avoid key collision
                        Log.d(TAG, "Step 3/7: Deleting old biometric AES key from Android KeyStore...");
                        if (storageCipherFactory.changedKeyAlgorithm()) {
                            try {
                                KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                                savedKeyCipher.deleteKey();

                                savedCipher.deleteKey(context);
                                Log.d(TAG, "Old key deleted from KeyStore");
                            } catch (Exception deleteError) {
                                Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                            }
                        }

                        // Step 4: Update algorithm markers to current
                        Log.d(TAG, "Step 4/7: Updating algorithm markers to current...");
                        updateAlgorithmMarkers(configSource);

                        // Step 5: Get NEW biometric cipher
                        // Will create fresh biometric AES key in KeyStore
                        Log.d(TAG, "Step 5/7: Getting current biometric cipher...");
                        KeyCipher currentKeyCipher = storageCipherFactory.getCurrentKeyCipher(context);
                        Cipher newCipher = currentKeyCipher.getCipher(context);

                        if (newCipher == null) {
                            throw new Exception("Failed to get current biometric cipher");
                        }

                        Log.i(TAG, "Authenticating with NEW biometric cipher to encrypt data...");

                        // Second authentication: NEW cipher
                        final Map<String, String> cachedData = decryptedCache;
                        authenticateUser(newCipher, new SecurePreferencesCallback<>() {
                            @Override
                            public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                                try {
                                    // Step 6: Initialize current biometric cipher
                                    Log.d(TAG, "Step 6/7: Initializing current biometric cipher...");
                                    StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, newCipher);

                                    // Step 7: Encrypt all data with NEW biometric cipher
                                    Log.d(TAG, "Step 7/7: Encrypting all data with current biometric cipher...");
                                    encryptAllWithCurrentCipher(cachedData, dataSource, currentCipher);

                                    storageCipher = currentCipher;

                                    Log.i(TAG, "Biometric→Biometric migration completed! Data now uses new biometric cipher.");
                                    callback.onSuccess(null);
                                } catch (Exception e) {
                                    Log.e(TAG, "Failed to complete migration after second authentication", e);
                                    callback.onError(e);
                                }
                            }

                            @Override
                            public void onError(Exception e) {
                                Log.e(TAG, "Second biometric authentication failed for migration", e);
                                callback.onError(new Exception("Migration cancelled: Second biometric authentication failed", e));
                            }
                        });
                    } catch (Exception e) {
                        Log.e(TAG, "Failed after first authentication", e);
                        callback.onError(e);
                    }
                }

                @Override
                public void onError(Exception e) {
                    Log.e(TAG, "First biometric authentication failed for migration", e);
                    callback.onError(new Exception("Migration cancelled: First biometric authentication failed", e));
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize biometric-to-biometric migration", e);
            callback.onError(e);
        }
    }

    private void setEncryptedPrefsMigrated(SharedPreferences configSource) {
        SharedPreferences.Editor editor = configSource.edit();
        editor.putBoolean("ENCRYPTED_PREFERENCES_MIGRATED", true);
        editor.commit();
    }

    private Boolean getEncryptedPrefsMigrated(SharedPreferences configSource) {
        return configSource.getBoolean("ENCRYPTED_PREFERENCES_MIGRATED", false);
    }

    /**
     * Handles key mismatch exceptions that occur when stored encryption keys
     * cannot be decrypted/unwrapped due to algorithm changes or key corruption.
     *
     * @param configSource SharedPreferences for configuration/algorithm storage
     * @param callback Callback to notify of success/failure
     * @param exception The original exception (BadPaddingException, InvalidKeyException, etc.)
     * @param errorType Human-readable description of the error type
     */
    private void handleKeyMismatch(SharedPreferences configSource, SecurePreferencesCallback<Void> callback,
                                   Exception exception, String errorType) {
        Log.e(TAG, "Key mismatch detected during cipher initialization: " + errorType, exception);
        Log.e(TAG, "This typically occurs after an algorithm change.");
        Log.e(TAG, "Stored key cannot be decrypted with current algorithm.");

        // Check if migration is enabled
        if (config.shouldMigrateOnAlgorithmChange()) {
            Log.i(TAG, "migrateOnAlgorithmChange is enabled. Attempting data migration...");

            SharedPreferences dataPrefs = context.getSharedPreferences(
                    config.getSharedPreferencesName(),
                    Context.MODE_PRIVATE
            );

            migrateData(configSource, dataPrefs, new SecurePreferencesCallback<>() {
                @Override
                public void onSuccess(Void unused) {
                    Log.i(TAG, "Data migration completed successfully!");
                    setEncryptedPrefsMigrated(configSource);
                    callback.onSuccess(null);
                }

                @Override
                public void onError(Exception migrationError) {
                    Log.e(TAG, "Data migration failed: " + migrationError.getMessage(), migrationError);

                    // Migration failed, check if we should delete
                    if (config.shouldDeleteOnFailure()) {
                        Log.w(TAG, "resetOnError is enabled. Deleting all data as fallback...");
                        deleteAllDataAndKeys(configSource, callback);
                        setEncryptedPrefsMigrated(configSource);
                    } else {
                        Log.e(TAG, "Set resetOnError=true to automatically delete data after migration failure.");
                        String userMessage = String.format(
                            "Migration failed after algorithm change (%s). Enable resetOnError=true or call deleteAll().",
                            errorType
                        );
                        callback.onError(new Exception(userMessage, migrationError));
                    }
                }
            });
        } else {
            // Migration disabled, go straight to delete if enabled
            Log.w(TAG, "migrateOnAlgorithmChange is disabled. Skipping data migration.");

            if (config.shouldDeleteOnFailure()) {
                Log.w(TAG, "resetOnError is enabled. Deleting all data and keys to recover.");
                deleteAllDataAndKeys(configSource, callback);
            } else {
                Log.e(TAG, "Set resetOnError=true to automatically delete data and recover.");
                Log.e(TAG, "Or set migrateOnAlgorithmChange=true to preserve data during algorithm changes.");
                String userMessage = String.format(
                    "Key mismatch after algorithm change (%s). Enable migrateOnAlgorithmChange=true to preserve data, or resetOnError=true to delete.",
                    errorType
                );
                callback.onError(new Exception(userMessage, exception));
            }
        }
    }



    /**
     * Deletes all encrypted data, keys, and algorithm markers, then reinitializes.
     * Extracted from handleKeyMismatch for reuse.
     */
    private void deleteAllDataAndKeys(SharedPreferences configSource, SecurePreferencesCallback<Void> callback) {
        try {
            // Delete keys from AndroidKeyStore
            try {
                KeyCipher cipher = storageCipherFactory.getCurrentKeyCipher(context);
                cipher.deleteKey();
                Log.i(TAG, "Deleted key from AndroidKeyStore");
            } catch (Exception keyDeleteError) {
                Log.w(TAG, "Failed to delete key from AndroidKeyStore (may not exist)", keyDeleteError);
            }

            // Delete all encrypted data
            SharedPreferences dataPrefs = context.getSharedPreferences(
                    config.getSharedPreferencesName(),
                    Context.MODE_PRIVATE
            );
            dataPrefs.edit().clear().apply();
            Log.d(TAG, "Deleted all encrypted data");

            // Delete stored wrapped keys
            SharedPreferences keyPrefs = context.getSharedPreferences(
                    "FlutterSecureKeyStorage",
                    Context.MODE_PRIVATE
            );
            keyPrefs.edit().clear().apply();

            Log.d(TAG, "Deleted wrapped keys from SharedPreferences");


            // Update algorithm markers to current algorithm
            SharedPreferences.Editor editor = configSource.edit();
            storageCipherFactory.storeCurrentAlgorithms(editor);
            editor.apply();
            Log.d(TAG, "Updated algorithm markers to current");

            Log.w(TAG, "All data deleted. Reinitializing with new algorithm...");

            // Retry initialization with clean state
            initializeStorageCipher(configSource, callback);
        } catch (Exception cleanupError) {
            Log.e(TAG, "Failed to clean up after key mismatch", cleanupError);
            callback.onError(cleanupError);
        }
    }

    /**
     * Checks if biometric authentication is available on the device.
     * Returns false if:
     * - Android version is below API 28 (Android 9.0)
     * - No biometric hardware is available
     * - No biometric credentials are enrolled
     */
    public boolean isBiometricAvailable() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager biometricManager = context.getSystemService(BiometricManager.class);
            if (biometricManager == null) return false;

            int result = biometricManager.canAuthenticate(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG |
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
            );

            return result == BiometricManager.BIOMETRIC_SUCCESS && isDeviceSecure();
        } else {
            return isDeviceSecure();
        }
    }

    public boolean isDeviceSecure() {
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return keyguardManager != null && keyguardManager.isDeviceSecure();
    }

    /**
     * Returns the application context.
     * Used by RecoveryMode to access SharedPreferences and KeyStore.
     */
    @NonNull
    public Context getContext() {
        return context;
    }

    /**
     * Ensures biometric authentication is available when enforcement is enabled.
     *
     * @param enforceRequired If true, throws exception when biometric unavailable.
     *                       If false, only logs warning.
     * @throws Exception When enforcement enabled but biometric unavailable
     */
    private void ensureBiometricAvailable(boolean enforceRequired) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (enforceRequired) {
                throw new Exception("BIOMETRIC_UNAVAILABLE: Biometric authentication requires Android 9 (API 28) or higher");
            }
            return; // Graceful degradation
        }

        // Check device security first (PIN/pattern/password)
        if (!isDeviceSecure()) {
            if (enforceRequired) {
                throw new Exception("BIOMETRIC_UNAVAILABLE: Device has no PIN, pattern, password, or biometric enrolled. Please secure your device in Settings.");
            } else {
                Log.w(TAG, "Device has no security. Biometric authentication will be skipped (enforceBiometrics=false).");
            }
            return;
        }

        // For Android 11+, check BiometricManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager biometricManager = context.getSystemService(BiometricManager.class);

            if (biometricManager == null) {
                if (enforceRequired) {
                    throw new Exception("BIOMETRIC_UNAVAILABLE: BiometricManager not available on this device");
                }
                return;
            }

            int result = biometricManager.canAuthenticate(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG |
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
            );

            // Handle specific BiometricManager status codes
            switch (result) {
                case BiometricManager.BIOMETRIC_SUCCESS:
                    return; // OK to proceed

                case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                    if (enforceRequired) {
                        throw new Exception("BIOMETRIC_UNAVAILABLE: No biometric hardware detected on this device");
                    }
                    break;

                case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                    if (enforceRequired) {
                        throw new Exception("BIOMETRIC_UNAVAILABLE: Biometric hardware temporarily unavailable");
                    }
                    break;

                case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                    if (enforceRequired) {
                        throw new Exception("BIOMETRIC_UNAVAILABLE: No fingerprint or face enrolled. Please enroll in Settings.");
                    }
                    break;

                case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                    if (enforceRequired) {
                        throw new Exception("BIOMETRIC_UNAVAILABLE: Security update required for biometric authentication");
                    }
                    break;
                default:
                    if (enforceRequired) {
                        throw new Exception("BIOMETRIC_UNAVAILABLE: Unknown biometric status (code: " + result + ")");
                    }
                    break;
            }

            Log.w(TAG, "Biometric check failed with code " + result + ", but continuing (enforceBiometrics=false)");
        }
    }

    private void authenticateUser(Cipher cipher, SecurePreferencesCallback<BiometricPrompt.AuthenticationResult> securePreferencesCallback) throws Exception {
        // Check if biometric is available based on enforcement setting
        boolean enforceRequired = config.getEnforceBiometrics();
        ensureBiometricAvailable(enforceRequired);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (enforceRequired) {
                throw new Exception("BIOMETRIC_UNAVAILABLE: Biometric authentication requires Android 9 (API 28) or higher");
            }
            return; // Skip authentication if not enforced
        }

        BiometricPrompt.CryptoObject crypto = new BiometricPrompt.CryptoObject(cipher);

        BiometricPrompt.Builder promptInfoBuilder = new BiometricPrompt.Builder(context)
                .setTitle(config.getBiometricPromptTitle())
                .setSubtitle(config.getPrefOptionBiometricPromptSubtitle());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            promptInfoBuilder
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        }

        BiometricPrompt promptInfo = promptInfoBuilder
                .build();

        CancellationSignal cancellationSignal = new CancellationSignal();
        Executor executor = Executors.newSingleThreadExecutor();

        BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                securePreferencesCallback.onSuccess(result);
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.w(TAG, "Biometric authentication failed, user not recognized");
                securePreferencesCallback.onError(new Exception("Biometric authentication failed, user not recognized"));
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Log.e(TAG, "Biometric authentication error [" + errorCode + "]: " + errString);
                securePreferencesCallback.onError(new Exception("Biometric authentication error [" + errorCode + "]: " + errString));
            }
        };

        promptInfo.authenticate(crypto, cancellationSignal, executor, callback);
    }

    /**
     * Checks if EncryptedSharedPreferences contains any data with our prefix.
     */
    private boolean hasDataInEncryptedSharedPreferences(SharedPreferences encryptedPreferences) {
        Map<String, ?> all = encryptedPreferences.getAll();
        for (String key : all.keySet()) {
            if (key.contains(config.getSharedPreferencesKeyPrefix())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Migrates data from EncryptedSharedPreferences to custom cipher storage WITH backup protection.
     * This is a simpler migration since ESP data is already encrypted by Tink.
     * We just copy ESP keys → custom cipher without creating backups (ESP encryption is the backup).
     */
    private void migrateESPWithBackup(SharedPreferences espSource, SharedPreferences target,
                                      SharedPreferences configSource, SecurePreferencesCallback<Void> callback) {
        Log.i(TAG, "Starting ESP→custom cipher migration WITH backup protection...");

        // Initialize custom cipher for migration target
        initializeStorageCipher(configSource, new SecurePreferencesCallback<>() {
            @Override
            public void onSuccess(Void unused) {
                try {
                    // Migrate ESP data to custom cipher
                    migrateFromEncryptedSharedPreferences(espSource, target);
                    preferences = target;
                    Log.i(TAG, "ESP migration completed successfully. Now using custom cipher storage.");
                    setEncryptedPrefsMigrated(configSource);
                    callback.onSuccess(null);
                } catch (Exception e) {
                    Log.e(TAG, "ESP migration failed. Falling back to ESP.", e);
                    preferences = espSource;
                    callback.onSuccess(null);
                }
            }

            @Override
            public void onError(Exception e) {
                Log.e(TAG, "Cipher initialization failed during ESP migration. Using ESP.", e);
                preferences = espSource;
                callback.onSuccess(null);
            }
        });
    }

    /**
     * Migrates data from EncryptedSharedPreferences to custom cipher storage.
     * Data is read from ESP (plaintext after ESP decryption), then encrypted with custom cipher.
     */
    private void migrateFromEncryptedSharedPreferences(SharedPreferences source, SharedPreferences target) throws Exception {
        migrateFromEncryptedSharedPreferences(source, target, storageCipher);
    }

    /**
     * Migrates data from EncryptedSharedPreferences to custom cipher storage using specified cipher.
     * Data is read from ESP (plaintext after ESP decryption), then encrypted with custom cipher.
     */
    private void migrateFromEncryptedSharedPreferences(SharedPreferences source, SharedPreferences target, StorageCipher cipher) throws Exception {
        int migratedCount = 0;

        for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
            Object v = entry.getValue();
            String key = entry.getKey();

            if (v instanceof String plainValue && key.contains(config.getSharedPreferencesKeyPrefix())) {
                byte[] encrypted = cipher.encrypt(plainValue.getBytes(charset));
                String baseEncoded = Base64.encodeToString(encrypted, 0);
                target.edit().putString(key, baseEncoded).apply();

                // Remove from EncryptedSharedPreferences
                source.edit().remove(key).apply();

                migratedCount++;
                Log.d(TAG, "Migrated key: " + key.replaceFirst(config.getSharedPreferencesKeyPrefix() + '_', ""));
            }
        }

        Log.i(TAG, "Migration complete: " + migratedCount + " items migrated from EncryptedSharedPreferences to custom cipher storage");
    }

    private SharedPreferences initializeEncryptedSharedPreferencesManager(Context context) throws GeneralSecurityException, IOException {
        MasterKey key = new MasterKey.Builder(context)
                .setKeyGenParameterSpec(
                        new KeyGenParameterSpec
                                .Builder(MasterKey.DEFAULT_MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setKeySize(256).build())
                .build();
        return EncryptedSharedPreferences.create(
                context,
                config.getSharedPreferencesName(),
                key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    /**
     * Handles storage operation errors. If resetOnError is enabled, deletes corrupted data.
     *
     * @param operation The operation that failed (read, write, readAll)
     * @param key The key involved (null for readAll)
     * @param error The exception that occurred
     * @return true if data was deleted and operation should be retried, false otherwise
     */
    private boolean handleStorageError(String operation, String key, Exception error) {
        final boolean deleteOnFailure = config.shouldDeleteOnFailure();
        final String target = (key != null) ? "key '" + key + "'" : "all data";

        Log.e(TAG, String.format(
                "Storage operation '%s' failed for %s. %s",
                operation,
                target,
                deleteOnFailure
                        ? "Attempting to delete corrupted data and retry..."
                        : "Set resetOnError=true to automatically delete corrupted data."
        ), error);

        if (!deleteOnFailure) {
            return false;
        }

        try {
            if (key != null) {
                delete(key);
            } else {
                deleteAll();
            }
            Log.w(TAG, String.format(
                    "%s completed. Retrying operation...",
                    (key != null) ? "Data for key has been deleted" : "All data has been deleted"
            ));
            return true; // Indicate that retry should be attempted
        } catch (Exception deleteError) {
            Log.e(TAG, String.format(
                    "Failed to %s during error handling.",
                    (key != null) ? "delete data for key" : "delete all data"
            ), deleteError);
            return false; // Don't retry if deletion failed
        }
    }

    private String decodeRawValue(String value) throws Exception {
        if (value == null) {
            return null;
        }
        byte[] data = Base64.decode(value, 0);
        byte[] result = storageCipher.decrypt(data);

        return new String(result, charset);
    }
    // ============================================================================
    // MIGRATION WITH BACKUP METHODS
    // ============================================================================

        private void migrateNonBiometricWithBackup(SharedPreferences configSource, SharedPreferences dataSource,
                                                   SecurePreferencesCallback<Void> callback) {
            Log.i(TAG, "Starting non-biometric migration WITH BACKUP (rename operation)...");

            try {
                SharedPreferences keyStorage = context.getSharedPreferences(
                    "FlutterSecureKeyStorage", Context.MODE_PRIVATE);

                // Step 1: Create backup - copies data + wrapped keys to _BACKUP, keeps originals.
                // createBackup() is idempotent: skips internally if status is already "complete".
                // On retry after crash, backup is already complete so this is a no-op.
                Log.d(TAG, "Step 1/8: Creating backup (copy originals to _BACKUP, keep originals)...");
                if (storageCipherFactory.changedKeyAlgorithm()) {
                    MigrationBackup.createBackup(
                        dataSource,
                        keyStorage,
                        configSource,
                        config,
                        config.getSharedPreferencesKeyPrefix()
                    );
                    Log.i(TAG, "Backup step complete - originals preserved alongside _BACKUP copies");
                } else {
                    Log.i(TAG, "No algorithm change detected, skipping backup");
                }

                // Step 2: Restore wrapped keys from _BACKUP, then initialize old cipher.
                // On first run: originals still exist, restore is a no-op (same value).
                // On retry after crash at step 4 or earlier: originals were deleted, restore brings them back.
                // IMPORTANT: If _MIGRATED markers exist, step 6 already ran (at least partially) in a prior
                // crashed run. The new OAEP-wrapped AES key is already in keyStorage. We still need to
                // temporarily restore the old _BACKUP key so getSavedStorageCipher can initialize (it reads
                // from keyStorage using the old RSA key). After savedCipher is initialized, we put the new
                // key back so step 6's preserved data remains readable with the new cipher.
                Log.d(TAG, "Step 2/8: Restoring wrapped keys from _BACKUP and initializing saved cipher...");
                boolean alreadyPartiallyMigrated = MigrationBackup.hasMigratedMarkers(
                        configSource, config.getSharedPreferencesKeyPrefix());
                // If step 6 ran previously, save the current (new) keyStorage entries so we can
                // restore them after initializing savedCipher from the _BACKUP blobs.
                Map<String, String> newKeyStorageEntries = new HashMap<>();
                if (alreadyPartiallyMigrated) {
                    for (Map.Entry<String, ?> entry : keyStorage.getAll().entrySet()) {
                        String k = entry.getKey();
                        if (!k.endsWith("_BACKUP") && entry.getValue() instanceof String) {
                            newKeyStorageEntries.put(k, (String) entry.getValue());
                        }
                    }
                    Log.d(TAG, "Step 2/8: _MIGRATED markers found — saved " + newKeyStorageEntries.size()
                            + " new key entries; temporarily restoring _BACKUP blobs for savedCipher init");
                }
                // Restore _BACKUP key blobs (so savedCipher can unwrap with old RSA key)
                SharedPreferences.Editor keyRestoreEditor = keyStorage.edit();
                for (Map.Entry<String, ?> entry : keyStorage.getAll().entrySet()) {
                    String k = entry.getKey();
                    if (k.endsWith("_BACKUP") && entry.getValue() instanceof String) {
                        String originalKey = k.substring(0, k.length() - "_BACKUP".length());
                        keyRestoreEditor.putString(originalKey, (String) entry.getValue());
                    }
                }
                keyRestoreEditor.commit();
                StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, null);
                // After savedCipher init: if step 6 already ran, put the new wrapped key back
                // so subsequent reads (and step 6 for any remaining keys) use the correct cipher.
                if (alreadyPartiallyMigrated && !newKeyStorageEntries.isEmpty()) {
                    SharedPreferences.Editor keyRevertEditor = keyStorage.edit();
                    for (Map.Entry<String, String> entry : newKeyStorageEntries.entrySet()) {
                        keyRevertEditor.putString(entry.getKey(), entry.getValue());
                    }
                    keyRevertEditor.commit();
                    Log.d(TAG, "Step 2/8: New wrapped key restored to keyStorage after savedCipher init");
                }

                // Step 3: Decrypt all data FROM _BACKUP keys (in memory only)
                // _BACKUP keys always contain the original old ciphertext, regardless of how many
                // times migration has been retried. Even if step 6 already re-encrypted the
                // Step 2 restored the wrapped AES key blob to its original name so savedCipher
                // is initialized correctly. Data is read from _BACKUP keys (not originals) because
                // originals may already be re-encrypted with the new cipher from a prior partial run.
                Log.d(TAG, "Step 3/8: Decrypting all data from _BACKUP keys...");
                Map<String, String> decryptedCache = decryptAllWithSavedCipherFromBackup(dataSource, null, savedCipher);
                Log.d(TAG, "Successfully decrypted " + decryptedCache.size() + " items from _BACKUP keys");

                // Step 4: Delete originals from dataSource and keyStorage.
                // Keys already marked _MIGRATED in configSource are preserved — they were
                // successfully re-encrypted on a prior (crashed) run and must not be deleted,
                // as step 6 will skip them (they're already in dataSource with new cipher).
                Log.d(TAG, "Step 4/8: Deleting original encrypted entries (preserving already-migrated)...");
                MigrationBackup.deleteOriginalData(dataSource, keyStorage, configSource, config.getSharedPreferencesKeyPrefix());

                if (decryptedCache.isEmpty()) {
                    Log.i(TAG, "No data found to migrate");
                } else {
                    Log.i(TAG, "Found " + decryptedCache.size() + " items to migrate");
                }

                // Step 5: Create new cipher (NEW algorithm)
                Log.d(TAG, "Step 5/8: Initializing current cipher with new algorithm...");
                StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, null);

                if (decryptedCache.isEmpty()) {
                    Log.i(TAG, "Step 6/8: No data to encrypt, skipping...");
                } else {
                    // Step 6: Encrypt all data with NEW cipher, tracking per-key progress.
                    // On retry after a crash mid-step 6, keys already marked _MIGRATED are skipped.
                    Log.d(TAG, "Step 6/8: Encrypting all data with current cipher (per-key tracking)...");
                    encryptAllWithCurrentCipherTracked(decryptedCache, dataSource, configSource, currentCipher,
                                                       config.getSharedPreferencesKeyPrefix());
                }

                // Step 7: Migrate ESP data if present (after algorithm migration complete)
                Log.d(TAG, "Step 7/8: Checking for ESP data to migrate...");

                // Check if ESP migration is needed
                Boolean isESPMigrated = getEncryptedPrefsMigrated(configSource);
                if (!isESPMigrated) {
                    try {
                        SharedPreferences encryptedPreferences = initializeEncryptedSharedPreferencesManager(context);
                        if (hasDataInEncryptedSharedPreferences(encryptedPreferences)) {
                            Log.i(TAG, "Found ESP data - migrating to custom cipher storage...");
                            migrateFromEncryptedSharedPreferences(encryptedPreferences, dataSource, currentCipher);
                            setEncryptedPrefsMigrated(configSource);
                            Log.i(TAG, "ESP migration completed successfully");
                        } else {
                            Log.d(TAG, "No ESP data found");
                        }
                    } catch (Exception espError) {
                        Log.w(TAG, "ESP migration failed or ESP not available: " + espError.getMessage());
                    }
                }

                // Step 8: Cleanup
                Log.d(TAG, "Step 8/8: Cleaning up - deleting _BACKUP, _MIGRATED markers, updating markers, deleting old keys...");

                // Delete all _BACKUP entries and _MIGRATED markers
                MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, config,
                                            config.getSharedPreferencesKeyPrefix());
                MigrationBackup.deleteMigratedMarkers(configSource, config.getSharedPreferencesKeyPrefix());
    
                // Update algorithm markers to NEW algorithms
                updateAlgorithmMarkers(configSource);
    
                // Delete OLD RSA keys from Android KeyStore
                if (storageCipherFactory.changedKeyAlgorithm()) {
                    try {
                        KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                        savedKeyCipher.deleteKey();
                        savedCipher.deleteKey(context);
                        Log.d(TAG, "Old RSA keys deleted from KeyStore");
                    } catch (Exception deleteError) {
                        Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                    }
                }
    
                // Update storageCipher to current
                storageCipher = currentCipher;

                Log.i(TAG, "Non-biometric migration WITH BACKUP completed successfully!");
                Log.i(TAG, "Migrated " + decryptedCache.size() + " data items with new algorithm.");

                callback.onSuccess(null);

            } catch (Exception e) {
                Log.e(TAG, "Non-biometric migration with backup failed", e);
                callback.onError(new Exception("Non-biometric migration with backup failed", e));
            }
        }
        private Map<String, String> decryptAllWithSavedCipherFromBackup(SharedPreferences dataSource,
                                                                         SharedPreferences espSource,
                                                                         StorageCipher savedStorageCipher) throws Exception {
            Map<String, String> decryptedCache = new HashMap<>();
            int encryptedCount = 0;
            int espCount = 0;

            // Decrypt ESP _BACKUP keys if ESP source provided
            if (espSource != null) {
                try {
                    for (Map.Entry<String, ?> entry : espSource.getAll().entrySet()) {
                        String key = entry.getKey();
                        Object value = entry.getValue();

                        // Only process _BACKUP keys
                        if (value instanceof String && key.contains(config.getSharedPreferencesKeyPrefix())
                            && key.endsWith("_BACKUP")) {
                            String stringValue = (String) value;
                            String originalKey = key.substring(0, key.length() - "_BACKUP".length());

                            // ESP data is already decrypted by ESP (Tink library)
                            // No need to decrypt again - just use the value directly
                            decryptedCache.put(originalKey, stringValue);
                            espCount++;
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Failed to read ESP _BACKUP keys: " + e.getMessage());
                    // Continue with regular backup keys
                }
            }

            // Decrypt regular _BACKUP keys from dataSource
            for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                // Only process _BACKUP keys
                if (value instanceof String && key.contains(config.getSharedPreferencesKeyPrefix())
                    && key.endsWith("_BACKUP")) {
                    String stringValue = (String) value;
                    String originalKey = key.substring(0, key.length() - "_BACKUP".length());

                    try {
                        // Decode Base64 and decrypt with saved cipher
                        byte[] encryptedData = Base64.decode(stringValue, 0);
                        byte[] decryptedData = savedStorageCipher.decrypt(encryptedData);
                        String plainValue = new String(decryptedData, charset);

                        decryptedCache.put(originalKey, plainValue);
                        encryptedCount++;
                    } catch (Exception decryptError) {
                        Log.e(TAG, "Failed to decrypt _BACKUP key (skipping): " + key, decryptError);
                    }
                }
            }

            Log.d(TAG, "Successfully processed " + (encryptedCount + espCount) + " items from _BACKUP keys (" +
                  encryptedCount + " encrypted, " + espCount + " ESP)");
            return decryptedCache;
        }
        private void migrateFromBiometricToNonBiometricWithBackup(SharedPreferences configSource, SharedPreferences dataSource,
                                                                   SecurePreferencesCallback<Void> callback) {
            try {
                SharedPreferences keyStorage = context.getSharedPreferences(
                    "FlutterSecureKeyStorage", Context.MODE_PRIVATE);
    
                // Step 0: Create backup BEFORE any destructive operations
                String backupStatus = MigrationBackup.getBackupStatus(configSource, config);
                if (!MigrationBackup.STATUS_COMPLETE.equals(backupStatus)) {
                    Log.i(TAG, "Creating backup before biometric→non-biometric migration...");
                    MigrationBackup.createBackup(
                        dataSource,
                        keyStorage,
                        configSource,
                        config,
                        config.getSharedPreferencesKeyPrefix()
                    );
                    Log.i(TAG, "Backup created successfully");
                }
    
                // Step 1: Get OLD biometric cipher (requires authentication)
                Log.d(TAG, "Step 1/7: Getting saved biometric cipher...");
                KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                Cipher oldKeyCipher = savedKeyCipher.getCipher(context);
    
                if (oldKeyCipher == null) {
                    throw new Exception("Failed to get saved biometric cipher");
                }
    
                Log.i(TAG, "Authenticating with OLD biometric cipher to decrypt data...");
    
                // Authenticate with OLD cipher
                authenticateUser(oldKeyCipher, new SecurePreferencesCallback<>() {
                    @Override
                    public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                        try {
                            // Step 2: Decrypt with OLD biometric cipher FROM BACKUP
                            Log.d(TAG, "Step 2/7: Decrypting all data from _BACKUP with saved biometric cipher...");
                            StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, oldKeyCipher);
                            Map<String, String> decryptedCache = decryptAllWithSavedCipherFromBackup(dataSource, null, savedCipher);
    
                            // Step 3: Get NEW non-biometric cipher (no auth)
                            Log.d(TAG, "Step 3/7: Initializing current non-biometric cipher...");
                            StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, null);
    
                            // Step 4: Encrypt all data with NEW cipher
                            Log.d(TAG, "Step 4/7: Encrypting all data with current cipher...");
                            encryptAllWithCurrentCipher(decryptedCache, dataSource, currentCipher);
    
                            // Step 5: Delete backup - data successfully re-encrypted
                            Log.d(TAG, "Step 5/7: Deleting backup after successful re-encryption...");
                            MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, config,
                                                        config.getSharedPreferencesKeyPrefix());
    
                            // Step 6: Update algorithm markers AFTER successful re-encryption
                            Log.d(TAG, "Step 6/7: Updating algorithm markers to current...");
                            updateAlgorithmMarkers(configSource);
    
                            // Step 7: Delete OLD biometric AES key from Android KeyStore
                            Log.d(TAG, "Step 7/7: Deleting old biometric AES key from Android KeyStore...");
                            if (storageCipherFactory.changedKeyAlgorithm()) {
                                try {
                                    KeyCipher oldKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                                    oldKeyCipher.deleteKey();
                                    savedCipher.deleteKey(context);
                                    Log.d(TAG, "Old key deleted from KeyStore");
                                } catch (Exception deleteError) {
                                    Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                                }
                            }
    
                            storageCipher = currentCipher;
    
                            Log.i(TAG, "Biometric→Non-biometric migration WITH BACKUP completed! Data no longer requires biometric authentication.");
                            callback.onSuccess(null);
                        } catch (Exception e) {
                            Log.e(TAG, "Failed to complete migration after authentication", e);
                            callback.onError(e);
                        }
                    }
    
                    @Override
                    public void onError(Exception e) {
                        Log.e(TAG, "Biometric authentication failed for migration", e);
                        callback.onError(new Exception("Migration cancelled: Biometric authentication failed", e));
                    }
                });
            } catch (Exception e) {
                Log.e(TAG, "Failed to initialize biometric migration with backup", e);
                callback.onError(e);
            }
        }
        private void migrateFromNonBiometricToBiometricWithBackup(SharedPreferences configSource, SharedPreferences dataSource,
                                                                   SecurePreferencesCallback<Void> callback) {
            try {
                SharedPreferences keyStorage = context.getSharedPreferences(
                    "FlutterSecureKeyStorage", Context.MODE_PRIVATE);
    
                // Step 0: Create backup BEFORE any destructive operations
                String backupStatus = MigrationBackup.getBackupStatus(configSource, config);
                if (!MigrationBackup.STATUS_COMPLETE.equals(backupStatus)) {
                    Log.i(TAG, "Creating backup before non-biometric→biometric migration...");
                    MigrationBackup.createBackup(
                        dataSource,
                        keyStorage,
                        configSource,
                        config,
                        config.getSharedPreferencesKeyPrefix()
                    );
                    Log.i(TAG, "Backup created successfully");
                }
    
                // Step 1: Decrypt with OLD non-biometric cipher FROM BACKUP (no auth)
                Log.d(TAG, "Step 1/7: Decrypting all data from _BACKUP with saved non-biometric cipher...");
                StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, null);
                Map<String, String> decryptedCache = decryptAllWithSavedCipherFromBackup(dataSource, null, savedCipher);
    
                // Step 2: Get NEW biometric cipher (requires authentication)
                Log.d(TAG, "Step 2/7: Getting current biometric cipher...");
                KeyCipher currentKeyCipher = storageCipherFactory.getCurrentKeyCipher(context);
                Cipher newCipher = currentKeyCipher.getCipher(context);
    
                if (newCipher == null) {
                    throw new Exception("Failed to get current biometric cipher");
                }
    
                Log.i(TAG, "Authenticating with NEW biometric cipher to encrypt data...");
    
                // Authenticate with NEW cipher
                final Map<String, String> cachedData = decryptedCache; // Make final for lambda
                authenticateUser(newCipher, new SecurePreferencesCallback<>() {
                    @Override
                    public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                        try {
                            // Step 3: Initialize current biometric cipher
                            Log.d(TAG, "Step 3/7: Initializing current biometric cipher...");
                            StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, newCipher);
    
                            // Step 4: Encrypt all data with NEW biometric cipher
                            Log.d(TAG, "Step 4/7: Encrypting all data with current biometric cipher...");
                            encryptAllWithCurrentCipher(cachedData, dataSource, currentCipher);
    
                            // Step 5: Delete backup - data successfully re-encrypted
                            Log.d(TAG, "Step 5/7: Deleting backup after successful re-encryption...");
                            MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, config,
                                                        config.getSharedPreferencesKeyPrefix());
    
                            // Step 6: Update algorithm markers AFTER successful re-encryption
                            Log.d(TAG, "Step 6/7: Updating algorithm markers to current...");
                            updateAlgorithmMarkers(configSource);
    
                            // Step 7: Delete OLD RSA key from Android KeyStore
                            Log.d(TAG, "Step 7/7: Deleting old RSA key from Android KeyStore...");
                            if (storageCipherFactory.changedKeyAlgorithm()) {
                                try {
                                    KeyCipher oldKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                                    oldKeyCipher.deleteKey();
                                    savedCipher.deleteKey(context);
                                    Log.d(TAG, "Old key deleted from KeyStore");
                                } catch (Exception deleteError) {
                                    Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                                }
                            }
    
                            storageCipher = currentCipher;
    
                            Log.i(TAG, "Non-biometric→Biometric migration WITH BACKUP completed! Data now requires biometric authentication.");
                            callback.onSuccess(null);
                        } catch (Exception e) {
                            Log.e(TAG, "Failed to complete migration after authentication", e);
                            callback.onError(e);
                        }
                    }
    
                    @Override
                    public void onError(Exception e) {
                        Log.e(TAG, "Biometric authentication failed for migration", e);
                        callback.onError(new Exception("Migration cancelled: Biometric authentication failed", e));
                    }
                });
            } catch (Exception e) {
                Log.e(TAG, "Failed to initialize biometric migration with backup", e);
                callback.onError(e);
            }
        }
        private void migrateBiometricToBiometricWithBackup(SharedPreferences configSource, SharedPreferences dataSource,
                                                            SecurePreferencesCallback<Void> callback) {
            try {
                SharedPreferences keyStorage = context.getSharedPreferences(
                    "FlutterSecureKeyStorage", Context.MODE_PRIVATE);
    
                // Step 0: Create backup BEFORE any destructive operations
                String backupStatus = MigrationBackup.getBackupStatus(configSource, config);
                if (!MigrationBackup.STATUS_COMPLETE.equals(backupStatus)) {
                    Log.i(TAG, "Creating backup before biometric→biometric migration...");
                    MigrationBackup.createBackup(
                        dataSource,
                        keyStorage,
                        configSource,
                        config,
                        config.getSharedPreferencesKeyPrefix()
                    );
                    Log.i(TAG, "Backup created successfully");
                }
    
                // Step 1: Get OLD biometric cipher
                Log.d(TAG, "Step 1/8: Getting saved biometric cipher...");
                KeyCipher savedKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                Cipher oldCipher = savedKeyCipher.getCipher(context);
    
                if (oldCipher == null) {
                    throw new Exception("Failed to get saved biometric cipher");
                }
    
                Log.i(TAG, "Authenticating with OLD biometric cipher to decrypt data...");
    
                // First authentication: OLD cipher
                authenticateUser(oldCipher, new SecurePreferencesCallback<>() {
                    @Override
                    public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                        try {
                            // Step 2: Decrypt with OLD biometric cipher FROM BACKUP
                            Log.d(TAG, "Step 2/8: Decrypting all data from _BACKUP with saved biometric cipher...");
                            StorageCipher savedCipher = storageCipherFactory.getSavedStorageCipher(context, oldCipher);
                            Map<String, String> decryptedCache = decryptAllWithSavedCipherFromBackup(dataSource, null, savedCipher);
    
                            if (decryptedCache.isEmpty()) {
                                Log.i(TAG, "No data found in _BACKUP keys to migrate");
                            } else {
                                Log.i(TAG, "Found " + decryptedCache.size() + " items to migrate from _BACKUP keys");
                            }
    
                            // Step 3: Get NEW biometric cipher (CONTINUES REGARDLESS)
                            Log.d(TAG, "Step 3/8: Getting current biometric cipher...");
                            KeyCipher currentKeyCipher = storageCipherFactory.getCurrentKeyCipher(context);
                            Cipher newCipher = currentKeyCipher.getCipher(context);
    
                            if (newCipher == null) {
                                throw new Exception("Failed to get current biometric cipher");
                            }
    
                            Log.i(TAG, "Authenticating with NEW biometric cipher to encrypt data...");
    
                            // Second authentication: NEW cipher
                            final Map<String, String> cachedData = decryptedCache;
                            authenticateUser(newCipher, new SecurePreferencesCallback<>() {
                                @Override
                                public void onSuccess(BiometricPrompt.AuthenticationResult unused) {
                                    try {
                                        // Step 4: Initialize current biometric cipher
                                        Log.d(TAG, "Step 4/8: Initializing current biometric cipher...");
                                        StorageCipher currentCipher = storageCipherFactory.getCurrentStorageCipher(context, newCipher);
    
                                        // Step 5: Encrypt all data with NEW biometric cipher
                                        if (cachedData.isEmpty()) {
                                            Log.i(TAG, "Step 5/8: No data to encrypt, skipping...");
                                        } else {
                                            Log.d(TAG, "Step 5/8: Encrypting all data with current biometric cipher...");
                                            encryptAllWithCurrentCipher(cachedData, dataSource, currentCipher);
                                        }
    
                                        // Step 6: Delete backup - data successfully re-encrypted
                                        Log.d(TAG, "Step 6/8: Deleting backup after successful re-encryption...");
                                        MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, config,
                                                                    config.getSharedPreferencesKeyPrefix());
    
                                        // Step 7: Update algorithm markers AFTER successful re-encryption
                                        Log.d(TAG, "Step 7/8: Updating algorithm markers to current...");
                                        updateAlgorithmMarkers(configSource);
    
                                        // Step 8: Delete OLD biometric AES key from Android KeyStore
                                        Log.d(TAG, "Step 8/8: Deleting old biometric AES key from Android KeyStore...");
                                        if (storageCipherFactory.changedKeyAlgorithm()) {
                                            try {
                                                KeyCipher oldKeyCipher = storageCipherFactory.getSavedKeyCipher(context);
                                                oldKeyCipher.deleteKey();
                                                savedCipher.deleteKey(context);
                                                Log.d(TAG, "Old key deleted from KeyStore");
                                            } catch (Exception deleteError) {
                                                Log.w(TAG, "Failed to delete old key from KeyStore (may not exist)", deleteError);
                                            }
                                        }
    
                                        storageCipher = currentCipher;
    
                                        Log.i(TAG, "Biometric→Biometric migration WITH BACKUP completed! Data now uses new biometric cipher.");
                                        Log.i(TAG, "Migrated " + cachedData.size() + " data items with new biometric algorithm.");
                                        callback.onSuccess(null);
                                    } catch (Exception e) {
                                        Log.e(TAG, "Failed to complete migration after second authentication", e);
                                        callback.onError(e);
                                    }
                                }
    
                                @Override
                                public void onError(Exception e) {
                                    Log.e(TAG, "Second biometric authentication failed for migration", e);
                                    callback.onError(new Exception("Migration cancelled: Second biometric authentication failed", e));
                                }
                            });
                        } catch (Exception e) {
                            Log.e(TAG, "Failed after first authentication", e);
                            callback.onError(e);
                        }
                    }
    
                    @Override
                    public void onError(Exception e) {
                        Log.e(TAG, "First biometric authentication failed for migration", e);
                        callback.onError(new Exception("Migration cancelled: First biometric authentication failed", e));
                    }
                });
            } catch (Exception e) {
                Log.e(TAG, "Failed to initialize biometric-to-biometric migration with backup", e);
                callback.onError(e);
            }
        }
}
