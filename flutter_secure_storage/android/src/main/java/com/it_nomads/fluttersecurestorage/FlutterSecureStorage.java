package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherFactory;
import com.it_nomads.fluttersecurestorage.crypto.EncryptedSharedPreferences;
import com.it_nomads.fluttersecurestorage.crypto.MasterKey;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class FlutterSecureStorage {

    private static final String TAG = "FlutterSecureStorage";
    private static final Charset CHARSET = StandardCharsets.UTF_8;
    private static final String PREF_KEY_MIGRATED = "preferencesMigrated";

    @NonNull
    private final FlutterSecureStorageConfig config;
    @NonNull
    private final Context context;

    private SharedPreferences encryptedPreferences;

    private FlutterSecureStorage(@NonNull Context context, Map<String, Object> options) {
        this.context = context;
        this.config = new FlutterSecureStorageConfig(options);
    }

    public static void create(@NonNull Context context, Map<String, Object> options, SecureStorageInitCallback callback) {
        FlutterSecureStorage storage = new FlutterSecureStorage(context, options);

        storage.authenticateIfNeeded(() -> {
            try {
                SharedPreferences encryptedPreferences = storage.initializeEncryptedSharedPreferencesManager(storage.config.getSharedPreferencesName());
                boolean migrated = encryptedPreferences.getBoolean(PREF_KEY_MIGRATED, false);
                if (!migrated) {
                    storage.migrateToEncryptedPreferences(storage.config.getSharedPreferencesName(), encryptedPreferences, storage.config.shouldDeleteOnFailure(), options);
                }

                Log.d(TAG, "Encrypted preferences initialized successfully.");
                storage.encryptedPreferences = encryptedPreferences;
                callback.onComplete(storage, null);  // Initialization successful

             } catch (KeyStoreException | UserNotAuthenticatedException e) {
                Log.w(TAG, "Authentication failed: Unable to access secure keystore. Check biometric settings.", e);
                callback.onComplete(null, e);

            } catch (GeneralSecurityException | IOException e) {
                if (!storage.config.shouldDeleteOnFailure()) {
                    Log.w(TAG, "Initialization failed: Secure storage could not be initialized. 'deleteOnFailure' is false, skipping reset.", e);
                    callback.onComplete(null, e);
                } else {
                    Log.w(TAG, "Initialization failed: Resetting storage as 'deleteOnFailure' is enabled.", e);
                    context.getSharedPreferences(storage.config.getSharedPreferencesName(), Context.MODE_PRIVATE).edit().clear().apply();

                    try {
                        SharedPreferences encryptedPreferences = storage.initializeEncryptedSharedPreferencesManager(storage.config.getSharedPreferencesName());
                        Log.i(TAG, "Secure storage successfully re-initialized after reset.");
                        storage.encryptedPreferences = encryptedPreferences;
                        callback.onComplete(storage, null);  // Re-initialization successful
                    } catch (Exception f) {
                        Log.e(TAG, "Critical failure: Initialization after reset failed.", f);
                        callback.onComplete(null, f);
                    }
                }
            }
        });
    }

    public boolean containsKey(String key) {
        return encryptedPreferences.contains(addPrefixToKey(key));
    }

    public String read(String key) {
        return encryptedPreferences.getString(addPrefixToKey(key), null);
    }

    public void write(String key, String value) {
        encryptedPreferences.edit().putString(addPrefixToKey(key), value).apply();
    }

    public void delete(String key) {
        encryptedPreferences.edit().remove(addPrefixToKey(key)).apply();
    }

    public void deleteAll() {
        encryptedPreferences.edit().clear().apply();
    }

    public Map<String, String> readAll() {
        Map<String, String> result = new HashMap<>();
        Map<String, ?> allEntries = encryptedPreferences.getAll();
        for (Map.Entry<String, ?> entry : allEntries.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (key.startsWith(config.getSharedPreferencesKeyPrefix()) && value instanceof String) {
                String originalKey = key.replaceFirst(config.getSharedPreferencesKeyPrefix() + "_", "");
                result.put(originalKey, (String) value);
            }
        }
        return result;
    }

    private void authenticateIfNeeded(Runnable onSuccess) {
        if (config.shouldUseBiometrics()) {
            authenticateUser(onSuccess);
        } else {
            onSuccess.run();
        }
    }

    private String addPrefixToKey(String key) {
        return config.getSharedPreferencesKeyPrefix() + "_" + key;
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    private MasterKey createSecretKeyApi30() throws GeneralSecurityException, IOException {
        return new MasterKey.Builder(context)
                .setUserAuthenticationRequired(config.shouldUseBiometrics(), 2)
                .setRequestStrongBoxBacked(true)
                .setKeyGenParameterSpec(new KeyGenParameterSpec.Builder(
                        MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setIsStrongBoxBacked(true)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationRequired(config.shouldUseBiometrics())  // Enforce user authentication
                        .setUserAuthenticationValidityDurationSeconds(2)
                        .setInvalidatedByBiometricEnrollment(true)
                        .setKeySize(256)
                        .build())
                .build();
    }

    private MasterKey createSecretKeyApi2329() throws GeneralSecurityException, IOException {
        return new MasterKey.Builder(context)
                .setKeyGenParameterSpec(new KeyGenParameterSpec.Builder(
                        MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationRequired(config.shouldUseBiometrics())  // Enforce user authentication
                        .setUserAuthenticationValidityDurationSeconds(1)
                        .setKeySize(256)
                        .build())
                .build();
    }
    private SharedPreferences initializeEncryptedSharedPreferencesManager(String sharedPreferencesName) throws GeneralSecurityException, IOException {
        MasterKey masterKey;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            masterKey = createSecretKeyApi30();
        } else {
            masterKey = createSecretKeyApi2329();
        }

        return EncryptedSharedPreferences.create(
                context,
                sharedPreferencesName,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    private void migrateToEncryptedPreferences(String sharedPreferencesName, SharedPreferences target, boolean deleteOnFailure, Map<String, Object> options) {
        SharedPreferences source = context.getSharedPreferences(sharedPreferencesName, Context.MODE_PRIVATE);

        Map<String, ?> sourceEntries = source.getAll();
        if (sourceEntries.isEmpty()) return;

        int succesfull = 0;
        int failed = 0;

        try {
            StorageCipher cipher = new StorageCipherFactory(source, options).getSavedStorageCipher(context);

            for (Map.Entry<String, ?> entry : sourceEntries.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                if (key.startsWith(config.getSharedPreferencesKeyPrefix()) && value instanceof String) {
                    try {
                        String decryptedValue = decryptValue((String) value, cipher);
                        target.edit().putString(key, decryptedValue).apply();
                        source.edit().remove(key).apply();
                        succesfull++;
                    } catch (Exception e) {
                        Log.e(TAG, "Migration failed for key: " + key, e);
                        failed++;

                        if (deleteOnFailure) {
                            source.edit().remove(key).apply();
                        }
                    }
                }
            }

            if (succesfull > 0) {
                Log.i(TAG, "Successfully migrated " + succesfull + " keys.");
            }

            if (failed > 0) {
                Log.w(TAG, "Failed to migrate " + failed + " keys.");
            }

            if (failed == 0 || deleteOnFailure) {
                target.edit().putBoolean(PREF_KEY_MIGRATED, true).apply();
            }

        } catch(Exception e) {
            Log.e(TAG, "Migration failed due to initialisation error.", e);

            // If a failure has occurred during StorageCipher initialization, set migrated to true
            // so migration is not run again
            if (deleteOnFailure) {
                target.edit().putBoolean(PREF_KEY_MIGRATED, true).apply();
            }
        }
    }

    private String decryptValue(String value, StorageCipher cipher) throws Exception {
        byte[] data = Base64.decode(value, Base64.DEFAULT);
        return new String(cipher.decrypt(data), CHARSET);
    }

    private void authenticateUser(Runnable onSuccess) {
        BiometricPrompt promptInfo = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            promptInfo = new BiometricPrompt.Builder(context)
                    .setTitle(config.getBiometricPromptTitle())
                    .setSubtitle(config.getPrefOptionBiometricPromptSubtitle())
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                    .build();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            promptInfo = new BiometricPrompt.Builder(context)
                    .setTitle(config.getBiometricPromptTitle())
                    .setSubtitle(config.getPrefOptionBiometricPromptSubtitle())
                    .build();
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            CancellationSignal cancellationSignal = new CancellationSignal();
            Executor executor = Executors.newSingleThreadExecutor();

            BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    Log.d(TAG, "Authentication Succeeded!");
                    onSuccess.run();
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    Log.d(TAG, "Authentication Failed. Try again.");
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    Log.e(TAG, "Authentication Error: " + errString);
                }
            };

            promptInfo.authenticate(cancellationSignal, executor, callback);
        } else {
            onSuccess.run();  // Proceed without authentication on unsupported devices
        }
    }

}
