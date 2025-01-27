package com.it_nomads.fluttersecurestorage;

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
    private static final String DEFAULT_PREF_NAME = "FlutterSecureStorage";
    private static final String DEFAULT_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    private static final String PREF_OPTION_NAME = "sharedPreferencesName";
    private static final String PREF_OPTION_PREFIX = "preferencesKeyPrefix";
    private static final String PREF_OPTION_DELETE_ON_FAILURE = "resetOnError";
    private static final String PREF_KEY_MIGRATED = "preferencesMigrated";
    @NonNull
    private final SharedPreferences encryptedPreferences;
    @NonNull
    private String preferencesKeyPrefix = DEFAULT_KEY_PREFIX;

    boolean shouldAuthenticate = true;

    public FlutterSecureStorage(Context context, Map<String, Object> options) throws GeneralSecurityException, IOException, KeyStoreException {
        String sharedPreferencesName = DEFAULT_PREF_NAME;
        if (options.containsKey(PREF_OPTION_NAME)) {
            var value = options.get(PREF_OPTION_NAME);
            if (value instanceof String && !((String) value).isEmpty()) {
                sharedPreferencesName = (String) value;
            }
        }

        if (options.containsKey(PREF_OPTION_PREFIX)) {
            var value = options.get(PREF_OPTION_PREFIX);
            if (value instanceof String && !((String) value).isEmpty()) {
                preferencesKeyPrefix = (String) value;
            }
        }

        boolean deleteOnFailure = false;

        if (options.containsKey(PREF_OPTION_DELETE_ON_FAILURE)) {
            var value = options.get(PREF_OPTION_DELETE_ON_FAILURE);
            if (value instanceof String) {
                deleteOnFailure = Boolean.parseBoolean((String) value);
            }
        }

        authenticateUser(context);


        encryptedPreferences = getEncryptedSharedPreferences(deleteOnFailure, options, context.getApplicationContext(), sharedPreferencesName);
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
            if (key.startsWith(preferencesKeyPrefix) && value instanceof String) {
                String originalKey = key.replaceFirst(preferencesKeyPrefix + "_", "");
                result.put(originalKey, (String) value);
            }
        }
        return result;
    }

    private String addPrefixToKey(String key) {
        return preferencesKeyPrefix + "_" + key;
    }

    private SharedPreferences getEncryptedSharedPreferences(boolean deleteOnFailure, Map<String, Object> options, Context context, String sharedPreferencesName) throws GeneralSecurityException, IOException {
        try {
            final SharedPreferences encryptedPreferences = initializeEncryptedSharedPreferencesManager(context, sharedPreferencesName);
            boolean migrated = encryptedPreferences.getBoolean(PREF_KEY_MIGRATED, false);
            if (!migrated) {
                migrateToEncryptedPreferences(context, sharedPreferencesName, encryptedPreferences, deleteOnFailure, options);
            }
            return encryptedPreferences;
        } catch (KeyStoreException f){
            // not authenticated
            Log.w(TAG, "Not authenticated", f);
            throw f;
        } catch (GeneralSecurityException | IOException e) {

            if (!deleteOnFailure) {
                Log.w(TAG, "initialization failed, resetOnError false, so throwing exception.", e);
                throw e;
            }
            Log.w(TAG, "initialization failed, resetting storage", e);

            context.getSharedPreferences(sharedPreferencesName, Context.MODE_PRIVATE).edit().clear().apply();

            try {
                return initializeEncryptedSharedPreferencesManager(context, sharedPreferencesName);
            } catch (Exception f) {
                Log.e(TAG, "initialization after reset failed", f);
                throw f;
            }
        }
    }

    private SharedPreferences initializeEncryptedSharedPreferencesManager(Context context, String sharedPreferencesName) throws GeneralSecurityException, IOException {
        MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyGenParameterSpec(new KeyGenParameterSpec.Builder(
                        MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationRequired(shouldAuthenticate)  // Enforce user authentication
                        .setUserAuthenticationValidityDurationSeconds(-1)  // Require authentication every 60 seconds
                        .setInvalidatedByBiometricEnrollment(true)
                        .setKeySize(256)
                        .build())
                .build();

        return EncryptedSharedPreferences.create(
                context,
                sharedPreferencesName,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    private void migrateToEncryptedPreferences(Context context, String sharedPreferencesName, SharedPreferences target, boolean deleteOnFailure, Map<String, Object> options) {
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
                if (key.startsWith(preferencesKeyPrefix) && value instanceof String) {
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

    private void authenticateUser(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricPrompt promptInfo = null;
            promptInfo = new BiometricPrompt.Builder(context)
                    .setTitle("Authenticate to access")
                    .setSubtitle("Use biometrics or device credentials")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                    .build();

            // 1. Create a CancellationSignal to allow cancelling the authentication if needed
            CancellationSignal cancellationSignal = new CancellationSignal();

            // 2. Create an Executor to run the callback methods on a background thread
            Executor executor = Executors.newSingleThreadExecutor();

            // 3. Define the AuthenticationCallback to handle success and failure
            BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    System.out.println("Authentication Succeeded!");
                    // Perform actions after successful authentication
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    System.out.println("Authentication Failed. Try again.");
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    System.out.println("Authentication Error: " + errString);
                }
            };

            promptInfo.authenticate(cancellationSignal, executor, callback);
        }
    }
}
