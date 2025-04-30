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

import com.it_nomads.fluttersecurestorage.ciphers.BiometricCallback;
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
    private String SHARED_PREFERENCES_NAME = "FlutterSecureStorage1";

    @NonNull
    private FlutterSecureStorageConfig config;
    @NonNull
    private final Context context;

    protected String ELEMENT_PREFERENCES_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    protected Map<String, Object> options;

    private SharedPreferences preferences;
    private StorageCipher storageCipher;
    private StorageCipherFactory storageCipherFactory;

    public FlutterSecureStorage(Context context, Map<String, Object> options) {
        this.options = options;
        this.context = context.getApplicationContext();
        this.config = new FlutterSecureStorageConfig(options);
    }

    public String addPrefixToKey(String key) {
        return ELEMENT_PREFERENCES_KEY_PREFIX + "_" + key;
    }

    public boolean containsKey(String key) {
        return preferences.contains(key);
    }

    public String read(String key) throws Exception {
        String rawValue = preferences.getString(key, null);
        if (config.isUseEncryptedSharedPreferences()) {
            return rawValue;
        }
        return decodeRawValue(rawValue);
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> readAll() throws Exception {
        Map<String, String> raw = (Map<String, String>) preferences.getAll();

        Map<String, String> all = new HashMap<>();
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String keyWithPrefix = entry.getKey();
            if (keyWithPrefix.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                String key = entry.getKey().replaceFirst(ELEMENT_PREFERENCES_KEY_PREFIX + '_', "");
                if (config.isUseEncryptedSharedPreferences()) {
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
        SharedPreferences.Editor editor = preferences.edit();

        if (config.isUseEncryptedSharedPreferences()) {
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
        final SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        if (!config.isUseEncryptedSharedPreferences()) {
            storageCipherFactory.storeCurrentAlgorithms(editor);
        }
        editor.apply();
    }

    protected void ensureOptions(){

        this.config = new FlutterSecureStorageConfig(options);
        if (options.containsKey("sharedPreferencesName") && !((String) options.get("sharedPreferencesName")).isEmpty()) {
            SHARED_PREFERENCES_NAME = (String) options.get("sharedPreferencesName");
        }

        if (options.containsKey("preferencesKeyPrefix") && !((String) options.get("preferencesKeyPrefix")).isEmpty()) {
            ELEMENT_PREFERENCES_KEY_PREFIX = (String) options.get("preferencesKeyPrefix");
        }
    }

    protected void ensureInitializedAsync(SecurePreferencesCallback<Void> callback) {
        if (preferences != null) {
            callback.onSuccess(null);
            return;
        }

        ensureOptions();

        SharedPreferences nonEncryptedPreferences = context.getSharedPreferences(
                SHARED_PREFERENCES_NAME,
                Context.MODE_PRIVATE
        );

        initStorageCipherAsync(nonEncryptedPreferences, new SecurePreferencesCallback<>() {
            @Override
            public void onSuccess(Void unused) {
                if (config.isUseEncryptedSharedPreferences()) {
                    try {
                        preferences = initializeEncryptedSharedPreferencesManager(context);
                        checkAndMigrateToEncrypted(nonEncryptedPreferences, preferences);
                    } catch (Exception e) {
                        Log.e(TAG, "EncryptedSharedPreferences init failed", e);
                        preferences = nonEncryptedPreferences;
                    }
                } else {
                    preferences = nonEncryptedPreferences;
                }
                callback.onSuccess(null);
            }

            @Override
            public void onError(Exception e) {
                callback.onError(e);
            }
        });
    }

    private void initStorageCipherAsync(SharedPreferences source, SecurePreferencesCallback<Void> callback) {
        storageCipherFactory = new StorageCipherFactory(source, options);

        if (!config.shouldUseBiometrics()) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    storageCipher = storageCipherFactory.getCurrentStorageCipher(context, null);
                }
                callback.onSuccess(null);
            } catch (Exception e) {
                callback.onError(e);
            }
        }

        BiometricCallback biometricCallback = result -> {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    storageCipher = storageCipherFactory.getCurrentStorageCipher(context, result.getCryptoObject().getCipher());
                }
                callback.onSuccess(null);
            } catch (Exception e) {
                callback.onError(e);
            }
        };

        try {
            authenticateIfNeeded(biometricCallback);
        } catch (Exception e) {
            callback.onError(e);
        }
    }

    private void authenticateIfNeeded(BiometricCallback biometricCallback) throws Exception {
        if (true) {
            authenticateUser(biometricCallback);
        } else {
            biometricCallback.onAuthenticationSuccessful(null);
        }
    }

    private void authenticateUser(BiometricCallback biometricCallback) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            biometricCallback.onAuthenticationSuccessful(null);  // Proceed without authentication on unsupported devices
            return;
        }

        Cipher cipher = storageCipherFactory.getCurrentKeyCipher(context).getCipher(context);
        if (cipher == null) return;
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
                Log.d(TAG, "Authentication Succeeded!");
                biometricCallback.onAuthenticationSuccessful(result);
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

        promptInfo.authenticate(crypto, cancellationSignal, executor, callback);

    }

    private void reEncryptPreferences(StorageCipherFactory storageCipherFactory, SharedPreferences source) throws Exception {
        try {
            storageCipher = storageCipherFactory.getSavedStorageCipher(context, null);
            final Map<String, String> cache = new HashMap<>();
            for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
                Object v = entry.getValue();
                String key = entry.getKey();
                if (v instanceof String && key.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                    final String decodedValue = decodeRawValue((String) v);
                    cache.put(key, decodedValue);
                }
            }
            storageCipher = storageCipherFactory.getCurrentStorageCipher(context, null);
            final SharedPreferences.Editor editor = source.edit();
            for (Map.Entry<String, String> entry : cache.entrySet()) {
                byte[] result = storageCipher.encrypt(entry.getValue().getBytes(charset));
                editor.putString(entry.getKey(), Base64.encodeToString(result, 0));
            }
            storageCipherFactory.storeCurrentAlgorithms(editor);
            editor.apply();
        } catch (Exception e) {
            Log.e(TAG, "re-encryption failed", e);
            storageCipher = storageCipherFactory.getSavedStorageCipher(context, null);
        }
    }

    private void checkAndMigrateToEncrypted(SharedPreferences source, SharedPreferences target) {
        try {
            for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
                Object v = entry.getValue();
                String key = entry.getKey();
                if (v instanceof String && key.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                    final String decodedValue = decodeRawValue((String) v);
                    target.edit().putString(key, (decodedValue)).apply();
                    source.edit().remove(key).apply();
                }
            }
            final SharedPreferences.Editor sourceEditor = source.edit();
            storageCipherFactory.removeCurrentAlgorithms(sourceEditor);
            sourceEditor.apply();
        } catch (Exception e) {
            Log.e(TAG, "Data migration failed", e);
        }
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
                SHARED_PREFERENCES_NAME,
                key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    private String decodeRawValue(String value) throws Exception {
        if (value == null) {
            return null;
        }
        byte[] data = Base64.decode(value, 0);
        byte[] result = storageCipher.decrypt(data);

        return new String(result, charset);
    }
}