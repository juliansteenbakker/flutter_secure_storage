package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StorageCipherImplementationGCM implements StorageCipher {
    private static final int keySize = 16;
    private static final int AUTHENTICATION_TAG_SIZE = 128;
    private static final String KEY_ALGORITHM = "AES";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage";
    private static final String SHARED_PREFERENCES_KEY = "AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
    private final String sharedPreferencesName;
    private final String sharedPreferencesKey;
    private final String legacyScopedPreferencesName;
    private final String legacyScopedPreferencesKey;
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private final Key secretKey;

    public StorageCipherImplementationGCM(Context context, KeyCipher rsaCipher, Cipher ignoredCipher) throws Exception {
        secureRandom = new SecureRandom();
        FlutterSecureStorageConfig resolvedConfig = resolveConfig(rsaCipher);
        if (resolvedConfig == null) {
            sharedPreferencesName = SHARED_PREFERENCES_NAME;
            sharedPreferencesKey = SHARED_PREFERENCES_KEY;
            legacyScopedPreferencesName = SHARED_PREFERENCES_NAME;
            legacyScopedPreferencesKey = SHARED_PREFERENCES_KEY;
        } else {
            sharedPreferencesName = resolvedConfig.getKeyStoragePreferencesName();
            sharedPreferencesKey = resolvedConfig.getNamespacedKey(SHARED_PREFERENCES_KEY);
            legacyScopedPreferencesName = SHARED_PREFERENCES_NAME + "_" + resolvedConfig.getStorageNamespace();
            legacyScopedPreferencesKey = SHARED_PREFERENCES_KEY + "_" + resolvedConfig.getStorageNamespace();
        }

        SharedPreferences preferences = context.getSharedPreferences(sharedPreferencesName, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        String aesKey = preferences.getString(sharedPreferencesKey, null);
        if (aesKey == null) {
            SharedPreferences legacyPreferences = context.getSharedPreferences(
                    legacyScopedPreferencesName,
                    Context.MODE_PRIVATE
            );
            String legacyAesKey = legacyPreferences.getString(legacyScopedPreferencesKey, null);
            if (legacyAesKey != null) {
                aesKey = legacyAesKey;
                editor.putString(sharedPreferencesKey, legacyAesKey).apply();
                legacyPreferences.edit().remove(legacyScopedPreferencesKey).apply();
            }
        }
        if (aesKey == null) {
            SharedPreferences legacyPreferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
            String legacyAesKey = legacyPreferences.getString(SHARED_PREFERENCES_KEY, null);
            if (legacyAesKey != null) {
                aesKey = legacyAesKey;
                editor.putString(sharedPreferencesKey, legacyAesKey).apply();
                legacyPreferences.edit().remove(SHARED_PREFERENCES_KEY).apply();
            }
        }

        cipher = getCipher();

        if (aesKey != null) {
            // Unwrap existing key - may throw BadPaddingException, InvalidKeyException if algorithm changed
            byte[] encrypted = Base64.decode(aesKey, Base64.DEFAULT);
            secretKey = rsaCipher.unwrap(encrypted, KEY_ALGORITHM);
            return;
        }

        // No stored key - generate new one (first initialization)
        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);
        secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        byte[] encryptedKey = rsaCipher.wrap(secretKey);
        editor.putString(sharedPreferencesKey, Base64.encodeToString(encryptedKey, Base64.DEFAULT));
        editor.apply();
    }

    @Override
    public void deleteKey(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(sharedPreferencesName, Context.MODE_PRIVATE);
        preferences.edit().remove(sharedPreferencesKey).apply();

        SharedPreferences legacyScopedPreferences = context.getSharedPreferences(
                legacyScopedPreferencesName,
                Context.MODE_PRIVATE
        );
        legacyScopedPreferences.edit().remove(legacyScopedPreferencesKey).apply();
    }

    private FlutterSecureStorageConfig resolveConfig(KeyCipher keyCipher) {
        FlutterSecureStorageConfig resolvedConfig = null;
        if (keyCipher instanceof KeyCipherImplementationRSA18) {
            resolvedConfig = ((KeyCipherImplementationRSA18) keyCipher).config;
        } else if (keyCipher instanceof KeyCipherImplementationAES23) {
            resolvedConfig = ((KeyCipherImplementationAES23) keyCipher).config;
        }
        return resolvedConfig;
    }

    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        byte[] iv = new byte[getIvSize()];
        secureRandom.nextBytes(iv);

        AlgorithmParameterSpec ivParameterSpec = getParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] payload = cipher.doFinal(input);
        byte[] combined = new byte[iv.length + payload.length];

        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(payload, 0, combined, iv.length, payload.length);

        return combined;
    }

    @Override
    public byte[] decrypt(byte[] input) throws Exception {
        byte[] iv = new byte[getIvSize()];
        System.arraycopy(input, 0, iv, 0, iv.length);
        AlgorithmParameterSpec ivParameterSpec = getParameterSpec(iv);

        int payloadSize = input.length - getIvSize();
        byte[] payload = new byte[payloadSize];
        System.arraycopy(input, iv.length, payload, 0, payloadSize);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        return cipher.doFinal(payload);
    }

    protected int getIvSize() {
        return 12;
    }

    protected AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
    }

}
