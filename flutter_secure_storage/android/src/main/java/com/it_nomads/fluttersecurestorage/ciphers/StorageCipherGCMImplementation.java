package com.it_nomads.fluttersecurestorage.ciphers;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import android.content.Context;

import javax.crypto.spec.GCMParameterSpec;

public class StorageCipherGCMImplementation implements StorageCipher {

    private static final int AUTHENTICATION_TAG_SIZE = 128;

    public StorageCipherGCMImplementation(Context context, KeyCipher keyCipher) throws Exception {
        secureRandom = new SecureRandom();
        String aesPreferencesKey = getAESPreferencesKey();

        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        String aesKey = preferences.getString(aesPreferencesKey, null);

        if (aesKey != null) {
            byte[] encrypted;
            try {
                encrypted = Base64.decode(aesKey, Base64.DEFAULT);
                secretKey = keyCipher.unwrap(encrypted, KEY_ALGORITHM);
                return;
            } catch (Exception e) {
                Log.e("StorageCipher18Impl", "unwrap key failed", e);
            }
        }

        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);
        secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        byte[] encryptedKey = keyCipher.wrap(secretKey);
        editor.putString(aesPreferencesKey, Base64.encodeToString(encryptedKey, Base64.DEFAULT));
        editor.apply();
    }

    protected String getAESPreferencesKey() {
        return "flutter_secure_storage_aes_gcm_key";
    }


    protected int getIvSize() {
        return 12;
    }

    protected AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
    }

    private static final int keySize = 16;
    private static final String KEY_ALGORITHM = "AES";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage";
    private final SecureRandom secureRandom;
    private Key secretKey;

    private Cipher getCipherInstance() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        Cipher cipher = getCipherInstance();

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
        Cipher cipher = getCipherInstance();

        byte[] iv = new byte[getIvSize()];
        System.arraycopy(input, 0, iv, 0, iv.length);
        AlgorithmParameterSpec ivParameterSpec = getParameterSpec(iv);

        int payloadSize = input.length - getIvSize();
        byte[] payload = new byte[payloadSize];
        System.arraycopy(input, iv.length, payload, 0, payloadSize);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        try {
            return cipher.doFinal(payload);
        } catch (AEADBadTagException e) {
            Log.w("StorageCipherGCM", "GCM authentication failed");
            throw new SecurityException("Decryption failed: authentication tag mismatch", e);
        }
    }
}