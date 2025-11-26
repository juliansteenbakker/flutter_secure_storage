package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

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
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private final Key secretKey;

    public StorageCipherImplementationGCM(Context context, KeyCipher rsaCipher, Cipher ignoredCipher) throws Exception {
        secureRandom = new SecureRandom();

        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        String aesKey = preferences.getString(SHARED_PREFERENCES_KEY, null);

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
        editor.putString(SHARED_PREFERENCES_KEY, Base64.encodeToString(encryptedKey, Base64.DEFAULT));
        editor.apply();
    }

    @Override
    public void deleteKey(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        preferences.edit().remove(SHARED_PREFERENCES_KEY).apply();
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
