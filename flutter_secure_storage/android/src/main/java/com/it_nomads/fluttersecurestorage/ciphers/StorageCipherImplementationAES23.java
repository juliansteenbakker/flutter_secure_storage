package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StorageCipherImplementationAES23 implements StorageCipher {
    private static final int keySize = 32;
    private static final int defaultIvSize = 12;
    private static final int AUTHENTICATION_TAG_SIZE = 128;
    private static final String KEY_ALGORITHM = "AES";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage";
    private static final String KEYSTORE_IV_NAME = "BVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private final Key secretKey;

    public StorageCipherImplementationAES23(Context context, KeyCipher ignoredKeyCipher, Cipher cipher) throws Exception{
        secureRandom = new SecureRandom();
        this.secretKey = loadOrGenerateApplicationKey(context, cipher);
        this.cipher = getCipher();
    }

    private SecretKey loadOrGenerateApplicationKey(Context context, Cipher biometricCipher) throws Exception {
        final Cipher cipher = (biometricCipher != null) ? biometricCipher : getCipher();
        assert (cipher != null);
        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        String encryptedAppKeyBase64 = preferences.getString(KEYSTORE_IV_NAME, null);

        if (encryptedAppKeyBase64 != null) {
            // Decrypt existing key - may throw BadPaddingException, IllegalBlockSizeException if algorithm changed
            byte[] encryptedAppKey = Base64.decode(encryptedAppKeyBase64, Base64.DEFAULT);
            byte[] appKey = cipher.doFinal(encryptedAppKey);
            return new SecretKeySpec(appKey, KEY_ALGORITHM);
        }

        // No stored key - generate new one (first initialization)
        byte[] appKey = generateIV(keySize);
        SecretKey secretKey = new SecretKeySpec(appKey, KEY_ALGORITHM);
        byte[] newEncryptedAppKey = cipher.doFinal(appKey);

        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(KEYSTORE_IV_NAME, Base64.encodeToString(newEncryptedAppKey, Base64.DEFAULT));
        editor.apply();

        return secretKey;
    }

    @Override
    public void deleteKey(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        preferences.edit().remove(KEYSTORE_IV_NAME).apply();
    }

    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        byte[] iv = generateIV(defaultIvSize);

        GCMParameterSpec spec = new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] payload = cipher.doFinal(input);

        byte[] combined = new byte[iv.length + payload.length];

        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(payload, 0, combined, iv.length, payload.length);

        return combined;
    }

    @Override
    public byte[] decrypt(byte[] input) throws Exception {
        byte[] iv = new byte[defaultIvSize];
        System.arraycopy(input, 0, iv, 0, iv.length);
        int payloadSize = input.length - defaultIvSize;
        byte[] payload = new byte[payloadSize];
        System.arraycopy(input, iv.length, payload, 0, payloadSize);

        GCMParameterSpec spec = new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return cipher.doFinal(payload);
    }

    public byte[] generateIV(int size) {
        byte[] iv = new byte[size];
        secureRandom.nextBytes(iv);
        return iv;
    }

}
