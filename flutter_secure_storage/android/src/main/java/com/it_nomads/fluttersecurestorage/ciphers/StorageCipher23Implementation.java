package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StorageCipher23Implementation implements StorageCipher {
    private static final int keySize = 32;
    private static final int defaultIvSize = 16;
    private static final String KEY_ALGORITHM = "AES";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage1";
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private Key secretKey;


    public StorageCipher23Implementation(Context context, KeyCipher keyCipher, Cipher cipher) throws Exception{
        secureRandom = new SecureRandom();
        this.cipher = getCipher();
        this.secretKey = loadOrGenerateApplicationKey(context, cipher);
    }

    private SecretKey loadOrGenerateApplicationKey(Context context, Cipher cipher) throws Exception {
        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        String keyAppKey = getKeyAppKey();

        String encryptedAppKeyBase64 = preferences.getString(keyAppKey, null);

        if (encryptedAppKeyBase64 != null) {
            try {
                byte[] encryptedAppKey = Base64.decode(encryptedAppKeyBase64, Base64.DEFAULT);
                byte[] appKey = cipher.doFinal(encryptedAppKey);
                return new SecretKeySpec(appKey, "AES");
            } catch (Exception e) {
                Log.e("StorageCipher23Impl", "decrypt key failed", e);
                // Fallback to generating new key
            }
        }

        // Generate new key if not found or decryption failed
        byte[] appKey = generateIV(keySize);
        SecretKey secretKey = new SecretKeySpec(appKey, KEY_ALGORITHM);
        byte[] newEncryptedAppKey = cipher.doFinal(appKey);

        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(keyAppKey, Base64.encodeToString(newEncryptedAppKey, Base64.DEFAULT));
        editor.apply();

        return secretKey;
    }


    protected String getKeyAppKey() {
        return "VGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
    }

    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }


    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        byte[] iv = generateIV(defaultIvSize);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

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

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        return cipher.doFinal(payload);
    }

    public byte[] generateIV(int size) {
        byte[] iv = new byte[size];
        secureRandom.nextBytes(iv);
        return iv;
    }

}
