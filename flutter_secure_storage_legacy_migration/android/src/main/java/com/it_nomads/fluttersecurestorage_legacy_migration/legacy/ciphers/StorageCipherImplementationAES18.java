package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;

import java.security.Key;
import java.util.Map;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StorageCipherImplementationAES18 implements StorageCipher {
    private static final int keySize = 16;
    private static final String KEY_ALGORITHM = "AES";
    private static final String SHARED_PREFERENCES_KEY = "VGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
    // The true v9.2.4 wrapped-key preference name (v10+'s GCM cipher uses its own, differently-prefixed name).
    static final String WRAPPED_KEY_PREF = SHARED_PREFERENCES_KEY;
    private final String keyStoragePrefsName;
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private final Key secretKey;

    public StorageCipherImplementationAES18(Context context, KeyCipher rsaCipher, Cipher ignoredStorageCipher, FlutterSecureStorageConfig config) throws Exception {
        this(context, rsaCipher, null, config, null);
    }

    public StorageCipherImplementationAES18(Context context, KeyCipher rsaCipher, Cipher ignoredCipher,
                                     FlutterSecureStorageConfig config, Map<String, String> wrappedKeys) throws Exception {
        keyStoragePrefsName = config.getEffectiveKeyStoragePrefsName();
        secureRandom = new SecureRandom();

        SharedPreferences preferences = context.getSharedPreferences(keyStoragePrefsName, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        String aesKey = wrappedKeys == null
                ? preferences.getString(SHARED_PREFERENCES_KEY, null) : wrappedKeys.get(SHARED_PREFERENCES_KEY);

        cipher = getCipher();

        if (aesKey != null) {
            // Unwrap existing key - may throw BadPaddingException, InvalidKeyException if algorithm changed
            byte[] encrypted = Base64.decode(aesKey, Base64.DEFAULT);
            secretKey = rsaCipher.unwrap(encrypted, KEY_ALGORITHM);
            if (wrappedKeys == null && !editor.putString(SHARED_PREFERENCES_KEY, aesKey).commit()) {
                throw new IllegalStateException("Could not persist wrapped key");
            }
            return;
        }

        if (wrappedKeys != null) {
            throw new IllegalStateException("Missing saved wrapped key");
        }

        // No stored key - generate new one (first initialization)
        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);
        secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        byte[] encryptedKey = rsaCipher.wrap(secretKey);
        editor.putString(SHARED_PREFERENCES_KEY, Base64.encodeToString(encryptedKey, Base64.DEFAULT));
        if (!editor.commit()) {
            throw new IllegalStateException("Could not persist wrapped key");
        }
    }

    @Override
    public boolean sharesKeyStorageWith(StorageCipher other) {
        return other instanceof StorageCipherImplementationAES18
                && keyStoragePrefsName.equals(((StorageCipherImplementationAES18) other).keyStoragePrefsName);
    }

    @Override
    public void deleteKey(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(keyStoragePrefsName, Context.MODE_PRIVATE);
        preferences.edit().remove(SHARED_PREFERENCES_KEY).apply();
    }

    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS7Padding");
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
        return 16;
    }

    protected AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return new IvParameterSpec(iv);
    }

}
