package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;;
import javax.crypto.spec.GCMParameterSpec;

class AESCipher23Implementation implements KeyCipher {

    private static final String KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage1";
    private static final String KEYSTORE_IV_NAME = "KeyStoreIV1";
    private static final int IV_SIZE = 16;
    private static final int KEY_SIZE = 256;
    protected final String keyAlias;

    public AESCipher23Implementation(Context context) throws Exception {
        keyAlias = createKeyAlias(context);
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key privateKey = ks.getKey(keyAlias, null);
        if (privateKey == null) {
            generateSymmetricKey();
        }
    }

    @Override
    public byte[] wrap(Key key) throws Exception {
        return null;
    }

    @Override
    public Key unwrap(byte[] wrappedKey, String algorithm) throws Exception {
        return null;
    }

    protected String createKeyAlias(Context context) {
        return context.getPackageName() + ".FlutterSecureStoragePluginKey";
    }

    @Override
    public Cipher getCipher(Context context) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key key = ks.getKey(keyAlias, null);
        if (key == null) {
            generateSymmetricKey();  // Generate if it doesn't exist
            key = ks.getKey(keyAlias, null);
            return getEncryptionCipher(context, key); // `context` needs to be stored in the class
        }

        return getEncryptionCipher(context, key); // `context` needs to be stored in the class
    }

    public Cipher getEncryptionCipher(Context context, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        String ivBase64 = preferences.getString(KEYSTORE_IV_NAME, null);

        if (ivBase64 != null) {
            byte[] iv =  Base64.decode(ivBase64, Base64.DEFAULT);

            GCMParameterSpec spec = new GCMParameterSpec(IV_SIZE * Byte.SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] iv = cipher.getIV();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putString(KEYSTORE_IV_NAME,  Base64.encodeToString(iv, Base64.DEFAULT));
            editor.apply();
        }

        return cipher;
    }

    public void generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER_ANDROID);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
                    .setIsStrongBoxBacked(true);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true);
        }

        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }

}
