package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import static android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG;
import static android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

class KeyCipherImplementationAES23 implements KeyCipher {

    private static final String TAG = "AESCipher23";
    private static final String KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore";
    private static final String SHARED_PREFERENCES_KEY = "KeyStoreIV1";
    private static final int IV_SIZE = 16;
    private static final int KEY_SIZE = 256;
    protected final String keyAlias;

    protected final Context context;
    protected final FlutterSecureStorageConfig config;

    public KeyCipherImplementationAES23(Context context, FlutterSecureStorageConfig config) throws Exception {
        this.context = context;
        this.config = config;
        keyAlias = createKeyAlias(context);
        ensureSymmetricKeyAtAlias();
    }

    private void ensureSymmetricKeyAtAlias() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key existingKey = ks.getKey(keyAlias, null);
        if (existingKey == null) {
            generateSymmetricKey();
        } else if (!(existingKey instanceof SecretKey)) {
            LegacyRsaAliasRetirement.verify(context, config);
            ks.deleteEntry(keyAlias);
            generateSymmetricKey();
        }
    }

    @Override
    public byte[] wrap(Key key) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("AES symmetric keys in AndroidKeyStore cannot wrap other keys");
    }

    @Override
    public Key unwrap(byte[] wrappedKey, String algorithm) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("AES symmetric keys in AndroidKeyStore cannot unwrap other keys");
    }

    protected String createKeyAlias(Context context) {
        return context.getPackageName() + ".FlutterSecureStoragePluginKey" + config.getKeyAliasSuffix();
    }

    @Override
    public void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        ks.deleteEntry(keyAlias);

        SharedPreferences preferences = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        preferences.edit().remove(SHARED_PREFERENCES_KEY).apply();
    }

    @Override
    public Cipher getCipher(Context context) throws Exception {
        ensureSymmetricKeyAtAlias();
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key key = ks.getKey(keyAlias, null);
        return getEncryptionCipher(context, key);
    }

    public Cipher getEncryptionCipher(Context context, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SharedPreferences preferences = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        String ivBase64 = preferences.getString(SHARED_PREFERENCES_KEY, null);

        if (ivBase64 != null && StorageCipherImplementationAES23.hasApplicationKey(preferences)) {
            byte[] iv = Base64.decode(ivBase64, Base64.DEFAULT);
            GCMParameterSpec spec = new GCMParameterSpec(IV_SIZE * Byte.SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
        } else {
            // IV missing, or IV exists but app key doesn't (stale from a failed/cancelled auth).
            // Start fresh with a new ENCRYPT cipher.
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] iv = cipher.getIV();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putString(SHARED_PREFERENCES_KEY, Base64.encodeToString(iv, Base64.DEFAULT));
            editor.apply();
        }

        return cipher;
    }

    /**
     * Checks if StrongBox is available on the device.
     * StrongBox is a hardware security module that provides additional protection for cryptographic keys.
     */
    protected boolean isStrongBoxAvailable() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false;
        }
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    /**
     * Checks if device has PIN/biometric security enabled.
     * This is used to determine if we should require user authentication for the key.
     */
    protected boolean isDeviceSecure() {
        android.app.KeyguardManager keyguardManager =
            (android.app.KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return keyguardManager != null && keyguardManager.isDeviceSecure();
    }

    public void generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER_ANDROID);

        // Check if device has security (PIN/biometric) configured
        boolean deviceHasSecurity = isDeviceSecure();
        boolean enforceBiometrics = config.getEnforceBiometrics();

        // ENFORCEMENT MODE: Fail if enforcement enabled but no device security
        if (enforceBiometrics && !deviceHasSecurity) {
            throw new Exception("BIOMETRIC_UNAVAILABLE: Biometric enforcement enabled but device has no PIN, pattern, password, or biometric enrolled. Cannot generate secure key.");
        }

        // GRACEFUL DEGRADATION MODE: Log warning if no device security
        if (!deviceHasSecurity) {
            Log.w(TAG, "Device has no PIN/biometric security. Generating key without user authentication requirement (enforceBiometrics=false).");
        }

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE);

        // Set authentication requirement based on device security
        if (deviceHasSecurity) {
            builder.setUserAuthenticationRequired(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                int authTypes = config.isStrongBiometricOnly()
                        ? AUTH_BIOMETRIC_STRONG
                        : AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG;
                builder.setUserAuthenticationParameters(0, authTypes);
            } else {
                configureLegacyAuth(builder);
            }

            builder.setInvalidatedByBiometricEnrollment(true);
        } else {
            // Explicitly set to false for clarity (default behavior)
            builder.setUserAuthenticationRequired(false);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true);

            // Only enable StrongBox if it's available
            if (isStrongBoxAvailable()) {
                builder.setIsStrongBoxBacked(true);
                Log.d(TAG, "StrongBox is available and enabled for biometric key");
            } else {
                Log.w(TAG, "StrongBox requested but not available on this device. Using standard TEE.");
            }
        }

        try {
            keyGenerator.init(builder.build());
            keyGenerator.generateKey();
        } catch (Exception e) {
            // If key generation fails with StrongBox, retry without it
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()) {
                Log.w(TAG, " Key generation failed with StrongBox. Retrying without StrongBox.", e);

                builder = new KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(KEY_SIZE)
                        .setUnlockedDeviceRequired(true);

                // Only require user authentication if device has security configured
                if (deviceHasSecurity) {
                    builder.setUserAuthenticationRequired(true);

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        int authTypes = config.isStrongBiometricOnly()
                                ? AUTH_BIOMETRIC_STRONG
                                : AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG;
                        builder.setUserAuthenticationParameters(0, authTypes);
                    } else {
                        configureLegacyAuth(builder);
                    }

                    builder.setInvalidatedByBiometricEnrollment(true);
                }

                keyGenerator.init(builder.build());
                keyGenerator.generateKey();
                Log.d(TAG, "Key generation succeeded without StrongBox");
            } else {
                throw e;
            }
        }
    }

    /**
     * Separate function due to build procedure still marking this as deprecated.
     */
    @SuppressWarnings({"deprecation", "RedundantSuppression"})
    private void configureLegacyAuth(KeyGenParameterSpec.Builder builder) {
        builder.setUserAuthenticationValidityDurationSeconds(-1);
    }


}
