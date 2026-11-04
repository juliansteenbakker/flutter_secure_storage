package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;

import java.util.Map;

import javax.crypto.Cipher;

/**
 * Moves the wrapped app key (the AES key that actually encrypts data, itself
 * wrapped by the biometric/PIN-gated Android Keystore key) when an app
 * switches between sharedPreferencesName and storageNamespace with the same
 * name. Mirrors LegacyNamespaceKeyRecovery, but the wrapping key here lives
 * in the Keystore and requires live user authentication to use, so this
 * class only does guard-checking and the raw unwrap/rewrap; the caller
 * drives the two BiometricPrompt round-trips (one for the old location's
 * key, one for the new one) and passes in each authenticated Cipher.
 */
public final class BiometricNamespaceKeyRecovery {

    private BiometricNamespaceKeyRecovery() {}

    /** True if the app key needs to be moved before the current namespace can read its data. */
    public static boolean isRecoveryNeeded(Context context, FlutterSecureStorageConfig config) {
        String name = config.getEffectiveDataPrefsName();
        SharedPreferences target = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        SharedPreferences source = context.getSharedPreferences(sourceConfig(config).getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        return !hasAppKey(target) && hasAppKey(source) && hasEncryptedData(context, name, config);
    }

    /** The config describing where the app key currently lives (before the namespace switch). */
    public static FlutterSecureStorageConfig sourceConfig(FlutterSecureStorageConfig config) {
        String name = config.getEffectiveDataPrefsName();
        return config.hasStorageNamespace() ? config.withoutStorageNamespace() : config.withStorageNamespace(name);
    }

    /** The KeyCipher for the OLD location's Keystore key; its getCipher() needs authentication. */
    public static KeyCipher sourceKeyCipher(Context context, FlutterSecureStorageConfig config) throws Exception {
        return KeyCipherAlgorithm.AES_GCM_NoPadding.keyCipher.apply(context, sourceConfig(config));
    }

    /** The KeyCipher for the NEW location's Keystore key; its getCipher() needs authentication. */
    public static KeyCipher targetKeyCipher(Context context, FlutterSecureStorageConfig config) throws Exception {
        return KeyCipherAlgorithm.AES_GCM_NoPadding.keyCipher.apply(context, config);
    }

    /** Decrypts the app key stored at the old location using an authenticated DECRYPT-mode cipher. */
    public static byte[] decryptSourceAppKey(Context context, FlutterSecureStorageConfig config,
                                             Cipher authenticatedCipher) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(
                sourceConfig(config).getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        String encoded = prefs.getString(StorageCipherImplementationAES23.APP_KEY_PREF, null);
        if (encoded == null) {
            throw new Exception("No biometric app key found to recover");
        }
        return authenticatedCipher.doFinal(Base64.decode(encoded, Base64.DEFAULT));
    }

    /** Encrypts the app key with an authenticated ENCRYPT-mode cipher and stores it at the new location. */
    public static void storeTargetAppKey(Context context, FlutterSecureStorageConfig config,
                                         Cipher authenticatedCipher, byte[] appKey) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        byte[] encrypted = authenticatedCipher.doFinal(appKey);
        prefs.edit()
                .putString(StorageCipherImplementationAES23.APP_KEY_PREF, Base64.encodeToString(encrypted, Base64.DEFAULT))
                .apply();
    }

    private static boolean hasAppKey(SharedPreferences prefs) {
        return StorageCipherImplementationAES23.hasApplicationKey(prefs);
    }

    // Guards against pulling an unrelated instance's key into an empty store.
    private static boolean hasEncryptedData(Context context, String dataPrefsName,
                                            FlutterSecureStorageConfig config) {
        SharedPreferences dataPrefs = context.getSharedPreferences(dataPrefsName, Context.MODE_PRIVATE);
        String keyPrefix = config.getSharedPreferencesKeyPrefix();
        for (Map.Entry<String, ?> entry : dataPrefs.getAll().entrySet()) {
            if (entry.getValue() instanceof String && entry.getKey().contains(keyPrefix)) {
                return true;
            }
        }
        return false;
    }
}
