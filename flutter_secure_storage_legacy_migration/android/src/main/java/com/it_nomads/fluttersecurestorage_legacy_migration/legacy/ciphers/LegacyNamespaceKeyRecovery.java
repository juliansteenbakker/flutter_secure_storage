package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Moves the wrapped AES key when an app switches between sharedPreferencesName
 * and storageNamespace with the same name. Only the key lives in a different
 * place; the data prefs file and algorithm markers already line up, so copying
 * the key across is enough. The source copy is left in place so switching back
 * keeps working. Non-biometric only; the wrapped key is unwrapped and rewrapped
 * with the same RSA algorithm it was already using (OAEP, or legacy PKCS1 for
 * installs that never went through the v10.0.0 OAEP migration), tried in that
 * order since OAEP is the common case.
 * <p>
 * Every non-namespaced instance shares the same plain key-storage file, so it can hold more
 * than one instance's wrapped-key entry. Every known preference name is tried, and a candidate
 * is only trusted once it's confirmed to decrypt this instance's own data. The entry is kept
 * under whichever preference name it was already stored under, since v9.2.4 and v10+ each read
 * a different name.
 */
public final class LegacyNamespaceKeyRecovery {

    private static final String TAG = "LegacyNamespaceKeyRecovery";
    private static final String KEY_STORAGE_PREFIX = "FlutterSecureKeyStorage";
    private static final KeyCipherAlgorithm[] RECOVERY_ALGORITHMS = {
            KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
            KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
    };
    private static final String[] WRAPPED_KEY_PREF_NAMES = {
            StorageCipherImplementationGCM.WRAPPED_KEY_PREF,
            StorageCipherImplementationAES18.WRAPPED_KEY_PREF,
            StorageCipherImplementationGCM.LEGACY_V9_KEY,
    };
    // A wrong-algorithm unwrap can silently "succeed" with garbage instead of throwing, so the
    // result is checked against the real key size (both storage ciphers wrap a 16-byte AES key).
    private static final int AES_KEY_SIZE_BYTES = 16;
    // The two storage-cipher formats a recovered key might need to decrypt.
    private static final String GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_SIZE = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final String CBC_TRANSFORMATION = "AES/CBC/PKCS7Padding";
    private static final int CBC_IV_SIZE = 16;

    /** Test seam. */
    interface KeyCipherProvider {
        KeyCipher forConfig(FlutterSecureStorageConfig config) throws Exception;
    }

    private LegacyNamespaceKeyRecovery() {}

    public static boolean recoverIfNeeded(Context context, FlutterSecureStorageConfig config) {
        KeyCipherProvider[] providers = new KeyCipherProvider[RECOVERY_ALGORITHMS.length];
        for (int i = 0; i < RECOVERY_ALGORITHMS.length; i++) {
            KeyCipherAlgorithm algorithm = RECOVERY_ALGORITHMS[i];
            providers[i] = c -> algorithm.keyCipher.apply(context, c);
        }
        return recoverIfNeeded(context, config, providers);
    }

    /**
     * Tries every (preference name, RSA algorithm) combination until one produces a key that
     * actually decrypts this instance's own data.
     */
    static boolean recoverIfNeeded(Context context, FlutterSecureStorageConfig config,
                                   KeyCipherProvider... keyCiphers) {
        String name = config.getEffectiveDataPrefsName();
        SharedPreferences plainKeyPrefs = context.getSharedPreferences(
                KEY_STORAGE_PREFIX, Context.MODE_PRIVATE);
        SharedPreferences namespacedKeyPrefs = context.getSharedPreferences(
                KEY_STORAGE_PREFIX + ":" + name, Context.MODE_PRIVATE);

        final SharedPreferences source;
        final SharedPreferences target;
        final FlutterSecureStorageConfig sourceConfig;
        final FlutterSecureStorageConfig targetConfig;
        if (config.hasStorageNamespace()) {
            // adopt: plain -> namespaced
            source = plainKeyPrefs;
            target = namespacedKeyPrefs;
            sourceConfig = config.withoutStorageNamespace();
            targetConfig = config;
        } else {
            // recover: namespaced -> plain
            source = namespacedKeyPrefs;
            target = plainKeyPrefs;
            sourceConfig = config.withStorageNamespace(name);
            targetConfig = config;
        }

        if (hasWrappedKey(target) || !hasEncryptedData(context, name, config)) {
            return false;
        }

        String keyPrefix = config.getSharedPreferencesKeyPrefix();
        for (String candidateName : WRAPPED_KEY_PREF_NAMES) {
            if (!source.contains(candidateName)) {
                continue;
            }
            for (KeyCipherProvider keyCipher : keyCiphers) {
                if (tryRecover(context, name, source, target, sourceConfig, targetConfig,
                        candidateName, keyPrefix, keyCipher)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean tryRecover(Context context, String name, SharedPreferences source,
                                      SharedPreferences target, FlutterSecureStorageConfig sourceConfig,
                                      FlutterSecureStorageConfig targetConfig, String sourceKeyPrefName,
                                      String keyPrefix, KeyCipherProvider keyCiphers) {
        try {
            byte[] wrapped = Base64.decode(source.getString(sourceKeyPrefName, null), Base64.DEFAULT);
            Key aesKey = keyCiphers.forConfig(sourceConfig)
                    .unwrap(wrapped, StorageCipherImplementationGCM.WRAPPED_KEY_ALGORITHM);
            byte[] encodedAesKey = aesKey.getEncoded();
            if (encodedAesKey == null || encodedAesKey.length != AES_KEY_SIZE_BYTES) {
                throw new Exception("Unwrapped key is not AES-key-shaped ("
                        + (encodedAesKey == null ? "null" : encodedAesKey.length + " bytes")
                        + "); likely the wrong RSA algorithm");
            }
            if (!keyDecryptsOwnData(context, name, keyPrefix, encodedAesKey)) {
                throw new Exception("Unwrapped key does not decrypt this instance's own data; "
                        + "likely a different instance's key under the same preference name");
            }

            byte[] rewrapped = keyCiphers.forConfig(targetConfig).wrap(aesKey);

            target.edit()
                    .putString(sourceKeyPrefName, Base64.encodeToString(rewrapped, Base64.DEFAULT))
                    .apply();

            Log.i(TAG, "Moved wrapped key for namespace '" + name + "'");
            return true;
        } catch (Throwable e) {
            if (e instanceof VirtualMachineError) {
                throw (VirtualMachineError) e;
            }
            Log.w(TAG, "Could not move wrapped key for namespace '" + name + "'", e);
            return false;
        }
    }

    private static boolean hasWrappedKey(SharedPreferences prefs) {
        for (String prefName : WRAPPED_KEY_PREF_NAMES) {
            if (prefs.contains(prefName)) {
                return true;
            }
        }
        return false;
    }

    // Guards against pulling an unrelated instance's key into an empty store.
    private static boolean hasEncryptedData(Context context, String dataPrefsName,
                                            FlutterSecureStorageConfig config) {
        return sampleEncryptedValue(context, dataPrefsName, config.getSharedPreferencesKeyPrefix()) != null;
    }

    /** True if the given raw AES key decrypts a real stored entry of this instance's own data. */
    private static boolean keyDecryptsOwnData(Context context, String dataPrefsName, String keyPrefix,
                                              byte[] rawAesKey) {
        String sample = sampleEncryptedValue(context, dataPrefsName, keyPrefix);
        if (sample == null) {
            return false;
        }
        byte[] ciphertext;
        try {
            ciphertext = Base64.decode(sample, 0);
        } catch (IllegalArgumentException e) {
            return false;
        }
        Key key = new SecretKeySpec(rawAesKey, "AES");
        return canDecrypt(ciphertext, key, GCM_TRANSFORMATION, GCM_IV_SIZE, new GCMParameterSpec(GCM_TAG_BITS, ivOf(ciphertext, GCM_IV_SIZE)))
                || canDecrypt(ciphertext, key, CBC_TRANSFORMATION, CBC_IV_SIZE, new IvParameterSpec(ivOf(ciphertext, CBC_IV_SIZE)));
    }

    private static byte[] ivOf(byte[] input, int ivSize) {
        return input.length >= ivSize ? Arrays.copyOfRange(input, 0, ivSize) : new byte[0];
    }

    private static boolean canDecrypt(byte[] input, Key key, String transformation, int ivSize,
                                      AlgorithmParameterSpec spec) {
        if (input.length <= ivSize) {
            return false;
        }
        try {
            byte[] payload = Arrays.copyOfRange(input, ivSize, input.length);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            cipher.doFinal(payload);
            return true;
        } catch (Throwable e) {
            if (e instanceof VirtualMachineError) {
                throw (VirtualMachineError) e;
            }
            return false;
        }
    }

    private static String sampleEncryptedValue(Context context, String dataPrefsName, String keyPrefix) {
        SharedPreferences dataPrefs = context.getSharedPreferences(dataPrefsName, Context.MODE_PRIVATE);
        for (Map.Entry<String, ?> entry : dataPrefs.getAll().entrySet()) {
            if (entry.getValue() instanceof String && entry.getKey().contains(keyPrefix)) {
                return (String) entry.getValue();
            }
        }
        return null;
    }
}
