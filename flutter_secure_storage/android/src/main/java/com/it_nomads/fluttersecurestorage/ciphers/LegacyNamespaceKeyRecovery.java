package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Moves the wrapped AES key when an app switches between sharedPreferencesName
 * and storageNamespace with the same name. Only the key lives in a different
 * place; the data prefs file and algorithm markers already line up, so copying
 * the key across is enough. The source copy is left in place so switching back
 * keeps working. Non-biometric RSA-OAEP + AES-GCM only.
 * <p>
 * Every non-namespaced instance shares the same plain key-storage file, so a
 * sibling's wrapped key could sit under the same preference name. A candidate
 * is only trusted once it's confirmed to decrypt this instance's own data.
 */
public final class LegacyNamespaceKeyRecovery {

    private static final String TAG = "LegacyNamespaceKeyRecovery";
    private static final String KEY_STORAGE_PREFIX = "FlutterSecureKeyStorage";
    // A wrong-key unwrap can silently succeed with garbage instead of throwing, so the result
    // is checked against the real key size (StorageCipherImplementationGCM wraps a 16-byte key).
    private static final int AES_KEY_SIZE_BYTES = 16;
    private static final String GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_SIZE = 12;
    private static final int GCM_TAG_BITS = 128;

    /** Test seam. */
    interface KeyCipherProvider {
        KeyCipher forConfig(FlutterSecureStorageConfig config) throws Exception;
    }

    private LegacyNamespaceKeyRecovery() {}

    public static boolean recoverIfNeeded(Context context, FlutterSecureStorageConfig config) {
        return recoverIfNeeded(context, config,
                c -> KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding.keyCipher.apply(context, c));
    }

    static boolean recoverIfNeeded(Context context, FlutterSecureStorageConfig config,
                                   KeyCipherProvider keyCiphers) {
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

        if (hasWrappedKey(target) || !hasWrappedKey(source) || !hasEncryptedData(context, name, config)) {
            return false;
        }

        try {
            byte[] wrapped = Base64.decode(
                    source.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null),
                    Base64.DEFAULT);
            Key aesKey = keyCiphers.forConfig(sourceConfig)
                    .unwrap(wrapped, StorageCipherImplementationGCM.WRAPPED_KEY_ALGORITHM);
            byte[] encodedAesKey = aesKey.getEncoded();
            if (encodedAesKey == null || encodedAesKey.length != AES_KEY_SIZE_BYTES) {
                throw new Exception("Unwrapped key is not AES-key-shaped ("
                        + (encodedAesKey == null ? "null" : encodedAesKey.length + " bytes")
                        + "); likely belongs to a different instance");
            }
            if (!keyDecryptsOwnData(context, name, config.getSharedPreferencesKeyPrefix(), encodedAesKey)) {
                throw new Exception("Unwrapped key does not decrypt this instance's own data; "
                        + "likely a different instance's key under the same preference name");
            }

            byte[] rewrapped = keyCiphers.forConfig(targetConfig).wrap(aesKey);

            target.edit()
                    .putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF,
                            Base64.encodeToString(rewrapped, Base64.DEFAULT))
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
        return prefs.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null) != null;
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
        if (ciphertext.length <= GCM_IV_SIZE) {
            return false;
        }
        try {
            byte[] iv = Arrays.copyOfRange(ciphertext, 0, GCM_IV_SIZE);
            byte[] payload = Arrays.copyOfRange(ciphertext, GCM_IV_SIZE, ciphertext.length);
            Cipher cipher = Cipher.getInstance(GCM_TRANSFORMATION);
            AlgorithmParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawAesKey, "AES"), spec);
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
