package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import java.security.Key;
import java.util.Map;

/**
 * Moves the wrapped AES key when an app switches between sharedPreferencesName
 * and storageNamespace with the same name. Only the key lives in a different
 * place; the data prefs file and algorithm markers already line up, so copying
 * the key across is enough. The source copy is left in place so switching back
 * keeps working. Non-biometric RSA-OAEP + AES-GCM only.
 */
public final class LegacyNamespaceKeyRecovery {

    private static final String TAG = "LegacyNamespaceKeyRecovery";
    private static final String KEY_STORAGE_PREFIX = "FlutterSecureKeyStorage";

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
