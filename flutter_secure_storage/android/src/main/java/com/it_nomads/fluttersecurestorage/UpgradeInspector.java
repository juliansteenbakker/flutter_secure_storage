package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.security.KeyStore;

import com.it_nomads.fluttersecurestorage.ciphers.KeyCipherAlgorithm;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherAlgorithm;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Reports whether data written by an older plugin version is still readable, so
 * an app can warn its users before the next access discards it. Read-only: it
 * checks that key material exists before building any cipher, since the cipher
 * constructors create keys when they find none.
 */
public final class UpgradeInspector {

    private static final String TAG = "UpgradeInspector";

    // Mirrors SecureStorageUpgradeState on the Dart side.
    static final String STATE_OK = "ok";
    static final String STATE_LEGACY_DATA_UNREADABLE = "legacyDataUnreadable";
    static final String STATE_LEGACY_DATA_DISCARDED = "legacyDataDiscarded";
    static final String STATE_UNKNOWN = "unknown";

    // Mirrors SecureStorageUpgradeReason on the Dart side.
    static final String REASON_NONE = "none";
    static final String REASON_REMOVED_CIPHER = "removedCipher";
    static final String REASON_MISSING_ALGORITHM_MARKERS = "missingAlgorithmMarkers";
    static final String REASON_LEGACY_BACKEND_PRESENT = "legacyBackendPresent";
    static final String REASON_MISSING_KEY_MATERIAL = "missingKeyMaterial";
    static final String REASON_DECRYPT_FAILED = "decryptFailed";
    static final String REASON_AUTHENTICATION_REQUIRED = "authenticationRequired";

    // Keys the Jetpack Security EncryptedSharedPreferences (Tink) backend
    // writes into the data prefs file. v11 removed that backend.
    private static final String TINK_KEY_KEYSET =
            "__androidx_security_crypto_encrypted_prefs_key_keyset__";
    private static final String TINK_VALUE_KEYSET =
            "__androidx_security_crypto_encrypted_prefs_value_keyset__";
    private static final String ALGORITHM_MARKER_PREFIX = "FlutterSecureSAlgorithm";
    // The prefs key StorageCipherImplementationGCM stores the wrapped AES key under.
    private static final String GCM_WRAPPED_KEY = "AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";

    // Records a past wipe. Kept in the config prefs, which the delete paths
    // don't clear, so it outlives the data it describes.
    static final String DISCARDED_MARKER_KEY = "FlutterSecureStorageLegacyDataDiscarded";

    private static final String BACKUP_SUFFIX = "_BACKUP";

    private UpgradeInspector() {}

    /**
     * Inspects stored data and returns a status map for the method channel. A
     * pending "data was discarded" report wins and is cleared as it's read, so
     * an app sees it once.
     */
    public static Map<String, Object> inspect(Context context, FlutterSecureStorageConfig config) {
        NamespacedConfigSource configSource =
                new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());

        String discardedReason = configSource.getString(DISCARDED_MARKER_KEY, null);
        if (discardedReason != null) {
            configSource.edit().remove(DISCARDED_MARKER_KEY).apply();
            return status(STATE_LEGACY_DATA_DISCARDED, discardedReason, 0, false,
                    "Unreadable data was deleted by an earlier storage access.");
        }

        SharedPreferences dataPrefs = context.getSharedPreferences(
                config.getEffectiveDataPrefsName(),
                Context.MODE_PRIVATE
        );

        String keyPrefix = config.getSharedPreferencesKeyPrefix();
        int entryCount = 0;
        String sampleValue = null;
        for (Map.Entry<String, ?> entry : dataPrefs.getAll().entrySet()) {
            String key = entry.getKey();
            if (!(entry.getValue() instanceof String) || !key.contains(keyPrefix) || key.endsWith(BACKUP_SUFFIX)) {
                continue;
            }
            entryCount++;
            if (sampleValue == null) {
                sampleValue = (String) entry.getValue();
            }
        }

        if (entryCount == 0) {
            int tinkEntries = countEncryptedSharedPreferencesEntries(dataPrefs);
            if (tinkEntries > 0) {
                // v11 can't read the Tink store, but it also doesn't delete it,
                // so a downgrade to v10 can still migrate the data.
                return status(STATE_LEGACY_DATA_UNREADABLE, REASON_LEGACY_BACKEND_PRESENT,
                        tinkEntries, false,
                        "Data is in the EncryptedSharedPreferences (Tink) store, whose backend "
                                + "v11 removed. Upgrading to v10 before v11 would have migrated it.");
            }
            return status(STATE_OK, REASON_NONE, 0, false, "No stored data.");
        }

        String savedKeyAlgorithm = StorageCipherFactory.readSavedKeyAlgorithm(configSource);
        String savedStorageAlgorithm = StorageCipherFactory.readSavedStorageAlgorithm(configSource);

        if (savedKeyAlgorithm == null || savedStorageAlgorithm == null) {
            return unreadable(config, REASON_MISSING_ALGORITHM_MARKERS, entryCount,
                    "Data carries no algorithm markers, so it was written by v9 or earlier. "
                            + "Upgrading to v10 before v11 would have migrated it.");
        }

        if (KeyCipherAlgorithm.isRemoved(savedKeyAlgorithm)
                || StorageCipherAlgorithm.isRemoved(savedStorageAlgorithm)) {
            return unreadable(config, REASON_REMOVED_CIPHER, entryCount,
                    "Data was encrypted with " + savedKeyAlgorithm + "/" + savedStorageAlgorithm
                            + ", removed in v11. Upgrading to v10 before v11 would have migrated it.");
        }

        KeyCipherAlgorithm keyAlgorithm;
        try {
            keyAlgorithm = KeyCipherAlgorithm.fromString(savedKeyAlgorithm);
            StorageCipherAlgorithm.fromString(savedStorageAlgorithm);
        } catch (IllegalArgumentException e) {
            return unreadable(config, REASON_REMOVED_CIPHER, entryCount,
                    "Data was encrypted with unrecognised algorithm markers "
                            + savedKeyAlgorithm + "/" + savedStorageAlgorithm + ".");
        }

        if (keyAlgorithm == KeyCipherAlgorithm.AES_GCM_NoPadding) {
            // Decrypting would trigger a biometric prompt, which a preflight must not.
            return status(STATE_UNKNOWN, REASON_AUTHENTICATION_REQUIRED, entryCount, false,
                    "Stored data is behind user authentication, so it was not read.");
        }

        SharedPreferences keyPrefs = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(),
                Context.MODE_PRIVATE
        );

        if (!hasRsaKeyStoreEntry(context, config)
                || keyPrefs.getString(GCM_WRAPPED_KEY, null) == null) {
            return unreadable(config, REASON_MISSING_KEY_MATERIAL, entryCount,
                    "Stored data is orphaned: the key needed to decrypt it is gone.");
        }

        try {
            // Pass the saved algorithms as the current ones so the factory
            // doesn't see an algorithm change and doesn't write anything.
            StorageCipherFactory factory = new StorageCipherFactory(
                    configSource, savedKeyAlgorithm, savedStorageAlgorithm, config);
            StorageCipher cipher = factory.getSavedStorageCipher(context, null);
            cipher.decrypt(Base64.decode(sampleValue, 0));
            return status(STATE_OK, REASON_NONE, entryCount, false, "Stored data is readable.");
        } catch (Throwable e) {
            if (e instanceof VirtualMachineError) {
                throw (VirtualMachineError) e;
            }
            Log.w(TAG, "Trial decryption of stored data failed", e);
            return unreadable(config, REASON_DECRYPT_FAILED, entryCount,
                    "Stored data could not be decrypted: " + e.getMessage());
        }
    }

    // Counts real entries in a Tink data file (not the keysets or our markers).
    // Returns 0 if the file isn't a Tink store.
    private static int countEncryptedSharedPreferencesEntries(SharedPreferences dataPrefs) {
        Map<String, ?> all = dataPrefs.getAll();
        if (!all.containsKey(TINK_KEY_KEYSET) && !all.containsKey(TINK_VALUE_KEYSET)) {
            return 0;
        }
        int count = 0;
        for (Map.Entry<String, ?> entry : all.entrySet()) {
            String key = entry.getKey();
            if (!(entry.getValue() instanceof String)
                    || key.equals(TINK_KEY_KEYSET)
                    || key.equals(TINK_VALUE_KEYSET)
                    || key.startsWith(ALGORITHM_MARKER_PREFIX)
                    || key.equals(DISCARDED_MARKER_KEY)) {
                continue;
            }
            count++;
        }
        return count;
    }

    // Whether the RSA-OAEP key that decrypts non-biometric data is still in
    // the KeyStore. Read-only; never generates one.
    private static boolean hasRsaKeyStoreEntry(Context context, FlutterSecureStorageConfig config) {
        String alias = context.getPackageName()
                + ".FlutterSecureStoragePluginKeyOAEP" + config.getKeyAliasSuffix();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            return ks.containsAlias(alias);
        } catch (Exception e) {
            return false;
        }
    }

    private static Map<String, Object> unreadable(FlutterSecureStorageConfig config,
                                                  String reason, int entryCount, String details) {
        return status(STATE_LEGACY_DATA_UNREADABLE, reason, entryCount,
                config.shouldDeleteOnFailure(), details);
    }

    private static Map<String, Object> status(String state, String reason, int entryCount,
                                              boolean willDiscardOnNextAccess, String details) {
        Map<String, Object> result = new HashMap<>();
        result.put("state", state);
        result.put("reason", reason);
        result.put("entryCount", entryCount);
        result.put("willDiscardOnNextAccess", willDiscardOnNextAccess);
        result.put("details", details);
        return result;
    }
}
