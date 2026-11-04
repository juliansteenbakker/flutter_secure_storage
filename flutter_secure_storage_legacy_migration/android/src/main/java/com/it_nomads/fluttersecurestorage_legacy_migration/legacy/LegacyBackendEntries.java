package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.SharedPreferences;

import java.util.Map;

public final class LegacyBackendEntries {
    private LegacyBackendEntries() {}

    public static boolean hasEntries(SharedPreferences data, String prefix) {
        return count(data, prefix) > 0;
    }

    public static int count(SharedPreferences data, String prefix) {
        String keyKeyset = "__androidx_security_crypto_encrypted_prefs_key_keyset__";
        String valueKeyset = "__androidx_security_crypto_encrypted_prefs_value_keyset__";
        Map<String, ?> entries = data.getAll();
        if (!entries.containsKey(keyKeyset) && !entries.containsKey(valueKeyset)) {
            return 0;
        }
        int count = 0;
        for (Map.Entry<String, ?> entry : entries.entrySet()) {
            String key = entry.getKey();
            if (entry.getValue() instanceof String && !key.equals(keyKeyset) && !key.equals(valueKeyset)
                    && !key.startsWith(prefix + "_") && !key.startsWith("FlutterSecureSAlgorithm")) {
                count++;
            }
        }
        return count;
    }
}
