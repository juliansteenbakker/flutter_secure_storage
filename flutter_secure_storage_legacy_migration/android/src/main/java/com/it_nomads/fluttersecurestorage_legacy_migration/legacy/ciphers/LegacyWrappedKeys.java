package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.MigrationBackup;

import java.util.HashMap;
import java.util.Map;

final class LegacyWrappedKeys {
    private LegacyWrappedKeys() {}

    static Map<String, String> read(Context context, FlutterSecureStorageConfig config,
                                        KeyCipherAlgorithm keyAlgorithm, StorageCipherAlgorithm storageAlgorithm,
                                        SharedPreferences source) {
        SharedPreferences data = context.getSharedPreferences(
                config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        boolean ownsBackup = MigrationBackup.hasDataBackupEntries(data,
                new NamespacedConfigSource(context, config.getEffectiveDataPrefsName()),
                config.getSharedPreferencesKeyPrefix());
        return read(context, config, keyAlgorithm, storageAlgorithm, source, ownsBackup);
    }

    static Map<String, String> preserveLive(Context context, FlutterSecureStorageConfig config,
                                            KeyCipherAlgorithm keyAlgorithm, StorageCipherAlgorithm storageAlgorithm,
                                            SharedPreferences source) {
        Map<String, String> material = read(context, config, keyAlgorithm, storageAlgorithm, source, false);
        persist(context, config, keyAlgorithm, storageAlgorithm, material);
        return material;
    }

    private static Map<String, String> read(Context context, FlutterSecureStorageConfig config,
                                                KeyCipherAlgorithm keyAlgorithm, StorageCipherAlgorithm storageAlgorithm,
                                                SharedPreferences source, boolean preferBackup) {
        SharedPreferences archive = archive(context, config, keyAlgorithm, storageAlgorithm);
        Map<String, String> material = new HashMap<>();
        for (Map.Entry<String, ?> entry : archive.getAll().entrySet()) {
            if (entry.getValue() instanceof String) {
                material.put(entry.getKey(), (String) entry.getValue());
            }
        }
        if (!material.isEmpty()) {
            return material;
        }
        for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
            if (entry.getValue() instanceof String && !entry.getKey().endsWith("_BACKUP")) {
                material.put(entry.getKey(), (String) entry.getValue());
            }
        }
        if (preferBackup) {
            for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
                if (entry.getValue() instanceof String && entry.getKey().endsWith("_BACKUP")) {
                    String original = entry.getKey().substring(0, entry.getKey().length() - "_BACKUP".length());
                    material.put(original, (String) entry.getValue());
                }
            }
        }
        if (material.isEmpty()) {
            throw new IllegalStateException("Missing legacy wrapped-key material");
        }
        return material;
    }

    static void persist(Context context, FlutterSecureStorageConfig config,
                         KeyCipherAlgorithm keyAlgorithm, StorageCipherAlgorithm storageAlgorithm,
                         Map<String, String> material) {
        SharedPreferences.Editor editor = archive(context, config, keyAlgorithm, storageAlgorithm).edit();
        for (Map.Entry<String, String> entry : material.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        if (!editor.commit()) {
            throw new IllegalStateException("Could not preserve legacy wrapped-key material");
        }
    }
    private static SharedPreferences archive(Context context, FlutterSecureStorageConfig config,
                                              KeyCipherAlgorithm keyAlgorithm, StorageCipherAlgorithm storageAlgorithm) {
        return context.getSharedPreferences(
                "FlutterSecureStorageLegacyWrappedKeys:" + config.getEffectiveKeyStoragePrefsName()
                        + ":" + keyAlgorithm.name() + ":" + storageAlgorithm.name(), Context.MODE_PRIVATE);
    }

}
