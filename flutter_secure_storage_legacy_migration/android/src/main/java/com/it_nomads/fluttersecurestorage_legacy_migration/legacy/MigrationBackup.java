package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.SharedPreferences;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class MigrationBackup {
    public static final String DATA_BACKUP_PREFS_PREFIX = "FlutterSecureStorageLegacyCipherBackup:";
    public static final String STATUS_STARTED = "started";
    public static final String STATUS_COMPLETE = "complete";
    public static final String STATUS_DELETED = "deleted";
    public static final String STATUS_CLEANUP = "cleanup";
    private static final String BACKUP_STATUS_KEY = "FlutterSecureStorageBackupStatus";
    private static final String BACKUP_FORMAT_KEY = "FlutterSecureStorageDataBackupFormat";
    private static final String SEPARATE_FORMAT = "separate";
    private static final String BACKUP_SUFFIX = "_BACKUP";
    private static final String MIGRATED_SUFFIX = "_MIGRATED";

    private MigrationBackup() {}

    private static boolean usesSeparateDataBackup(NamespacedConfigSource source) {
        return SEPARATE_FORMAT.equals(source.getAll().get(BACKUP_FORMAT_KEY));
    }

    private static boolean hasLegacyBackupPhase(NamespacedConfigSource source, String prefix) {
        if (usesSeparateDataBackup(source)) {
            return false;
        }
        Object status = source.getAll().get(BACKUP_STATUS_KEY);
        if (STATUS_DELETED.equals(status)) {
            return false;
        }
        return STATUS_STARTED.equals(status) || STATUS_COMPLETE.equals(status)
                || STATUS_DELETED.equals(status) || STATUS_CLEANUP.equals(status)
                || hasMigratedMarkers(source, prefix);
    }

    public static Map<String, String> getDataBackups(SharedPreferences dataSource,
            NamespacedConfigSource source, String keyPrefix) {
        Map<String, String> backups = new HashMap<>();
        String prefix = keyPrefix + "_";
        if (usesSeparateDataBackup(source)) {
            for (Map.Entry<String, ?> entry : source.getDataBackupPreferences().getAll().entrySet()) {
                if (entry.getKey().startsWith(prefix) && entry.getValue() instanceof String) {
                    backups.put(entry.getKey(), (String) entry.getValue());
                }
            }
            return backups;
        }
        if (!hasLegacyBackupPhase(source, keyPrefix)) {
            return backups;
        }
        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            if (entry.getKey().startsWith(prefix) && entry.getKey().endsWith(BACKUP_SUFFIX)
                    && entry.getValue() instanceof String) {
                String original = entry.getKey().substring(0, entry.getKey().length() - BACKUP_SUFFIX.length());
                backups.put(original, (String) entry.getValue());
            }
        }
        return backups;
    }

    public static boolean isDataBackupEntry(NamespacedConfigSource source, String keyPrefix, String key) {
        return source != null && hasLegacyBackupPhase(source, keyPrefix)
                && key.startsWith(keyPrefix + "_") && key.endsWith(BACKUP_SUFFIX);
    }

    public static boolean hasDataBackupEntries(SharedPreferences dataSource,
            NamespacedConfigSource source, String keyPrefix) {
        return !getDataBackups(dataSource, source, keyPrefix).isEmpty();
    }

    public static boolean hasPendingMigration(SharedPreferences dataSource, SharedPreferences keyStorage,
            NamespacedConfigSource source, FlutterSecureStorageConfig config) {
        String status = getBackupStatus(source, config);
        return STATUS_STARTED.equals(status) || STATUS_COMPLETE.equals(status) || STATUS_DELETED.equals(status)
                || STATUS_CLEANUP.equals(status) || hasMigratedMarkers(source, config.getSharedPreferencesKeyPrefix())
                || hasDataBackupEntries(dataSource, source, config.getSharedPreferencesKeyPrefix());
    }

    public static boolean shouldFinishCleanup(SharedPreferences dataSource,
            NamespacedConfigSource source, FlutterSecureStorageConfig config) {
        return STATUS_CLEANUP.equals(getBackupStatus(source, config))
                || STATUS_DELETED.equals(getBackupStatus(source, config))
                || (hasMigratedMarkers(source, config.getSharedPreferencesKeyPrefix())
                && !hasDataBackupEntries(dataSource, source, config.getSharedPreferencesKeyPrefix()));
    }

    public static void verifyRecoveredEntries(SharedPreferences dataSource, NamespacedConfigSource source,
            String keyPrefix, Map<String, String> recovered) {
        Map<String, String> backups = getDataBackups(dataSource, source, keyPrefix);
        Set<String> expected = new HashSet<>(backups.keySet());
        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            if (entry.getKey().startsWith(keyPrefix + "_") && entry.getValue() instanceof String
                    && !isDataBackupEntry(source, keyPrefix, entry.getKey())) {
                expected.add(entry.getKey());
            }
        }
        if (!backups.keySet().containsAll(expected) || !recovered.keySet().containsAll(expected)) {
            throw new IllegalStateException("Incomplete recovery for secure-storage entries");
        }
    }

    public static void createBackup(SharedPreferences dataSource, SharedPreferences keyStorage,
            NamespacedConfigSource source, FlutterSecureStorageConfig config, String keyPrefix) {
        createBackup(dataSource, keyStorage, null, source, config, keyPrefix);
    }

    public static void createBackup(SharedPreferences dataSource, SharedPreferences keyStorage,
            SharedPreferences espSource, NamespacedConfigSource source,
            FlutterSecureStorageConfig config, String keyPrefix) {
        String status = getBackupStatus(source, config);
        if (STATUS_COMPLETE.equals(status)) {
            return;
        }
        if (STATUS_STARTED.equals(status)) {
            if (!usesSeparateDataBackup(source)) {
                throw new IllegalStateException("Cannot restart an ambiguous legacy backup",
                        new IOException("Original user keys were not recorded by the legacy backup format"));
            }
            deleteBackupData(dataSource, keyStorage, null, source, keyPrefix);
        }
        if (!source.edit().putString(BACKUP_FORMAT_KEY, SEPARATE_FORMAT)
                .putString(BACKUP_STATUS_KEY, STATUS_STARTED).commit()) {
            throw new IllegalStateException("Could not persist backup format and phase");
        }
        SharedPreferences.Editor dataEditor = source.getDataBackupPreferences().edit();
        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            if (entry.getKey().startsWith(keyPrefix + "_") && entry.getValue() instanceof String) {
                dataEditor.putString(entry.getKey(), (String) entry.getValue());
            }
        }
        if (!dataEditor.commit()) {
            throw new IllegalStateException("Could not persist encrypted data backup");
        }
        SharedPreferences.Editor keyEditor = keyStorage.edit();
        for (Map.Entry<String, ?> entry : keyStorage.getAll().entrySet()) {
            if (entry.getValue() instanceof String && !entry.getKey().endsWith(BACKUP_SUFFIX)) {
                keyEditor.putString(entry.getKey() + BACKUP_SUFFIX, (String) entry.getValue());
            }
        }
        if (!keyEditor.commit()) {
            throw new IllegalStateException("Could not persist wrapped-key backup");
        }
        setBackupStatus(source, config, STATUS_COMPLETE);
    }

    public static void deleteBackup(SharedPreferences dataSource, SharedPreferences keyStorage,
            NamespacedConfigSource source, FlutterSecureStorageConfig config, String keyPrefix) {
        deleteBackup(dataSource, keyStorage, null, source, config, keyPrefix);
    }

    public static void deleteBackup(SharedPreferences dataSource, SharedPreferences keyStorage,
            SharedPreferences espSource, NamespacedConfigSource source,
            FlutterSecureStorageConfig config, String keyPrefix) {
        if (STATUS_DELETED.equals(getBackupStatus(source, config))) {
            if (!source.edit().putString(BACKUP_FORMAT_KEY, SEPARATE_FORMAT)
                    .putString(BACKUP_STATUS_KEY, STATUS_CLEANUP).commit()) {
                throw new IllegalStateException("Could not persist completed legacy backup cleanup phase");
            }
        } else {
            setBackupStatus(source, config, STATUS_CLEANUP);
        }
        deleteBackupData(dataSource, keyStorage, espSource, source, keyPrefix);
    }

    private static void deleteBackupData(SharedPreferences dataSource, SharedPreferences keyStorage,
            SharedPreferences espSource, NamespacedConfigSource source, String keyPrefix) {
        if (usesSeparateDataBackup(source)) {
            SharedPreferences.Editor editor = source.getDataBackupPreferences().edit();
            for (String key : getDataBackups(dataSource, source, keyPrefix).keySet()) {
                editor.remove(key);
            }
            if (!editor.commit()) {
                throw new IllegalStateException("Could not persist data backup cleanup");
            }
        } else {
            SharedPreferences.Editor editor = dataSource.edit();
            for (String key : dataSource.getAll().keySet()) {
                if (isDataBackupEntry(source, keyPrefix, key)) { editor.remove(key); }
            }
            if (!editor.commit()) { throw new IllegalStateException("Could not persist legacy backup cleanup"); }
            if (espSource != null) {
                SharedPreferences.Editor espEditor = espSource.edit();
                for (String key : espSource.getAll().keySet()) {
                    if (isDataBackupEntry(source, keyPrefix, key)) { espEditor.remove(key); }
                }
                if (!espEditor.commit()) { throw new IllegalStateException("Could not persist encrypted backup cleanup"); }
            }
        }
        SharedPreferences.Editor keyEditor = keyStorage.edit();
        for (String key : keyStorage.getAll().keySet()) {
            if (key.endsWith(BACKUP_SUFFIX)) { keyEditor.remove(key); }
        }
        if (!keyEditor.commit()) { throw new IllegalStateException("Could not persist wrapped-key cleanup"); }
    }

    public static void setBackupStatus(NamespacedConfigSource source,
            FlutterSecureStorageConfig config, String status) {
        if (!config.shouldMigrateWithBackup()) { return; }
        if (!source.edit().putString(BACKUP_STATUS_KEY, status).commit()) {
            throw new IllegalStateException("Could not persist migration phase");
        }
    }

    public static String getBackupStatus(NamespacedConfigSource source, FlutterSecureStorageConfig config) {
        Object status = source.getAll().get(BACKUP_STATUS_KEY);
        return status instanceof String ? (String) status : null;
    }

    public static boolean hasBackup(NamespacedConfigSource source, FlutterSecureStorageConfig config) {
        return STATUS_COMPLETE.equals(getBackupStatus(source, config));
    }

    public static void deleteOriginalData(SharedPreferences dataSource, SharedPreferences keyStorage,
            String keyPrefix) {
        deleteOriginalData(dataSource, keyStorage, null, keyPrefix);
    }

    public static void deleteOriginalData(SharedPreferences dataSource, SharedPreferences keyStorage,
            NamespacedConfigSource source, String keyPrefix) {
        SharedPreferences.Editor editor = dataSource.edit();
        for (String key : dataSource.getAll().keySet()) {
            if (key.startsWith(keyPrefix + "_") && !isDataBackupEntry(source, keyPrefix, key)
                    && (source == null || !source.contains(key + MIGRATED_SUFFIX))) {
                editor.remove(key);
            }
        }
        if (!editor.commit()) { throw new IllegalStateException("Could not persist data cleanup"); }
    }

    public static boolean hasMigratedMarkers(NamespacedConfigSource source, String keyPrefix) {
        for (String key : source.getAll().keySet()) {
            if (key.startsWith(keyPrefix + "_") && key.endsWith(MIGRATED_SUFFIX)) { return true; }
        }
        return false;
    }

    public static void deleteMigratedMarkers(NamespacedConfigSource source, String keyPrefix) {
        SharedPreferences.Editor editor = source.edit();
        for (String key : source.getAll().keySet()) {
            if (key.startsWith(keyPrefix + "_") && key.endsWith(MIGRATED_SUFFIX)) { editor.remove(key); }
        }
        if (!editor.commit()) { throw new IllegalStateException("Could not persist migration marker cleanup"); }
    }
}
