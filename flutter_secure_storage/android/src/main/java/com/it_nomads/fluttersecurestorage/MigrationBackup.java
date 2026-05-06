package com.it_nomads.fluttersecurestorage;

import android.content.SharedPreferences;
import android.util.Log;

import java.util.Map;

/**
 * Helper class for managing migration backups.
 * Implements a rename-based backup strategy: copy to _BACKUP, mark complete, delete originals.
 */
public class MigrationBackup {
    private MigrationBackup() {}

    private static final String TAG = "MigrationBackup";
    private static final String BACKUP_STATUS_KEY = "FlutterSecureStorageBackupStatus";
    private static final String BACKUP_SUFFIX = "_BACKUP";
    private static final String MIGRATED_SUFFIX = "_MIGRATED";  // stored in configSource, not dataSource

    public static final String STATUS_STARTED = "started";
    public static final String STATUS_COMPLETE = "complete";
    public static final String STATUS_DELETED = "deleted";

    /**
     * Creates backup by copying encrypted entries to <key>_BACKUP, then deleting originals.
     * Follows rename workflow: copy → mark complete → delete originals.
     *
     * @param dataSource SharedPreferences containing encrypted user data
     * @param keyStorage SharedPreferences containing wrapped AES keys
     * @param configSource SharedPreferences for backup status tracking
     * @param config Configuration object
     * @param keyPrefix Prefix to filter data keys
     */
    public static void createBackup(SharedPreferences dataSource,
                                   SharedPreferences keyStorage,
                                   NamespacedConfigSource configSource,
                                   FlutterSecureStorageConfig config,
                                   String keyPrefix) {
        createBackup(dataSource, keyStorage, null, configSource, config, keyPrefix);
    }

    /**
     * Creates backup by copying encrypted entries to <key>_BACKUP, then deleting originals.
     * Follows rename workflow: copy → mark complete → delete originals.
     * Can also backup ESP data if espSource is provided.
     *
     * @param dataSource SharedPreferences containing encrypted user data
     * @param keyStorage SharedPreferences containing wrapped AES keys
     * @param espSource EncryptedSharedPreferences source (can be null)
     * @param configSource SharedPreferences for backup status tracking
     * @param config Configuration object
     * @param keyPrefix Prefix to filter data keys
     */
    public static void createBackup(SharedPreferences dataSource,
                                   SharedPreferences keyStorage,
                                   SharedPreferences espSource,
                                   NamespacedConfigSource configSource,
                                   FlutterSecureStorageConfig config,
                                   String keyPrefix) {
        // Check if backup already exists - skip if complete or deleted
        String status = getBackupStatus(configSource, config);
        if (STATUS_COMPLETE.equals(status) || STATUS_DELETED.equals(status)) {
            Log.d(TAG, "Backup already exists (status: " + status + "), skipping");
            return;
        }

        // If status is "started", delete incomplete backup and start fresh
        if (STATUS_STARTED.equals(status)) {
            Log.w(TAG, "Found incomplete backup (status: started), deleting and restarting");
            deleteBackupData(dataSource, keyStorage, espSource, keyPrefix);
        }

        Log.i(TAG, "Starting backup creation (rename operation)...");

        // Mark backup as started
        setBackupStatus(configSource, config, STATUS_STARTED);

        int dataCount = 0;
        int keyCount = 0;
        int espCount = 0;

        // Step 1a: Copy ESP data to _BACKUP within ESP itself if ESP source provided
        if (espSource != null) {
            Log.i(TAG, "Backing up EncryptedSharedPreferences data with _BACKUP suffix...");
            try {
                SharedPreferences.Editor espEditor = espSource.edit();
                for (Map.Entry<String, ?> entry : espSource.getAll().entrySet()) {
                    String key = entry.getKey();
                    if (entry.getValue() instanceof String && key.contains(keyPrefix) && !key.endsWith(BACKUP_SUFFIX)) {
                        // Copy ESP data: <key> → <key>_BACKUP (within ESP storage)
                        // ESP handles encryption, so the backed-up key remains encrypted
                        espEditor.putString(key + BACKUP_SUFFIX, (String) entry.getValue());
                        espCount++;
                    }
                }
                if (!espEditor.commit()) {
                    throw new RuntimeException("Failed to copy ESP data to backup");
                }
                Log.i(TAG, "Backed up " + espCount + " items in ESP");
            } catch (Exception espError) {
                // ESP is corrupted and can't be read - skip ESP backup
                // The migration will proceed with algorithm mismatch handling
                Log.w(TAG, "ESP backup failed (ESP corrupted): " + espError.getMessage());
                Log.w(TAG, "Skipping ESP backup - migration will use algorithm mismatch recovery");
                espCount = 0;
            }
        }

        // Step 1b: Copy encrypted user data to _BACKUP
        SharedPreferences.Editor dataEditor = dataSource.edit();
        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            String key = entry.getKey();
            if (entry.getValue() instanceof String && key.contains(keyPrefix) && !key.endsWith(BACKUP_SUFFIX)) {
                // Simple string copy: <key> → <key>_BACKUP
                dataEditor.putString(key + BACKUP_SUFFIX, (String) entry.getValue());
                dataCount++;
            }
        }
        if (!dataEditor.commit()) {
            throw new RuntimeException("Failed to copy encrypted data to backup");
        }

        // Step 2: Copy wrapped AES keys to _BACKUP
        SharedPreferences.Editor keyEditor = keyStorage.edit();
        for (Map.Entry<String, ?> entry : keyStorage.getAll().entrySet()) {
            String key = entry.getKey();
            if (entry.getValue() instanceof String && !key.endsWith(BACKUP_SUFFIX)) {
                // Simple string copy: <key> → <key>_BACKUP
                keyEditor.putString(key + BACKUP_SUFFIX, (String) entry.getValue());
                keyCount++;
            }
        }
        if (!keyEditor.commit()) {
            throw new RuntimeException("Failed to copy wrapped keys to backup");
        }

        // Step 3: Mark backup as complete (critical safety point)
        // Originals are kept - they will be deleted in step 7 after successful migration
        setBackupStatus(configSource, config, STATUS_COMPLETE);
        Log.i(TAG, "Backup complete: " + dataCount + " data items, " +
             keyCount + " wrapped keys, " + espCount + " ESP items - originals preserved until migration succeeds");
    }

    /**
     * Deletes all _BACKUP entries from storage.
     * Sets backup status to "deleted" in configSource.
     *
     * @param dataSource SharedPreferences containing user data
     * @param keyStorage SharedPreferences containing wrapped keys
     * @param configSource SharedPreferences for status tracking
     * @param config Configuration object
     * @param keyPrefix Prefix to filter data keys
     */
    public static void deleteBackup(SharedPreferences dataSource,
                                   SharedPreferences keyStorage,
                                   NamespacedConfigSource configSource,
                                   FlutterSecureStorageConfig config,
                                   String keyPrefix) {
        deleteBackup(dataSource, keyStorage, null, configSource, config, keyPrefix);
    }

    /**
     * Deletes all _BACKUP entries from storage, including ESP.
     * Sets backup status to "deleted" in configSource.
     *
     * @param dataSource SharedPreferences containing user data
     * @param keyStorage SharedPreferences containing wrapped keys
     * @param espSource EncryptedSharedPreferences source (can be null)
     * @param configSource SharedPreferences for status tracking
     * @param config Configuration object
     * @param keyPrefix Prefix to filter data keys
     */
    public static void deleteBackup(SharedPreferences dataSource,
                                   SharedPreferences keyStorage,
                                   SharedPreferences espSource,
                                   NamespacedConfigSource configSource,
                                   FlutterSecureStorageConfig config,
                                   String keyPrefix) {
        deleteBackupData(dataSource, keyStorage, espSource, keyPrefix);

        // Remove backup status key entirely — migration is complete, no trace needed
        configSource.edit().remove(BACKUP_STATUS_KEY).commit();

        Log.d(TAG, "Backup deleted and status key removed");
    }

    /**
     * Sets backup status in configSource.
     * Only writes if config.shouldMigrateWithBackup() is true.
     *
     * @param configSource SharedPreferences for status tracking
     * @param config Configuration object
     * @param status Status string (started/complete/deleted)
     */
    public static void setBackupStatus(NamespacedConfigSource configSource,
                                      FlutterSecureStorageConfig config,
                                      String status) {
        if (!config.shouldMigrateWithBackup()) {
            return;  // Don't write backup status if backup disabled
        }

        configSource.edit()
            .putString(BACKUP_STATUS_KEY, status)
            .commit();
    }

    /**
     * Gets backup status from configSource.
     *
     * @param configSource SharedPreferences for status tracking
     * @param config Configuration object
     * @return Status string or null if not present
     */
    public static String getBackupStatus(NamespacedConfigSource configSource,
                                        FlutterSecureStorageConfig config) {
        return configSource.getString(BACKUP_STATUS_KEY, null);
    }

    /**
     * Checks if backup exists (status is "complete").
     *
     * @param configSource SharedPreferences for status tracking
     * @param config Configuration object
     * @return true if backup status is "complete"
     */
    public static boolean hasBackup(NamespacedConfigSource configSource,
                                   FlutterSecureStorageConfig config) {
        String status = getBackupStatus(configSource, config);
        return STATUS_COMPLETE.equals(status);
    }

    /**
     * Deletes _BACKUP entries from storage, including ESP (without updating status).
     * Internal helper method.
     */
    private static void deleteBackupData(SharedPreferences dataSource,
                                        SharedPreferences keyStorage,
                                        SharedPreferences espSource,
                                        String keyPrefix) {
        int dataCount = 0;
        int keyCount = 0;
        int espCount = 0;

        // Delete _BACKUP keys from ESP if provided
        if (espSource != null) {
            SharedPreferences.Editor espEditor = espSource.edit();
            for (Map.Entry<String, ?> entry : espSource.getAll().entrySet()) {
                String key = entry.getKey();
                if (key.endsWith(BACKUP_SUFFIX) && key.contains(keyPrefix)) {
                    espEditor.remove(key);
                    espCount++;
                }
            }
            espEditor.commit();
        }

        // Delete _BACKUP keys from dataSource
        SharedPreferences.Editor dataEditor = dataSource.edit();
        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            String key = entry.getKey();
            if (key.endsWith(BACKUP_SUFFIX) && key.contains(keyPrefix)) {
                dataEditor.remove(key);
                dataCount++;
            }
        }
        dataEditor.commit();

        // Delete _BACKUP keys from keyStorage
        SharedPreferences.Editor keyEditor = keyStorage.edit();
        for (Map.Entry<String, ?> entry : keyStorage.getAll().entrySet()) {
            String key = entry.getKey();
            if (key.endsWith(BACKUP_SUFFIX)) {
                keyEditor.remove(key);
                keyCount++;
            }
        }
        keyEditor.commit();

        if (dataCount > 0 || keyCount > 0 || espCount > 0) {
            Log.d(TAG, "Deleted " + dataCount + " data _BACKUP entries, " + keyCount + " key _BACKUP entries, " + espCount + " ESP _BACKUP entries");
        }
    }

    /**
     * Deletes original (non-_BACKUP) entries from dataSource and keyStorage.
     * Called after successful decryption from _BACKUP keys, before re-encryption.
     * RSA KeyStore keys are NOT deleted here - they are deleted at step 7.
     *
     * @param dataSource SharedPreferences containing user data
     * @param keyStorage SharedPreferences containing wrapped AES keys
     * @param keyPrefix Prefix to filter data keys
     */
    public static void deleteOriginalData(SharedPreferences dataSource,
                                          SharedPreferences keyStorage,
                                          String keyPrefix) {
        deleteOriginalData(dataSource, keyStorage, null, keyPrefix);
    }

    /**
     * Deletes original (non-_BACKUP) entries from dataSource and keyStorage,
     * preserving any data key that already has a <key>_MIGRATED marker in configSource.
     * A _MIGRATED marker means that key was already successfully re-encrypted with the
     * new cipher on a previous (crashed) run — deleting it would cause data loss on retry.
     *
     * @param dataSource SharedPreferences containing user data
     * @param keyStorage SharedPreferences containing wrapped AES keys
     * @param configSource SharedPreferences for migration tracking (may be null to skip check)
     * @param keyPrefix Prefix to filter data keys
     */
    public static void deleteOriginalData(SharedPreferences dataSource,
                                          SharedPreferences keyStorage,
                                          NamespacedConfigSource configSource,
                                          String keyPrefix) {
        int dataCount = 0;
        int preservedCount = 0;
        int keyCount = 0;

        // Delete original keys from dataSource, except those already _MIGRATED
        SharedPreferences.Editor dataEditor = dataSource.edit();
        for (Map.Entry<String, ?> entry : dataSource.getAll().entrySet()) {
            String key = entry.getKey();
            if (!key.endsWith(BACKUP_SUFFIX) && key.contains(keyPrefix)) {
                if (configSource != null && configSource.contains(key + MIGRATED_SUFFIX)) {
                    // This key was already re-encrypted on a prior (crashed) run — preserve it
                    Log.d(TAG, "Preserving already-migrated key in dataSource: " + key);
                    preservedCount++;
                    continue;
                }
                dataEditor.remove(key);
                dataCount++;
            }
        }
        dataEditor.commit();

        // Delete original keys from keyStorage — but only if no _MIGRATED markers exist.
        // If _MIGRATED markers exist, step 5 already ran in a prior crashed run and wrote the new
        // wrapped AES key to keyStorage. Deleting it now would cause BAD_DECRYPT because step 5
        // will skip those keys (they're already migrated) and never rewrite the key.
        if (configSource == null || !hasMigratedMarkers(configSource, keyPrefix)) {
            // No already-migrated keys — safe to delete keyStorage originals
            SharedPreferences.Editor keyEditor = keyStorage.edit();
            for (Map.Entry<String, ?> entry : keyStorage.getAll().entrySet()) {
                String key = entry.getKey();
                if (!key.endsWith(BACKUP_SUFFIX)) {
                    keyEditor.remove(key);
                    keyCount++;
                }
            }
            keyEditor.commit();
        } else {
            // _MIGRATED markers exist — step 5 already ran in a prior crashed run and wrote the
            // new wrapped AES key to keyStorage. Must be preserved.
            Log.d(TAG, "Preserving keyStorage originals (new wrapped AES key) — already-migrated keys exist");
        }

        Log.d(TAG, "Deleted " + dataCount + " original data entries (preserved " + preservedCount + " already-migrated), " + keyCount + " original key entries");
    }

    /**
     * Returns true if any _MIGRATED markers exist in configSource for the given keyPrefix.
     * Used to detect whether step 5 has run (at least partially) in a prior crashed run.
     * If true, step 2 must NOT restore _BACKUP key blobs — the new wrapped AES key is already
     * in keyStorage (written when getCurrentStorageCipher was initialized at step 4/5) and must
     * not be overwritten with the old _BACKUP version.
     *
     * @param configSource SharedPreferences used for migration status tracking
     * @param keyPrefix Prefix to filter marker keys
     * @return true if at least one _MIGRATED marker exists
     */
    public static boolean hasMigratedMarkers(NamespacedConfigSource configSource, String keyPrefix) {
        for (Map.Entry<String, ?> entry : configSource.getAll().entrySet()) {
            String key = entry.getKey();
            if (key.endsWith(MIGRATED_SUFFIX) && key.contains(keyPrefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Deletes all _MIGRATED marker entries from configSource.
     * Markers are stored in configSource (not dataSource) to keep them isolated from real user data.
     * Called during step 7 cleanup after all keys have been successfully re-encrypted.
     *
     * @param configSource SharedPreferences used for migration status tracking
     * @param keyPrefix Prefix to filter marker keys (matches the prefix used when writing markers)
     */
    public static void deleteMigratedMarkers(NamespacedConfigSource configSource, String keyPrefix) {
        SharedPreferences.Editor editor = configSource.edit();
        int count = 0;
        for (Map.Entry<String, ?> entry : configSource.getAll().entrySet()) {
            String key = entry.getKey();
            if (key.endsWith(MIGRATED_SUFFIX) && key.contains(keyPrefix)) {
                editor.remove(key);
                count++;
            }
        }
        editor.commit();
        if (count > 0) {
            Log.d(TAG, "Deleted " + count + " _MIGRATED marker entries from configSource");
        }
    }

}
