package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MigrationBackupTest {

    private static final String KEY_PREFIX = "TestPrefix";
    private static final String BACKUP_STATUS_KEY = "FlutterSecureStorageBackupStatus";

    private SharedPreferences dataSource;
    private SharedPreferences keyStorage;
    private SharedPreferences configSource;
    private FlutterSecureStorageConfig config;
    private FlutterSecureStorageConfig configWithBackup;

    @Before
    public void setUp() {
        Context context = RuntimeEnvironment.getApplication();
        dataSource   = context.getSharedPreferences("TestData",   Context.MODE_PRIVATE);
        keyStorage   = context.getSharedPreferences("TestKeys",   Context.MODE_PRIVATE);
        configSource = context.getSharedPreferences("TestConfig", Context.MODE_PRIVATE);

        dataSource.edit().clear().commit();
        keyStorage.edit().clear().commit();
        configSource.edit().clear().commit();

        config = new FlutterSecureStorageConfig(new HashMap<>());

        HashMap<String, Object> backupOptions = new HashMap<>();
        backupOptions.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_WITH_BACKUP, "true");
        configWithBackup = new FlutterSecureStorageConfig(backupOptions);
    }

    // -------------------------------------------------------------------------
    // setBackupStatus / getBackupStatus
    // -------------------------------------------------------------------------

    @Test
    public void setBackupStatus_writesStatus_whenMigrateWithBackupEnabled() {
        MigrationBackup.setBackupStatus(configSource, configWithBackup, MigrationBackup.STATUS_COMPLETE);

        assertEquals(MigrationBackup.STATUS_COMPLETE, configSource.getString(BACKUP_STATUS_KEY, null));
    }

    @Test
    public void setBackupStatus_doesNotWrite_whenMigrateWithBackupDisabled() {
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_COMPLETE);

        assertNull(configSource.getString(BACKUP_STATUS_KEY, null));
    }

    @Test
    public void getBackupStatus_returnsNull_whenNotSet() {
        assertNull(MigrationBackup.getBackupStatus(configSource, configWithBackup));
    }

    @Test
    public void getBackupStatus_returnsStoredStatus() {
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_STARTED).commit();

        assertEquals(MigrationBackup.STATUS_STARTED, MigrationBackup.getBackupStatus(configSource, configWithBackup));
    }

    // -------------------------------------------------------------------------
    // hasBackup
    // -------------------------------------------------------------------------

    @Test
    public void hasBackup_returnsFalse_whenNoStatus() {
        assertFalse(MigrationBackup.hasBackup(configSource, configWithBackup));
    }

    @Test
    public void hasBackup_returnsFalse_whenStatusIsStarted() {
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_STARTED).commit();

        assertFalse(MigrationBackup.hasBackup(configSource, configWithBackup));
    }

    @Test
    public void hasBackup_returnsTrue_whenStatusIsComplete() {
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_COMPLETE).commit();

        assertTrue(MigrationBackup.hasBackup(configSource, configWithBackup));
    }

    // -------------------------------------------------------------------------
    // createBackup
    // -------------------------------------------------------------------------

    @Test
    public void createBackup_copiesDataEntriesToBackup() {
        dataSource.edit().putString(KEY_PREFIX + "_key1", "encryptedValue1").commit();
        dataSource.edit().putString(KEY_PREFIX + "_key2", "encryptedValue2").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("encryptedValue1", dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
        assertEquals("encryptedValue2", dataSource.getString(KEY_PREFIX + "_key2_BACKUP", null));
    }

    @Test
    public void createBackup_copiesKeyEntriesToBackup() {
        keyStorage.edit().putString("wrappedKey1", "wrappedKeyValue1").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("wrappedKeyValue1", keyStorage.getString("wrappedKey1_BACKUP", null));
    }

    @Test
    public void createBackup_setsStatusToComplete() {
        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertEquals(MigrationBackup.STATUS_COMPLETE, configSource.getString(BACKUP_STATUS_KEY, null));
    }

    @Test
    public void createBackup_skipsIfStatusIsAlreadyComplete() {
        dataSource.edit().putString(KEY_PREFIX + "_key1", "value1").commit();
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_COMPLETE).commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        // _BACKUP entry should NOT have been written since we skipped
        assertNull(dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
    }

    @Test
    public void createBackup_skipsIfStatusIsAlreadyDeleted() {
        dataSource.edit().putString(KEY_PREFIX + "_key1", "value1").commit();
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_DELETED).commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
    }

    @Test
    public void createBackup_restartsIfStatusIsStarted() {
        // Simulate a partially created backup: existing _BACKUP entry from crashed run
        dataSource.edit()
                .putString(KEY_PREFIX + "_key1", "value1")
                .putString(KEY_PREFIX + "_oldKey_BACKUP", "staleValue")
                .commit();
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_STARTED).commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        // Stale _BACKUP entry should be gone, new one created
        assertNull(dataSource.getString(KEY_PREFIX + "_oldKey_BACKUP", null));
        assertEquals("value1", dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
        assertEquals(MigrationBackup.STATUS_COMPLETE, configSource.getString(BACKUP_STATUS_KEY, null));
    }

    @Test
    public void createBackup_doesNotCopyEntriesWithoutKeyPrefix() {
        dataSource.edit().putString("OtherPrefix_key1", "value1").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(dataSource.getString("OtherPrefix_key1_BACKUP", null));
    }

    @Test
    public void createBackup_doesNotDoubleBackupExistingBackupEntries() {
        dataSource.edit().putString(KEY_PREFIX + "_key1_BACKUP", "alreadyBackedUp").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        // Should not create _BACKUP_BACKUP
        assertNull(dataSource.getString(KEY_PREFIX + "_key1_BACKUP_BACKUP", null));
    }

    // -------------------------------------------------------------------------
    // deleteBackup
    // -------------------------------------------------------------------------

    @Test
    public void deleteBackup_removesBackupEntriesFromDataSource() {
        dataSource.edit()
                .putString(KEY_PREFIX + "_key1", "value1")
                .putString(KEY_PREFIX + "_key1_BACKUP", "backupValue1")
                .commit();
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_COMPLETE).commit();

        MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
        assertEquals("value1", dataSource.getString(KEY_PREFIX + "_key1", null));
    }

    @Test
    public void deleteBackup_removesBackupEntriesFromKeyStorage() {
        keyStorage.edit()
                .putString("wrappedKey1", "wrappedValue")
                .putString("wrappedKey1_BACKUP", "backupWrappedValue")
                .commit();

        MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(keyStorage.getString("wrappedKey1_BACKUP", null));
        assertEquals("wrappedValue", keyStorage.getString("wrappedKey1", null));
    }

    @Test
    public void deleteBackup_removesStatusKey() {
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_COMPLETE).commit();

        MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(configSource.getString(BACKUP_STATUS_KEY, null));
    }

    // -------------------------------------------------------------------------
    // deleteOriginalData
    // -------------------------------------------------------------------------

    @Test
    public void deleteOriginalData_removesNonBackupDataEntries() {
        dataSource.edit()
                .putString(KEY_PREFIX + "_key1", "value1")
                .putString(KEY_PREFIX + "_key1_BACKUP", "backupValue1")
                .commit();

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, KEY_PREFIX);

        assertNull(dataSource.getString(KEY_PREFIX + "_key1", null));
        assertEquals("backupValue1", dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
    }

    @Test
    public void deleteOriginalData_removesKeyStorageEntries_whenNoMigratedMarkers() {
        keyStorage.edit()
                .putString("wrappedKey1", "wrappedValue")
                .commit();

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, KEY_PREFIX);

        assertNull(keyStorage.getString("wrappedKey1", null));
    }

    @Test
    public void deleteOriginalData_preservesAlreadyMigratedKeys() {
        dataSource.edit()
                .putString(KEY_PREFIX + "_key1", "oldValue")
                .putString(KEY_PREFIX + "_key2", "notMigratedYet")
                .commit();
        configSource.edit()
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .commit();

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, configSource, KEY_PREFIX);

        // key1 was already migrated — preserve it
        assertEquals("oldValue", dataSource.getString(KEY_PREFIX + "_key1", null));
        // key2 was not migrated — delete it
        assertNull(dataSource.getString(KEY_PREFIX + "_key2", null));
    }

    @Test
    public void deleteOriginalData_preservesKeyStorage_whenMigratedMarkersExist() {
        keyStorage.edit().putString("wrappedKey1", "newWrappedValue").commit();
        configSource.edit()
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .commit();

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, configSource, KEY_PREFIX);

        // keyStorage must be preserved when migrated markers exist
        assertEquals("newWrappedValue", keyStorage.getString("wrappedKey1", null));
    }

    // -------------------------------------------------------------------------
    // hasMigratedMarkers / deleteMigratedMarkers
    // -------------------------------------------------------------------------

    @Test
    public void hasMigratedMarkers_returnsFalse_whenNoMarkers() {
        assertFalse(MigrationBackup.hasMigratedMarkers(configSource, KEY_PREFIX));
    }

    @Test
    public void hasMigratedMarkers_returnsTrue_whenMarkerExists() {
        configSource.edit()
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .commit();

        assertTrue(MigrationBackup.hasMigratedMarkers(configSource, KEY_PREFIX));
    }

    @Test
    public void hasMigratedMarkers_ignoresMarkersForOtherPrefixes() {
        configSource.edit()
                .putBoolean("OtherPrefix_key1_MIGRATED", true)
                .commit();

        assertFalse(MigrationBackup.hasMigratedMarkers(configSource, KEY_PREFIX));
    }

    @Test
    public void deleteMigratedMarkers_removesAllMarkersForPrefix() {
        configSource.edit()
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .putBoolean(KEY_PREFIX + "_key2_MIGRATED", true)
                .commit();

        MigrationBackup.deleteMigratedMarkers(configSource, KEY_PREFIX);

        assertFalse(configSource.contains(KEY_PREFIX + "_key1_MIGRATED"));
        assertFalse(configSource.contains(KEY_PREFIX + "_key2_MIGRATED"));
    }

    @Test
    public void deleteMigratedMarkers_doesNotRemoveMarkersForOtherPrefixes() {
        configSource.edit()
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .putBoolean("OtherPrefix_key1_MIGRATED", true)
                .commit();

        MigrationBackup.deleteMigratedMarkers(configSource, KEY_PREFIX);

        assertTrue(configSource.contains("OtherPrefix_key1_MIGRATED"));
    }
}
