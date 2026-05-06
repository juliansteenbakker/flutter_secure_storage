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
import java.util.Map;
import java.util.Set;

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
    private NamespacedConfigSource configSource;
    private FlutterSecureStorageConfig config;
    private FlutterSecureStorageConfig configWithBackup;

    @Before
    public void setUp() {
        Context context = RuntimeEnvironment.getApplication();
        dataSource   = context.getSharedPreferences("TestData",   Context.MODE_PRIVATE);
        keyStorage   = context.getSharedPreferences("TestKeys",   Context.MODE_PRIVATE);
        configSource = new NamespacedConfigSource(context, "TestConfig");

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
    public void hasBackup_returnsFalse_whenStatusIsDeleted() {
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_DELETED).commit();

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
    public void createBackup_skipsNonStringDataEntries() {
        dataSource.edit()
                .putString(KEY_PREFIX + "_stringKey", "stringValue")
                .putInt(KEY_PREFIX + "_intKey", 42)
                .commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("stringValue", dataSource.getString(KEY_PREFIX + "_stringKey_BACKUP", null));
        assertNull(dataSource.getString(KEY_PREFIX + "_intKey_BACKUP", null));
    }

    @Test
    public void createBackup_doesNotCopyEntriesWithoutKeyPrefix() {
        dataSource.edit().putString("OtherPrefix_key1", "value1").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(dataSource.getString("OtherPrefix_key1_BACKUP", null));
    }

    @Test
    public void createBackup_skipsNonStringKeyStorageEntries() {
        keyStorage.edit().putInt("intWrappedKey", 42).commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(keyStorage.getString("intWrappedKey_BACKUP", null));
    }

    @Test
    public void createBackup_doesNotDoubleBackupExistingKeyStorageBackupEntries() {
        keyStorage.edit().putString("wrappedKey1_BACKUP", "alreadyBackedUp").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertNull(keyStorage.getString("wrappedKey1_BACKUP_BACKUP", null));
    }

    @Test
    public void createBackup_doesNotDoubleBackupExistingBackupEntries() {
        dataSource.edit().putString(KEY_PREFIX + "_key1_BACKUP", "alreadyBackedUp").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        // Should not create _BACKUP_BACKUP
        assertNull(dataSource.getString(KEY_PREFIX + "_key1_BACKUP_BACKUP", null));
    }

    // -------------------------------------------------------------------------
    // createBackup with espSource
    // -------------------------------------------------------------------------

    @Test
    public void createBackup_withEspSource_copiesEspEntriesToBackup() {
        SharedPreferences espSource = RuntimeEnvironment.getApplication()
                .getSharedPreferences("TestEsp", Context.MODE_PRIVATE);
        espSource.edit().clear().commit();
        espSource.edit().putString(KEY_PREFIX + "_espKey1", "encryptedEspValue1").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, espSource, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("encryptedEspValue1", espSource.getString(KEY_PREFIX + "_espKey1_BACKUP", null));
    }

    @Test
    public void createBackup_withEspSource_skipsNonStringAndNonPrefixEspEntries() {
        SharedPreferences espSource = RuntimeEnvironment.getApplication()
                .getSharedPreferences("TestEspSkip", Context.MODE_PRIVATE);
        espSource.edit().clear().commit();
        espSource.edit()
                .putString("OtherPrefix_espKey", "otherValue")  // no keyPrefix
                .putInt(KEY_PREFIX + "_intEspKey", 99)           // non-String
                .commit();

        MigrationBackup.createBackup(dataSource, keyStorage, espSource, configSource, configWithBackup, KEY_PREFIX);

        assertNull(espSource.getString("OtherPrefix_espKey_BACKUP", null));
        assertNull(espSource.getString(KEY_PREFIX + "_intEspKey_BACKUP", null));
    }

    @Test
    public void createBackup_withEspSource_doesNotDoubleBackupEspBackupEntries() {
        SharedPreferences espSource = RuntimeEnvironment.getApplication()
                .getSharedPreferences("TestEsp", Context.MODE_PRIVATE);
        espSource.edit().clear().commit();
        espSource.edit().putString(KEY_PREFIX + "_espKey1_BACKUP", "alreadyBackedUp").commit();

        MigrationBackup.createBackup(dataSource, keyStorage, espSource, configSource, configWithBackup, KEY_PREFIX);

        assertNull(espSource.getString(KEY_PREFIX + "_espKey1_BACKUP_BACKUP", null));
    }

    @Test
    public void createBackup_withEspSource_continuesWhenEspCommitFails() {
        SharedPreferences failingEsp = new FailingCommitSharedPreferences(
                RuntimeEnvironment.getApplication().getSharedPreferences("TestEspFailCommit", Context.MODE_PRIVATE));
        dataSource.edit().putString(KEY_PREFIX + "_key1", "value1").commit();

        // ESP commit failure is caught internally — data backup still completes
        MigrationBackup.createBackup(dataSource, keyStorage, failingEsp, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("value1", dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
        assertEquals(MigrationBackup.STATUS_COMPLETE, configSource.getString(BACKUP_STATUS_KEY, null));
    }

    @Test(expected = RuntimeException.class)
    public void createBackup_throwsWhenDataEditorCommitFails() {
        SharedPreferences failingData = new FailingCommitSharedPreferences(dataSource);

        MigrationBackup.createBackup(failingData, keyStorage, configSource, configWithBackup, KEY_PREFIX);
    }

    @Test(expected = RuntimeException.class)
    public void createBackup_throwsWhenKeyEditorCommitFails() {
        SharedPreferences failingKeys = new FailingCommitSharedPreferences(keyStorage);

        MigrationBackup.createBackup(dataSource, failingKeys, configSource, configWithBackup, KEY_PREFIX);
    }

    @Test
    public void createBackup_withCorruptedEspSource_continuesAndCompletesBackup() {
        SharedPreferences corruptedEsp = new ThrowingSharedPreferences(
                RuntimeEnvironment.getApplication().getSharedPreferences("TestEspCorrupted", Context.MODE_PRIVATE));
        dataSource.edit().putString(KEY_PREFIX + "_key1", "value1").commit();

        // Should not throw — exception is caught and ESP backup is skipped
        MigrationBackup.createBackup(dataSource, keyStorage, corruptedEsp, configSource, configWithBackup, KEY_PREFIX);

        // Data backup still completes
        assertEquals("value1", dataSource.getString(KEY_PREFIX + "_key1_BACKUP", null));
        assertEquals(MigrationBackup.STATUS_COMPLETE, configSource.getString(BACKUP_STATUS_KEY, null));
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
    public void deleteBackup_withEspSource_removesEspBackupEntries() {
        SharedPreferences espSource = RuntimeEnvironment.getApplication()
                .getSharedPreferences("TestEsp", Context.MODE_PRIVATE);
        espSource.edit().clear().commit();
        espSource.edit()
                .putString(KEY_PREFIX + "_espKey1", "espValue")
                .putString(KEY_PREFIX + "_espKey1_BACKUP", "backupEspValue")
                .commit();

        MigrationBackup.deleteBackup(dataSource, keyStorage, espSource, configSource, configWithBackup, KEY_PREFIX);

        assertNull(espSource.getString(KEY_PREFIX + "_espKey1_BACKUP", null));
        assertEquals("espValue", espSource.getString(KEY_PREFIX + "_espKey1", null));
    }

    @Test
    public void deleteBackup_doesNotRemoveDataBackupEntriesWithoutKeyPrefix() {
        dataSource.edit().putString("OtherPrefix_key1_BACKUP", "otherBackupValue").commit();

        MigrationBackup.deleteBackup(dataSource, keyStorage, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("otherBackupValue", dataSource.getString("OtherPrefix_key1_BACKUP", null));
    }

    @Test
    public void deleteBackup_withEspSource_doesNotRemoveEspBackupEntriesWithoutKeyPrefix() {
        SharedPreferences espSource = RuntimeEnvironment.getApplication()
                .getSharedPreferences("TestEspOther", Context.MODE_PRIVATE);
        espSource.edit().clear().commit();
        espSource.edit().putString("OtherPrefix_espKey_BACKUP", "otherBackupValue").commit();

        MigrationBackup.deleteBackup(dataSource, keyStorage, espSource, configSource, configWithBackup, KEY_PREFIX);

        assertEquals("otherBackupValue", espSource.getString("OtherPrefix_espKey_BACKUP", null));
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
    public void deleteOriginalData_doesNotRemoveDataEntriesWithoutKeyPrefix() {
        dataSource.edit().putString("OtherPrefix_key1", "otherValue").commit();

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, KEY_PREFIX);

        assertEquals("otherValue", dataSource.getString("OtherPrefix_key1", null));
    }

    @Test
    public void deleteOriginalData_doesNotRemoveKeyStorageBackupEntries() {
        keyStorage.edit()
                .putString("wrappedKey1", "wrappedValue")
                .putString("wrappedKey1_BACKUP", "backupWrappedValue")
                .commit();

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, KEY_PREFIX);

        assertNull(keyStorage.getString("wrappedKey1", null));
        assertEquals("backupWrappedValue", keyStorage.getString("wrappedKey1_BACKUP", null));
    }

    @Test
    public void deleteOriginalData_deletesKeyStorage_whenConfigSourceNotNullButNoMigratedMarkers() {
        keyStorage.edit().putString("wrappedKey1", "wrappedValue").commit();
        // configSource is not null but has no _MIGRATED markers

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, configSource, KEY_PREFIX);

        assertNull(keyStorage.getString("wrappedKey1", null));
    }

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

    @Test
    public void deleteOriginalData_preservesKeyStorage_whenDataSourceEmptyButMigratedMarkersExist() {
        // Regression test for cc0d932: dataSource is empty (all values already re-encrypted and
        // written back), but configSource still has _MIGRATED markers from the previous run.
        // preservedCount stays 0 because there are no dataSource entries to iterate, yet
        // hasMigratedMarkers() must still return true so keyStorage is preserved.
        keyStorage.edit().putString("wrappedKey1", "newWrappedValue").commit();
        configSource.edit()
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .commit();
        // dataSource intentionally empty

        MigrationBackup.deleteOriginalData(dataSource, keyStorage, configSource, KEY_PREFIX);

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
    public void hasMigratedMarkers_ignoresNonMigratedEntriesInConfigSource() {
        configSource.edit().putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_COMPLETE).commit();

        assertFalse(MigrationBackup.hasMigratedMarkers(configSource, KEY_PREFIX));
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
    public void deleteMigratedMarkers_doesNotRemoveNonMigratedEntries() {
        configSource.edit()
                .putString(BACKUP_STATUS_KEY, MigrationBackup.STATUS_COMPLETE)
                .putBoolean(KEY_PREFIX + "_key1_MIGRATED", true)
                .commit();

        MigrationBackup.deleteMigratedMarkers(configSource, KEY_PREFIX);

        assertEquals(MigrationBackup.STATUS_COMPLETE, configSource.getString(BACKUP_STATUS_KEY, null));
    }

    @Test
    public void deleteMigratedMarkers_noOp_whenNoMarkersExist() {
        // count stays 0 — exercises the count == 0 branch (no log written)
        MigrationBackup.deleteMigratedMarkers(configSource, KEY_PREFIX);
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

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * SharedPreferences wrapper whose edit() returns an Editor that always returns false from
     * commit(), to exercise the commit-failure RuntimeException paths in MigrationBackup.
     */
    private static class FailingCommitSharedPreferences implements SharedPreferences {
        private final SharedPreferences delegate;

        FailingCommitSharedPreferences(SharedPreferences delegate) {
            this.delegate = delegate;
        }

        @Override public Map<String, ?> getAll() { return delegate.getAll(); }
        @Override public String getString(String key, String defValue) { return delegate.getString(key, defValue); }
        @Override public Set<String> getStringSet(String key, Set<String> defValues) { return delegate.getStringSet(key, defValues); }
        @Override public int getInt(String key, int defValue) { return delegate.getInt(key, defValue); }
        @Override public long getLong(String key, long defValue) { return delegate.getLong(key, defValue); }
        @Override public float getFloat(String key, float defValue) { return delegate.getFloat(key, defValue); }
        @Override public boolean getBoolean(String key, boolean defValue) { return delegate.getBoolean(key, defValue); }
        @Override public boolean contains(String key) { return delegate.contains(key); }
        @Override public Editor edit() { return new FailingEditor(delegate.edit()); }
        @Override public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) { delegate.registerOnSharedPreferenceChangeListener(listener); }
        @Override public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) { delegate.unregisterOnSharedPreferenceChangeListener(listener); }
    }

    private static class FailingEditor implements SharedPreferences.Editor {
        private final SharedPreferences.Editor delegate;

        FailingEditor(SharedPreferences.Editor delegate) {
            this.delegate = delegate;
        }

        @Override public SharedPreferences.Editor putString(String key, String value) { return delegate.putString(key, value); }
        @Override public SharedPreferences.Editor putStringSet(String key, Set<String> values) { return delegate.putStringSet(key, values); }
        @Override public SharedPreferences.Editor putInt(String key, int value) { return delegate.putInt(key, value); }
        @Override public SharedPreferences.Editor putLong(String key, long value) { return delegate.putLong(key, value); }
        @Override public SharedPreferences.Editor putFloat(String key, float value) { return delegate.putFloat(key, value); }
        @Override public SharedPreferences.Editor putBoolean(String key, boolean value) { return delegate.putBoolean(key, value); }
        @Override public SharedPreferences.Editor remove(String key) { return delegate.remove(key); }
        @Override public SharedPreferences.Editor clear() { return delegate.clear(); }
        @Override public boolean commit() { return false; }
        @Override public void apply() { delegate.apply(); }
    }

    /**
     * SharedPreferences wrapper whose getAll() throws to simulate a corrupted
     * EncryptedSharedPreferences instance. All other methods delegate to the real backing store.
     */
    private static class ThrowingSharedPreferences implements SharedPreferences {
        private final SharedPreferences delegate;

        ThrowingSharedPreferences(SharedPreferences delegate) {
            this.delegate = delegate;
        }

        @Override
        public Map<String, ?> getAll() {
            throw new RuntimeException("Simulated ESP corruption");
        }

        @Override public String getString(String key, String defValue) { return delegate.getString(key, defValue); }
        @Override public Set<String> getStringSet(String key, Set<String> defValues) { return delegate.getStringSet(key, defValues); }
        @Override public int getInt(String key, int defValue) { return delegate.getInt(key, defValue); }
        @Override public long getLong(String key, long defValue) { return delegate.getLong(key, defValue); }
        @Override public float getFloat(String key, float defValue) { return delegate.getFloat(key, defValue); }
        @Override public boolean getBoolean(String key, boolean defValue) { return delegate.getBoolean(key, defValue); }
        @Override public boolean contains(String key) { return delegate.contains(key); }
        @Override public Editor edit() { return delegate.edit(); }
        @Override public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) { delegate.registerOnSharedPreferenceChangeListener(listener); }
        @Override public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) { delegate.unregisterOnSharedPreferenceChangeListener(listener); }
    }
}
