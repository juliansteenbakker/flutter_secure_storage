package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.KeyCipher;
import java.security.Key;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MigrationRecoveryTest {
    private Context context;
    private FlutterSecureStorageConfig config;
    private NamespacedConfigSource configSource;
    private SharedPreferences data;
    private SharedPreferences keys;
    private String entry;
    private String ciphertext;

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        Map<String, Object> options = new HashMap<>();
        options.put("migrateWithBackup", "true");
        config = new FlutterSecureStorageConfig(options);
        configSource = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
        data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        keys = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        entry = config.getSharedPreferencesKeyPrefix() + "_token";
        ciphertext = Base64.encodeToString("saved-token".getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
    }

    @Test
    public void storageCipherOnlyChangePreservesValues() throws Exception {
        data.edit().putString(entry, ciphertext).commit();
        keys.edit().putString("wrapped-key", "saved-key").commit();

        Exception failure = migrate(false);

        assertNull(failure);
        assertEquals(ciphertext, data.getString(entry, null));
        assertFalse(data.contains(entry + "_BACKUP"));
    }

    @Test
    public void backupOnlyInterruptedMigrationResumes() throws Exception {
        data.edit().putString(entry + "_BACKUP", ciphertext).commit();
        keys.edit().putString("wrapped-key_BACKUP", "saved-key").commit();
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_COMPLETE);
        assertTrue(MigrationBackup.hasPendingMigration(data, keys, configSource, config));

        Exception failure = migrate(false);

        assertNull(failure);
        assertEquals(ciphertext, data.getString(entry, null));
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
    }

    @Test
    public void failedDecryptionPreservesOriginalsAndBackup() throws Exception {
        data.edit().putString(entry, ciphertext).commit();
        keys.edit().putString("wrapped-key", "saved-key").commit();

        Exception failure = migrate(true);

        assertNotNull(failure);
        assertEquals(ciphertext, data.getString(entry, null));
        assertEquals(ciphertext, configSource.getDataBackupPreferences().getString(entry, null));
        assertEquals("saved-key", keys.getString("wrapped-key", null));
    }

    @Test
    public void pendingDetectionIncludesStatusProgressAndBackupEntries() {
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_STARTED);
        assertTrue(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        configSource.edit().clear().commit();
        configSource.edit().putBoolean(entry + "_MIGRATED", true).commit();
        assertTrue(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        configSource.edit().clear().commit();
        data.edit().putString(entry + "_BACKUP", ciphertext).commit();
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        data.edit().clear().commit();
        keys.edit().putString("wrapped-key_BACKUP", "saved-key").commit();
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_CLEANUP);
        assertTrue(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
    }

    @Test
    public void interruptedFinalCleanupPreservesMigratedValues() throws Exception {
        data.edit().putString(entry, ciphertext).commit();
        configSource.edit().putBoolean(entry + "_MIGRATED", true).commit();
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_COMPLETE);
        FlutterSecureStorage storage = createStorage(false);
        Method cleanup = FlutterSecureStorage.class.getDeclaredMethod("finishInterruptedCleanup",
                NamespacedConfigSource.class, SharedPreferences.class, javax.crypto.Cipher.class);
        cleanup.setAccessible(true);

        cleanup.invoke(storage, configSource, data, null);

        assertEquals(ciphertext, data.getString(entry, null));
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
    }

    @Test
    public void cleanupResumesWithOnlyWrappedKeyBackups() throws Exception {
        data.edit().putString(entry, ciphertext).commit();
        keys.edit().putString("wrapped-key", "current-key")
                .putString("wrapped-key_BACKUP", "old-key").commit();
        configSource.edit().putBoolean(entry + "_MIGRATED", true).commit();
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_COMPLETE);

        assertTrue(MigrationBackup.shouldFinishCleanup(data, configSource, config));
        finishCleanup(createStorage(false));

        assertEquals(ciphertext, data.getString(entry, null));
        assertEquals("current-key", keys.getString("wrapped-key", null));
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
    }

    @Test
    public void cleanupPhaseResumesBeforeAndAfterEachBackupDeletion() throws Exception {
        for (int boundary = 0; boundary < 3; boundary++) {
            data.edit().clear().putString(entry, ciphertext).commit();
            keys.edit().clear().putString("wrapped-key", "current-key").commit();
            configSource.edit().clear().putBoolean(entry + "_MIGRATED", true).commit();
            if (boundary == 0) {
                data.edit().putString(entry + "_BACKUP", ciphertext).commit();
            }
            if (boundary < 2) {
                keys.edit().putString("wrapped-key_BACKUP", "old-key").commit();
            }
            MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_CLEANUP);

            assertTrue(MigrationBackup.shouldFinishCleanup(data, configSource, config));
            finishCleanup(createStorage(false));

            assertEquals(ciphertext, data.getString(entry, null));
            assertEquals("current-key", keys.getString("wrapped-key", null));
            assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        }
    }

    @Test
    public void unreadableMigratedDataPreservesCleanupBackups() throws Exception {
        data.edit().putString(entry, ciphertext).putString(entry + "_BACKUP", ciphertext).commit();
        keys.edit().putString("wrapped-key_BACKUP", "old-key").commit();
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_CLEANUP);
        try {
            finishCleanup(createStorage(true));
            org.junit.Assert.fail("Unreadable migrated data must not discard backups");
        } catch (java.lang.reflect.InvocationTargetException expected) {
            assertNotNull(expected.getCause());
        }
        assertTrue(data.contains(entry + "_BACKUP"));
        assertTrue(keys.contains("wrapped-key_BACKUP"));
        assertEquals(MigrationBackup.STATUS_CLEANUP, MigrationBackup.getBackupStatus(configSource, config));
    }

    @Test
    public void readableMarkerlessEntriesPersistCurrentAlgorithms() throws Exception {
        data.edit().putString(entry, ciphertext).commit();
        FlutterSecureStorage storage = createStorage(false);
        Method initialize = FlutterSecureStorage.class.getDeclaredMethod("initializeMarkerlessStorage",
                NamespacedConfigSource.class);
        initialize.setAccessible(true);

        assertTrue((Boolean) initialize.invoke(storage, configSource));

        StorageCipherFactory restored = new StorageCipherFactory(configSource,
                config.getPrefOptionKeyCipherAlgorithm(), config.getPrefOptionStorageCipherAlgorithm(), config);
        assertFalse(restored.assumedSavedAlgorithms());
        assertFalse(restored.requiresReEncryption());
        assertEquals(ciphertext, data.getString(entry, null));
    }

    @Test
    public void everyMarkerlessEntryMustBeReadable() throws Exception {
        data.edit().putString(entry, ciphertext).putString(entry + "-bad", "not-base64!").commit();
        FlutterSecureStorage storage = createStorage(false);
        Method initialize = FlutterSecureStorage.class.getDeclaredMethod("initializeMarkerlessStorage",
                NamespacedConfigSource.class);
        initialize.setAccessible(true);

        assertFalse((Boolean) initialize.invoke(storage, configSource));

        StorageCipherFactory restored = new StorageCipherFactory(configSource,
                config.getPrefOptionKeyCipherAlgorithm(), config.getPrefOptionStorageCipherAlgorithm(), config);
        assertTrue(restored.assumedSavedAlgorithms());
    }

    @Test
    public void persistedMixedStoreOverridesEncryptedPreferencesMigratedFlag() {
        configSource.edit().putBoolean("ENCRYPTED_PREFERENCES_MIGRATED", true).commit();
        data.edit().putString(entry, ciphertext)
                .putString("__androidx_security_crypto_encrypted_prefs_key_keyset__", "keyset")
                .putString("encrypted-tink-key", "encrypted-tink-value").commit();
        Map<String, Object> options = new HashMap<>();
        options.put("migrateWithBackup", "false");
        FlutterSecureStorageConfig migrationConfig = new FlutterSecureStorageConfig(options);

        assertTrue(FlutterSecureStorage.shouldMigrateEncryptedPreferences(data, configSource, migrationConfig));
        data.edit().remove("encrypted-tink-key").commit();
        assertFalse(FlutterSecureStorage.shouldMigrateEncryptedPreferences(data, configSource, migrationConfig));
    }

    @Test
    public void standaloneBackupSuffixIsAUserKeyWithoutMigrationState() throws Exception {
        data.edit().putString(entry + "_BACKUP", ciphertext).commit();
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        assertEquals(java.util.Set.of("token_BACKUP"),
                new FlutterSecureStorage(context).selectedEntryKeys(config, Map.of()));
    }

    @Test
    public void pairedBackupSuffixUserKeysSurviveMigrationAndRetry() throws Exception {
        String suffixValue = Base64.encodeToString("suffix-token".getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
        data.edit().putString(entry, ciphertext).putString(entry + "_BACKUP", suffixValue).commit();
        keys.edit().putString("wrapped-key", "saved-key").commit();
        assertNotNull(migrate(true));
        assertEquals(ciphertext, data.getString(entry, null));
        assertEquals(suffixValue, data.getString(entry + "_BACKUP", null));
        assertNull(migrate(false));
        assertEquals(Map.of(entry, ciphertext, entry + "_BACKUP", suffixValue), data.getAll());
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
    }

    @Test
    public void standaloneBackupSuffixSurvivesLegacyMigrationWithoutRenaming() throws Exception {
        data.edit().putString(entry + "_BACKUP", ciphertext).commit();
        keys.edit().putString("wrapped-key", "saved-key").commit();
        assertNull(migrate(false));
        assertEquals(Map.of(entry + "_BACKUP", ciphertext), data.getAll());
    }

    @Test
    public void creatingBackupDoesNotWriteToTheUserPreferences() {
        String suffixValue = Base64.encodeToString("suffix-token".getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
        data.edit().putString(entry, ciphertext).putString(entry + "_BACKUP", suffixValue).commit();
        Map<String, ?> original = new HashMap<>(data.getAll());
        keys.edit().putString("wrapped-key", "saved-key").commit();
        MigrationBackup.createBackup(data, keys, configSource, config, config.getSharedPreferencesKeyPrefix());
        assertEquals(original, data.getAll());
    }

    @Test
    public void interruptedSeparateBackupRestartsWithoutOverwritingSuffixUserKeys() throws Exception {
        String suffixValue = Base64.encodeToString("suffix-token".getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
        data.edit().putString(entry, ciphertext).putString(entry + "_BACKUP", suffixValue).commit();
        keys.edit().putString("wrapped-key", "saved-key").commit();
        MigrationBackup.createBackup(data, keys, configSource, config, config.getSharedPreferencesKeyPrefix());
        configSource.getDataBackupPreferences().edit().remove(entry + "_BACKUP").commit();
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_STARTED);
        assertNull(migrate(false));
        assertEquals(Map.of(entry, ciphertext, entry + "_BACKUP", suffixValue), data.getAll());
        assertTrue(configSource.getDataBackupPreferences().getAll().isEmpty());
    }

    @Test
    public void anotherStoresGlobalMigrationStatusDoesNotClaimSuffixUserKeys() {
        data.edit().putString(entry + "_BACKUP", ciphertext).commit();
        context.getSharedPreferences("FlutterSecureStorageConfiguration", Context.MODE_PRIVATE).edit()
                .putString("FlutterSecureStorageBackupStatus", MigrationBackup.STATUS_COMPLETE).commit();
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
        assertTrue(MigrationBackup.getDataBackups(data, configSource, config.getSharedPreferencesKeyPrefix()).isEmpty());
    }

    @Test
    public void completedLegacyBackupCleanupCannotClaimNewSuffixUserKeys() throws Exception {
        data.edit().putString(entry + "_BACKUP", ciphertext).commit();
        MigrationBackup.setBackupStatus(configSource, config, MigrationBackup.STATUS_DELETED);
        assertTrue(MigrationBackup.getDataBackups(data, configSource, config.getSharedPreferencesKeyPrefix()).isEmpty());
        finishCleanup(createStorage(false));
        assertEquals(Map.of(entry + "_BACKUP", ciphertext), data.getAll());
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, configSource, config));
    }

    private void finishCleanup(FlutterSecureStorage storage) throws Exception {
        Method cleanup = FlutterSecureStorage.class.getDeclaredMethod("finishInterruptedCleanup",
                NamespacedConfigSource.class, SharedPreferences.class, javax.crypto.Cipher.class);
        cleanup.setAccessible(true);
        cleanup.invoke(storage, configSource, data, null);
    }

    private FlutterSecureStorage createStorage(boolean failDecryption) throws Exception {
        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        Field configField = FlutterSecureStorage.class.getDeclaredField("config");
        configField.setAccessible(true);
        configField.set(storage, config);
        Field factoryField = FlutterSecureStorage.class.getDeclaredField("storageCipherFactory");
        factoryField.setAccessible(true);
        factoryField.set(storage, new StorageCipherFactory(configSource,
                config.getPrefOptionKeyCipherAlgorithm(), config.getPrefOptionStorageCipherAlgorithm(), config) {
            private final StorageCipher cipher = new StorageCipher() {
                public byte[] encrypt(byte[] input) {
                    return input;
                }

                public byte[] decrypt(byte[] input) throws Exception {
                    if (failDecryption) {
                        throw new Exception("Unreadable backup");
                    }
                    return input;
                }

                public void deleteKey(Context context) {}
            };

            public KeyCipher getCurrentKeyCipher(Context context) {
                return new KeyCipher() {
                    public Cipher getCipher(Context ignored) { return null; }
                    public void deleteKey() {}
                    public byte[] wrap(Key key) { return key.getEncoded(); }
                    public Key unwrap(byte[] input, String algorithm) { return null; }
                };
            }

            public boolean currentCipherDecrypts(Context context, byte[] input) {
                return !failDecryption;
            }

            public boolean changedKeyAlgorithm() {
                return false;
            }

            public StorageCipher getSavedStorageCipherFromBackup(Context context, Cipher ignored,
                                                                  SharedPreferences keyStorage) {
                return cipher;
            }

            public StorageCipher getSavedStorageCipher(Context context, Cipher ignored) {
                return cipher;
            }

            public StorageCipher getCurrentStorageCipher(Context context, Cipher ignored) {
                return cipher;
            }
        });
        return storage;
    }

    private Exception migrate(boolean failDecryption) throws Exception {
        FlutterSecureStorage storage = createStorage(failDecryption);
        final Exception[] failure = {null};
        Method migration = FlutterSecureStorage.class.getDeclaredMethod("migrateNonBiometricWithBackup",
                NamespacedConfigSource.class, SharedPreferences.class, SecurePreferencesCallback.class);
        migration.setAccessible(true);
        migration.invoke(storage, configSource, data, new SecurePreferencesCallback<Void>() {
            public void onSuccess(Void ignored) {}

            public void onError(Exception error) {
                failure[0] = error;
            }
        });
        return failure[0];
    }
}
