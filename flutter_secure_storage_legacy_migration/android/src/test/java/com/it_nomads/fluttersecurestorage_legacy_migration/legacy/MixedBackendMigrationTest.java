package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import androidx.security.crypto.EncryptedSharedPreferences;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkConfig;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.KeyCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherFactory;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherImplementationAES18;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherImplementationGCM;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MixedBackendMigrationTest {
    @Test
    public void cbcAndJetpackValuesSurviveMigrationAndReopen() throws Exception {
        Fixture fixture = new Fixture("mixed-cbc", true);
        fixture.migrateAndVerify();
        assertTrue(LegacyBackendEntries.hasEntries(fixture.data, fixture.prefix));
        fixture.storage.completeVerifiedMigration(fixture.config);
        fixture.assertReopened();
        assertFalse(LegacyBackendEntries.hasEntries(fixture.data, fixture.prefix));
    }

    @Test
    public void repeatedCompletionAfterAnotherEngineCleansUpIsSafe() throws Exception {
        Fixture fixture = new Fixture("mixed-repeat-cleanup", true);
        fixture.migrateAndVerify();
        fixture.storage.completeVerifiedMigration(fixture.config);
        fixture.newStorage().completeVerifiedMigration(fixture.config);
        fixture.assertReopened();
        assertFalse(MigrationVerification.hasPending(fixture.context, fixture.config));
    }

    @Test
    public void missingVerificationCannotAuthorizeDeletionOfLegacyEntries() throws Exception {
        Fixture fixture = new Fixture("mixed-unverified", true);
        fixture.migrate();
        assertThrows(java.io.IOException.class,
                () -> fixture.storage.completeVerifiedMigration(fixture.config));
        assertEquals("jetpack-value", fixture.encrypted().getString(fixture.prefix + "_jetpack", null));
    }

    @Test
    public void jetpackOnlyStoreDoesNotRequireCustomWrappedKeys() throws Exception {
        Fixture fixture = new Fixture("jetpack-only", true);
        fixture.data.edit().remove(fixture.prefix + "_custom").commit();
        fixture.context.getSharedPreferences(fixture.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().commit();
        fixture.migrate();
        assertEquals(Map.of("jetpack", "jetpack-value"), fixture.storage.readAll());
        fixture.storage.recordMigrationVerification();
        assertTrue(MigrationVerification.hasPending(fixture.context, fixture.config));
        fixture.storage.completeVerifiedMigration(fixture.config);
        assertFalse(MigrationVerification.hasPending(fixture.context, fixture.config));
        assertFalse(LegacyBackendEntries.hasEntries(fixture.data, fixture.prefix));
        StorageCipher reopened = new StorageCipherImplementationGCM(fixture.context, fixture.newRsa, null, fixture.config);
        assertEquals("jetpack-value", new String(reopened.decrypt(Base64.decode(
                fixture.data.getString(fixture.prefix + "_jetpack", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
    }

    @Test
    public void currentGcmEntriesTakePrecedenceOverDuplicateJetpackEntries() throws Exception {
        Fixture fixture = new Fixture("mixed-gcm", false);
        fixture.encrypted().edit().putString(fixture.prefix + "_custom", "older-value").commit();
        fixture.migrateAndVerify();
        fixture.storage.completeVerifiedMigration(fixture.config);
        fixture.assertReopened();
    }

    @Test
    public void interruptionBeforeVersion11VerificationKeepsOriginalsAndResumes() throws Exception {
        Fixture fixture = new Fixture("mixed-interrupted", true);
        fixture.migrateAndVerify();
        assertEquals("jetpack-value", fixture.encrypted().getString(fixture.prefix + "_jetpack", null));
        fixture.storage = fixture.newStorage();
        fixture.migrateAndVerify();
        fixture.storage.completeVerifiedMigration(fixture.config);
        fixture.assertReopened();
    }

    @Test
    public void changedCiphertextCannotAuthorizeOriginalDeletion() throws Exception {
        Fixture fixture = new Fixture("mixed-corrupt", true);
        fixture.migrateAndVerify();
        fixture.data.edit().putString(fixture.prefix + "_custom", "corrupt").commit();
        assertThrows(java.io.IOException.class,
                () -> fixture.storage.completeVerifiedMigration(fixture.config));
        assertEquals("jetpack-value", fixture.encrypted().getString(fixture.prefix + "_jetpack", null));
    }

    @Test
    public void changedJetpackSourceCannotBeDeletedUsingAnEarlierVerification() throws Exception {
        Fixture fixture = new Fixture("mixed-source-changed", true);
        fixture.migrateAndVerify();
        fixture.encrypted().edit().putString(fixture.prefix + "_jetpack", "changed-value").commit();
        assertThrows(java.io.IOException.class,
                () -> fixture.storage.completeVerifiedMigration(fixture.config));
        assertEquals("changed-value", fixture.encrypted().getString(fixture.prefix + "_jetpack", null));
    }

    @Test
    public void completingMigrationPreservesJetpackEntriesFromAnotherPrefix() throws Exception {
        Fixture fixture = new Fixture("mixed-prefix", true);
        fixture.encrypted().edit().putString("other-prefix_token", "other-account-token").commit();
        fixture.migrateAndVerify();
        fixture.storage.completeVerifiedMigration(fixture.config);
        assertEquals("other-account-token", fixture.encrypted().getString("other-prefix_token", null));
        fixture.assertReopened();
    }

    @Test
    public void selectedKeysExcludeOtherPrefixesBeforeAndAfterMigration() throws Exception {
        Fixture fixture = new Fixture("selected-prefix-count", true);
        fixture.data.edit().remove(fixture.prefix + "_custom").commit();
        fixture.encrypted().edit().putString("other-prefix_token", "other-account-token").commit();
        assertEquals(java.util.Set.of("jetpack"),
                fixture.storage.selectedEntryKeys(fixture.config, Map.of()));
        fixture.migrate();
        assertEquals(Map.of("jetpack", "jetpack-value"), fixture.storage.readAll());
        fixture.storage.recordMigrationVerification();
        fixture.storage.completeVerifiedMigration(fixture.config);
        fixture.newStorage().completeVerifiedMigration(fixture.config);
        assertEquals("other-account-token", fixture.encrypted().getString("other-prefix_token", null));
    }

    @Test
    public void partialCipherMigrationIsRejectedWhileBothPrefixesRemainReadable() throws Exception {
        Fixture fixture = new Fixture("raw-other-prefix", true);
        StorageCipher original = new StorageCipherImplementationAES18(
                fixture.context, fixture.oldRsa, null, fixture.config);
        fixture.data.edit().putString("other-prefix_token", Base64.encodeToString(original.encrypt(
                "other-account-token".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT)).commit();
        Map<String, ?> data = new HashMap<>(fixture.data.getAll());
        SharedPreferences wrapped = fixture.context.getSharedPreferences(
                fixture.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        Map<String, ?> keys = new HashMap<>(wrapped.getAll());
        NamespacedConfigSource metadata = new NamespacedConfigSource(
                fixture.context, fixture.config.getEffectiveDataPrefsName());
        Map<String, ?> markers = new HashMap<>(metadata.getAll());
        assertThrows(java.io.IOException.class, fixture::migrate);
        assertEquals(data, fixture.data.getAll());
        assertEquals(keys, wrapped.getAll());
        assertEquals(markers, metadata.getAll());
        StorageCipher reopened = new StorageCipherImplementationAES18(
                fixture.context, fixture.oldRsa, null, fixture.config);
        assertEquals("custom-value", new String(reopened.decrypt(Base64.decode(
                fixture.data.getString(fixture.prefix + "_custom", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
        assertEquals("other-account-token", new String(reopened.decrypt(Base64.decode(
                fixture.data.getString("other-prefix_token", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
        FlutterSecureStorageConfig other = new FlutterSecureStorageConfig(Map.of(
                "storageNamespace", "raw-other-prefix", "preferencesKeyPrefix", "other-prefix",
                "migrateWithBackup", "true", "resetOnError", "false"));
        Exception[] failure = {null};
        fixture.newStorage().initializeCustomStorage(other, new SecurePreferencesCallback<>() {
            public void onSuccess(Void unused) { fail("Partial migration must be rejected"); }
            public void onError(Exception error) { failure[0] = error; }
        });
        assertTrue(failure[0] instanceof java.io.IOException);
        assertEquals(data, fixture.data.getAll());
    }

    @Test
    public void verificationReceiptsBelongToTheSelectedPrefix() throws Exception {
        Fixture fixture = new Fixture("prefix-verification", false);
        FlutterSecureStorageConfig other = new FlutterSecureStorageConfig(Map.of(
                "storageNamespace", "prefix-verification", "preferencesKeyPrefix", "other-prefix"));
        MigrationVerification.record(fixture.context, fixture.config, java.util.Set.of("custom"));
        assertFalse(MigrationVerification.hasPending(fixture.context, other));
        MigrationVerification.record(fixture.context, other, java.util.Set.of("token"));
        MigrationVerification.clear(fixture.context, fixture.config);
        assertTrue(MigrationVerification.hasPending(fixture.context, other));
    }

    @Test
    public void cbcUserKeysEndingInBackupSurviveMigrationAndColdReopen() throws Exception {
        for (boolean standalone : new boolean[]{false, true}) {
            Fixture fixture = new Fixture("suffix-cbc-" + standalone, true);
            StorageCipher original = new StorageCipherImplementationAES18(
                    fixture.context, fixture.oldRsa, null, fixture.config);
            fixture.data.edit().putString(fixture.prefix + "_custom_BACKUP", Base64.encodeToString(original.encrypt(
                    "suffix-value".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT)).commit();
            if (standalone) {
                fixture.data.edit().remove(fixture.prefix + "_custom").commit();
            }
            assertTrue(fixture.storage.hasLegacyCustomEntries(fixture.config));
            fixture.migrate();
            Map<String, String> expected = new HashMap<>(Map.of("custom_BACKUP", "suffix-value", "jetpack", "jetpack-value"));
            if (!standalone) { expected.put("custom", "custom-value"); }
            assertEquals(expected, fixture.storage.readAll());
            fixture.storage.recordMigrationVerification();
            fixture.storage.completeVerifiedMigration(fixture.config);
            StorageCipher reopened = new StorageCipherImplementationGCM(fixture.context, fixture.newRsa, null, fixture.config);
            for (Map.Entry<String, String> entry : expected.entrySet()) {
                assertEquals(entry.getValue(), new String(reopened.decrypt(Base64.decode(
                        fixture.data.getString(fixture.prefix + "_" + entry.getKey(), null), Base64.DEFAULT)), StandardCharsets.UTF_8));
            }
            assertEquals(expected.keySet(), fixture.storage.selectedEntryKeys(fixture.config, Map.of()));
        }
    }

    @Test
    public void readableGcmSuffixUserKeysAreNotPendingMigration() throws Exception {
        for (boolean standalone : new boolean[]{false, true}) {
            Fixture fixture = new Fixture("suffix-current-" + standalone, false);
            fixture.encrypted().edit().remove(fixture.prefix + "_jetpack").commit();
            StorageCipher original = new StorageCipherImplementationGCM(
                    fixture.context, fixture.newRsa, null, fixture.config);
            fixture.data.edit().putString(fixture.prefix + "_custom_BACKUP", Base64.encodeToString(original.encrypt(
                    "suffix-value".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT)).commit();
            if (standalone) { fixture.data.edit().remove(fixture.prefix + "_custom").commit(); }
            NamespacedConfigSource source = new NamespacedConfigSource(fixture.context, fixture.config.getEffectiveDataPrefsName());
            assertFalse(MigrationBackup.hasPendingMigration(fixture.data,
                    fixture.context.getSharedPreferences(fixture.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE),
                    source, fixture.config));
            assertFalse(fixture.storage.hasLegacyCustomEntries(fixture.config));
            java.util.Set<String> expected = new java.util.HashSet<>(java.util.Set.of("custom_BACKUP"));
            if (!standalone) { expected.add("custom"); }
            assertEquals(expected, fixture.storage.selectedEntryKeys(fixture.config, Map.of()));
            StorageCipher reopened = new StorageCipherImplementationGCM(fixture.context, fixture.newRsa, null, fixture.config);
            assertEquals("suffix-value", new String(reopened.decrypt(Base64.decode(
                    fixture.data.getString(fixture.prefix + "_custom_BACKUP", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
        }
    }

    @Test
    public void anotherPrefixesSeparateBackupCannotRetireItsCipher() throws Exception {
        Fixture fixture = new Fixture("foreign-prefix-backup", true);
        StorageCipher original = new StorageCipherImplementationAES18(
                fixture.context, fixture.oldRsa, null, fixture.config);
        String ciphertext = Base64.encodeToString(original.encrypt(
                "other-account-token".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT);
        fixture.data.edit().clear().putString("other-prefix_token", ciphertext).commit();
        NamespacedConfigSource source = new NamespacedConfigSource(fixture.context, fixture.config.getEffectiveDataPrefsName());
        SharedPreferences wrapped = fixture.context.getSharedPreferences(
                fixture.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        MigrationBackup.createBackup(fixture.data, wrapped, source, fixture.config, "other-prefix");
        MigrationBackup.deleteOriginalData(fixture.data, wrapped, source, "other-prefix");
        Map<String, ?> keys = new HashMap<>(wrapped.getAll());
        Map<String, ?> markers = new HashMap<>(source.getAll());
        assertThrows(java.io.IOException.class, fixture::migrate);
        assertEquals(keys, wrapped.getAll());
        assertEquals(markers, source.getAll());
        StorageCipher reopened = new StorageCipherImplementationAES18(
                fixture.context, fixture.oldRsa, null, fixture.config);
        assertEquals("other-account-token", new String(reopened.decrypt(Base64.decode(
                source.getDataBackupPreferences().getString("other-prefix_token", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
    }

    private static final class Fixture {
        final Context context = RuntimeEnvironment.getApplication();
        final FlutterSecureStorageConfig config;
        final SharedPreferences data;
        final String prefix;
        final RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        final RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        final Aead values;
        final DeterministicAead keys;
        FlutterSecureStorage storage;

        Fixture(String namespace, boolean cbc) throws Exception {
            Security.addProvider(new BouncyCastleProvider());
            TinkConfig.register();
            values = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM")).getPrimitive(Aead.class);
            keys = KeysetHandle.generateNew(KeyTemplates.get("AES256_SIV")).getPrimitive(DeterministicAead.class);
            Map<String, Object> options = new HashMap<>();
            options.put("storageNamespace", namespace);
            options.put("migrateWithBackup", "true");
            options.put("resetOnError", "false");
            config = new FlutterSecureStorageConfig(options);
            prefix = config.getSharedPreferencesKeyPrefix();
            data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
            NamespacedConfigSource metadata = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
            metadata.edit().putString("FlutterSecureSAlgorithmKey", cbc ? "RSA_ECB_PKCS1Padding" : "RSA_ECB_OAEPwithSHA_256andMGF1Padding")
                    .putString("FlutterSecureSAlgorithmStorage", cbc ? "AES_CBC_PKCS7Padding" : "AES_GCM_NoPadding")
                    .putBoolean("ENCRYPTED_PREFERENCES_MIGRATED", true).commit();
            StorageCipher original = cbc ? new StorageCipherImplementationAES18(context, oldRsa, null, config)
                    : new StorageCipherImplementationGCM(context, newRsa, null, config);
            data.edit().putString(prefix + "_custom", Base64.encodeToString(original.encrypt(
                    "custom-value".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT))
                    .putString("__androidx_security_crypto_encrypted_prefs_key_keyset__", "test-keyset")
                    .putString("__androidx_security_crypto_encrypted_prefs_value_keyset__", "test-keyset").commit();
            encrypted().edit().putString(prefix + "_jetpack", "jetpack-value").commit();
            storage = newStorage();
        }

        SharedPreferences encrypted() throws Exception {
            Constructor<EncryptedSharedPreferences> constructor = EncryptedSharedPreferences.class.getDeclaredConstructor(
                    String.class, String.class, SharedPreferences.class, Aead.class, DeterministicAead.class);
            constructor.setAccessible(true);
            Context filtered = new LegacyEncryptedPreferencesContext(context, config.getEffectiveDataPrefsName());
            return constructor.newInstance(config.getEffectiveDataPrefsName(), "test-master", filtered.getSharedPreferences(
                    config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE), values, keys);
        }

        FlutterSecureStorage newStorage() {
            return new FlutterSecureStorage(context) {
                @Override
                protected StorageCipherFactory createStorageCipherFactory(NamespacedConfigSource source) {
                    return new StorageCipherFactory(source, config.getPrefOptionKeyCipherAlgorithm(),
                            config.getPrefOptionStorageCipherAlgorithm(), config) {
                        public KeyCipher getSavedKeyCipher(Context ignored) { return oldRsa; }
                        public KeyCipher getCurrentKeyCipher(Context ignored) { return newRsa; }
                    };
                }

                @Override
                protected SharedPreferences initializeEncryptedSharedPreferencesManager(Context ignored) {
                    try {
                        return encrypted();
                    } catch (Exception error) {
                        throw new IllegalStateException(error);
                    }
                }
            };
        }

        void migrateAndVerify() throws Exception {
            migrate();
            assertEquals(Map.of("custom", "custom-value", "jetpack", "jetpack-value"), storage.readAll());
            storage.recordMigrationVerification();
        }

        void migrate() throws Exception {
            Exception[] failure = {null};
            boolean[] initialized = {false};
            storage.initializeCustomStorage(config, new SecurePreferencesCallback<Void>() {
                public void onSuccess(Void unused) { initialized[0] = true; }
                public void onError(Exception error) { failure[0] = error; }
            });
            if (failure[0] != null) {
                throw failure[0];
            }
            assertTrue(initialized[0]);
            storage.copyLegacyEncryptedEntries();
        }

        void assertReopened() throws Exception {
            Map<String, Object> options = new HashMap<>();
            options.put("storageNamespace", config.getStorageNamespace());
            com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig currentConfig =
                    new com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig(options);
            com.it_nomads.fluttersecurestorage.ciphers.StorageCipher reopened =
                    new com.it_nomads.fluttersecurestorage.ciphers.StorageCipherImplementationGCM(
                            context, newRsa, null, currentConfig);
            assertEquals("custom-value", new String(reopened.decrypt(Base64.decode(data.getString(prefix + "_custom", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
            assertEquals("jetpack-value", new String(reopened.decrypt(Base64.decode(data.getString(prefix + "_jetpack", null), Base64.DEFAULT)), StandardCharsets.UTF_8));
        }
    }

    private static final class RsaWrapper implements KeyCipher, com.it_nomads.fluttersecurestorage.ciphers.KeyCipher {
        final KeyPair pair;
        final String transformation;

        RsaWrapper(String transformation) throws Exception {
            this.transformation = transformation;
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            pair = generator.generateKeyPair();
        }

        public Cipher getCipher(Context context) { return null; }
        public void deleteKey() {}
        public byte[] wrap(Key key) throws Exception {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.WRAP_MODE, pair.getPublic());
            return cipher.wrap(key);
        }
        public Key unwrap(byte[] key, String algorithm) throws Exception {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.UNWRAP_MODE, pair.getPrivate());
            return cipher.unwrap(key, algorithm, Cipher.SECRET_KEY);
        }
    }
}
