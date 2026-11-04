package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.KeyCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherFactory;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherImplementationGCM;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherImplementationAES18;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class GcmKeyMigrationTest {
    @Test
    public void namespacedPkcs1GcmMigrationReopensWithOaepGcm() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Map<String, Object> options = new HashMap<>();
        options.put("storageNamespace", "gcm-key-migration");
        options.put("migrateWithBackup", "true");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        NamespacedConfigSource metadata = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
        metadata.edit().putString("FlutterSecureSAlgorithmKey", "RSA_ECB_PKCS1Padding")
                .putString("FlutterSecureSAlgorithmStorage", "AES_GCM_NoPadding")
                .putBoolean("ENCRYPTED_PREFERENCES_MIGRATED", true).commit();
        SharedPreferences data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        SharedPreferences keys = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        byte[] token = "credential-that-must-survive".getBytes(StandardCharsets.UTF_8);
        String entry = config.getSharedPreferencesKeyPrefix() + "_token";
        StorageCipher oldCipher = new StorageCipherImplementationGCM(context, oldRsa, null, config);
        data.edit().putString(entry, Base64.encodeToString(oldCipher.encrypt(token), Base64.DEFAULT)).commit();
        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        setField(storage, "config", config);
        setField(storage, "storageCipherFactory", new StorageCipherFactory(metadata,
                config.getPrefOptionKeyCipherAlgorithm(), config.getPrefOptionStorageCipherAlgorithm(), config) {
            public KeyCipher getCurrentKeyCipher(Context ignored) {
                return newRsa;
            }

            public KeyCipher getSavedKeyCipher(Context ignored) {
                return oldRsa;
            }
        });
        Exception[] failure = {null};
        Method migrate = FlutterSecureStorage.class.getDeclaredMethod("migrateNonBiometricWithBackup",
                NamespacedConfigSource.class, SharedPreferences.class, SecurePreferencesCallback.class);
        migrate.setAccessible(true);

        migrate.invoke(storage, metadata, data, new SecurePreferencesCallback<Void>() {
            public void onSuccess(Void unused) {}
            public void onError(Exception error) { failure[0] = error; }
        });

        assertNull(failure[0]);
        assertTrue(oldRsa.deleted);
        assertFalse(newRsa.deleted);
        assertFalse(MigrationBackup.hasPendingMigration(data, keys, metadata, config));
        assertFalse(keys.getAll().isEmpty());
        StorageCipher reopened = new StorageCipherImplementationGCM(context, newRsa, null, config);
        assertArrayEquals(token, reopened.decrypt(Base64.decode(data.getString(entry, null), Base64.DEFAULT)));
        StorageCipherFactory reopenedMetadata = new StorageCipherFactory(metadata,
                config.getPrefOptionKeyCipherAlgorithm(), config.getPrefOptionStorageCipherAlgorithm(), config);
        assertFalse(reopenedMetadata.requiresReEncryption());
    }

    @Test
    public void twoSharedCbcStoresMigrateSequentiallyWithoutLosingTheirKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Context context = RuntimeEnvironment.getApplication();
        RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Store first = new Store(context, "first-cbc", false, "AES_CBC_PKCS7Padding", oldRsa, newRsa);
        Store second = new Store(context, "second-cbc", false, "AES_CBC_PKCS7Padding", oldRsa, newRsa);
        first.writeLegacy("token", "first-token");
        second.writeLegacy("token", "second-token");
        Map<String, ?> originalKeys = new HashMap<>(first.keys.getAll());

        assertNull(first.migrate(first.factory()));

        StorageCipher stillLegacy = new StorageCipherImplementationAES18(context, oldRsa, null, second.config);
        assertArrayEquals("second-token".getBytes(StandardCharsets.UTF_8),
                stillLegacy.decrypt(Base64.decode(second.data.getString(second.entry("token"), null), Base64.DEFAULT)));
        for (String key : originalKeys.keySet()) {
            assertEquals(originalKeys.get(key), first.keys.getString(key, null));
        }
        assertNull(second.migrate(second.factory()));
        first.assertReadable("token", "first-token");
        second.assertReadable("token", "second-token");
        assertFalse(oldRsa.deleted);
    }

    @Test
    public void twoSharedGcmStoresRetainTheOriginalKeyAcrossSequentialMigration() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Store first = new Store(context, "first-gcm", false, "AES_GCM_NoPadding", oldRsa, newRsa);
        Store second = new Store(context, "second-gcm", false, "AES_GCM_NoPadding", oldRsa, newRsa);
        first.writeLegacy("token", "first-token");
        second.writeLegacy("token", "second-token");

        assertNull(first.migrate(first.factory()));
        StorageCipher recovered = second.factory().getSavedStorageCipherFromBackup(context, null, second.keys);
        assertArrayEquals("second-token".getBytes(StandardCharsets.UTF_8),
                recovered.decrypt(Base64.decode(second.data.getString(second.entry("token"), null), Base64.DEFAULT)));
        assertNull(second.migrate(second.factory()));

        first.assertReadable("token", "first-token");
        second.assertReadable("token", "second-token");
        assertFalse(oldRsa.deleted);
    }

    @Test
    public void migratingCbcAlsoPreservesTheSharedLegacyGcmKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Context context = RuntimeEnvironment.getApplication();
        RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Store cbc = new Store(context, "mixed-cbc", false, "AES_CBC_PKCS7Padding", oldRsa, newRsa);
        Store gcm = new Store(context, "mixed-gcm", false, "AES_GCM_NoPadding", oldRsa, newRsa);
        cbc.writeLegacy("token", "cbc-token");
        gcm.writeLegacy("token", "gcm-token");

        assertNull(cbc.migrate(cbc.factory()));
        assertNull(gcm.migrate(gcm.factory()));

        cbc.assertReadable("token", "cbc-token");
        gcm.assertReadable("token", "gcm-token");
        assertFalse(oldRsa.deleted);
    }

    @Test
    public void actualV9GcmWrappedPreferenceMigratesToOaep() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Store store = new Store(context, "v9-gcm", true, "AES_GCM_NoPadding",
                new RsaWrapper("RSA/ECB/PKCS1Padding"),
                new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
        store.writeLegacy("token", "v9-token");
        String modern = "AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
        String legacy = "VGhpcyBpcyB0aGUga2V5IGZvcihBIHNlY3XyZZBzdG9yYWdlIEFFUyBLZXkK";
        String wrapped = store.keys.getString(modern, null);
        store.keys.edit().putString(legacy, wrapped).remove(modern).commit();

        assertNull(store.migrate(store.factory()));

        store.assertReadable("token", "v9-token");
        assertEquals(wrapped, store.keys.getString(legacy, null));
    }

    @Test
    public void twoActualV9GcmStoresRemainReadableAfterSequentialMigration() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Store first = new Store(context, "first-v9", false, "AES_GCM_NoPadding", oldRsa, newRsa);
        Store second = new Store(context, "second-v9", false, "AES_GCM_NoPadding", oldRsa, newRsa);
        first.writeLegacy("token", "first-token");
        second.writeLegacy("token", "second-token");
        String modern = "AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
        String legacy = "VGhpcyBpcyB0aGUga2V5IGZvcihBIHNlY3XyZZBzdG9yYWdlIEFFUyBLZXkK";
        String wrapped = first.keys.getString(modern, null);
        first.keys.edit().putString(legacy, wrapped).remove(modern).commit();

        assertNull(first.migrate(first.factory()));
        assertNull(second.migrate(second.factory()));

        first.assertReadable("token", "first-token");
        second.assertReadable("token", "second-token");
        assertEquals(wrapped, first.keys.getString(legacy, null));
        assertFalse(oldRsa.deleted);
    }

    @Test
    public void failedCurrentKeyCommitDoesNotTriggerLegacyKeyReplacement() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Store store = new Store(context, "failed-key-commit", true, "AES_GCM_NoPadding",
                new RsaWrapper("RSA/ECB/PKCS1Padding"),
                new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
        store.writeLegacy("token", "preserved-token");
        Map<String, ?> before = new HashMap<>(store.keys.getAll());
        StorageCipherFactory factory = new StorageCipherFactory(store.metadata,
                store.config.getPrefOptionKeyCipherAlgorithm(), store.config.getPrefOptionStorageCipherAlgorithm(), store.config) {
            public StorageCipher getCurrentStorageCipher(Context ignored, Cipher cipher) {
                throw new IllegalStateException("Could not persist wrapped key");
            }
            public KeyCipher getCurrentKeyCipher(Context ignored) { return store.newRsa; }
            public KeyCipher getSavedKeyCipher(Context ignored) {
                throw new AssertionError("A failed commit must not be handled as a key unwrap failure");
            }
        };
        org.junit.Assert.assertThrows(IllegalStateException.class,
                () -> factory.getCurrentStorageCipherForMigration(context, null));
        assertEquals(before, store.keys.getAll());
    }

    @Test
    public void v9GcmMigrationPreservesAnExistingOaepWrappedKeyFromAnotherStore() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Store store = new Store(context, "v9-with-modern-sibling", false, "AES_GCM_NoPadding",
                new RsaWrapper("RSA/ECB/PKCS1Padding"),
                new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
        store.writeLegacy("token", "v9-token");
        String modern = "AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
        String legacy = "VGhpcyBpcyB0aGUga2V5IGZvcihBIHNlY3XyZZBzdG9yYWdlIEFFUyBLZXkK";
        String old = store.keys.getString(modern, null);
        byte[] currentKey = new byte[16];
        new java.security.SecureRandom().nextBytes(currentKey);
        String currentWrapped = Base64.encodeToString(store.newRsa.wrap(
                new javax.crypto.spec.SecretKeySpec(currentKey, "AES")), Base64.DEFAULT);
        store.keys.edit().putString(legacy, old).putString(modern, currentWrapped).commit();

        assertNull(store.migrate(store.factory()));

        store.assertReadable("token", "v9-token");
        assertEquals(currentWrapped, store.keys.getString(modern, null));
        assertEquals(old, store.keys.getString(legacy, null));
    }

    @Test
    public void emptyLegacyStoreDoesNotRequireAnOldWrappedKey() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Store store = new Store(context, "empty-legacy", true, "AES_GCM_NoPadding",
                new RsaWrapper("RSA/ECB/PKCS1Padding"),
                new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));

        assertNull(store.migrate(store.factory()));

        assertFalse(MigrationBackup.hasPendingMigration(store.data, store.keys, store.metadata, store.config));
        assertFalse(store.factory().requiresReEncryption());
    }

    @Test
    public void repeatedInterruptionsWhileReadingSavedGcmKeyNeverOverwriteTheLiveKey() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        RsaWrapper oldRsa = new RsaWrapper("RSA/ECB/PKCS1Padding");
        RsaWrapper newRsa = new RsaWrapper("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Store store = new Store(context, "partial-gcm", true, "AES_GCM_NoPadding", oldRsa, newRsa);
        store.writeLegacy("first", "first-token");
        store.writeLegacy("second", "second-token");
        MigrationBackup.createBackup(store.data, store.keys, store.metadata,
                store.config, store.config.getSharedPreferencesKeyPrefix());
        StorageCipherFactory initial = store.factory();
        initial.getSavedStorageCipherFromBackup(context, null, store.keys);
        StorageCipher target = initial.getCurrentStorageCipherForMigration(context, null);
        store.data.edit().putString(store.entry("first"),
                Base64.encodeToString(target.encrypt("first-token".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT)).commit();
        store.metadata.edit().putBoolean(store.entry("first") + "_MIGRATED", true).commit();
        Map<String, ?> liveKeys = new HashMap<>(store.keys.getAll());
        StorageCipherFactory interrupted = new StorageCipherFactory(store.metadata,
                store.config.getPrefOptionKeyCipherAlgorithm(), store.config.getPrefOptionStorageCipherAlgorithm(), store.config) {
            public KeyCipher getSavedKeyCipher(Context ignored) { return oldRsa; }
            public KeyCipher getCurrentKeyCipher(Context ignored) { return newRsa; }

            public StorageCipher getSavedStorageCipherFromBackup(Context ignored, Cipher cipher,
                                                                  SharedPreferences keys) throws Exception {
                super.getSavedStorageCipherFromBackup(context, cipher, keys);
                throw new Exception("Interrupted immediately after saved-key initialization");
            }
        };

        assertTrue(store.migrate(interrupted) != null);
        assertEquals(liveKeys, store.keys.getAll());
        store.assertReadable("first", "first-token");
        assertTrue(store.migrate(interrupted) != null);
        assertEquals(liveKeys, store.keys.getAll());
        store.assertReadable("first", "first-token");
        assertNull(store.migrate(store.factory()));

        store.assertReadable("first", "first-token");
        store.assertReadable("second", "second-token");
        assertFalse(MigrationBackup.hasPendingMigration(store.data, store.keys, store.metadata, store.config));
    }

    private static final class Store {
        final Context context;
        final FlutterSecureStorageConfig config;
        final NamespacedConfigSource metadata;
        final SharedPreferences data;
        final SharedPreferences keys;
        final RsaWrapper oldRsa;
        final RsaWrapper newRsa;
        final String legacyAlgorithm;

        Store(Context context, String name, boolean namespaced, String legacyAlgorithm,
              RsaWrapper oldRsa, RsaWrapper newRsa) {
            this.context = context;
            this.oldRsa = oldRsa;
            this.newRsa = newRsa;
            this.legacyAlgorithm = legacyAlgorithm;
            Map<String, Object> options = new HashMap<>();
            options.put(namespaced ? "storageNamespace" : "sharedPreferencesName", name);
            options.put("migrateWithBackup", "true");
            config = new FlutterSecureStorageConfig(options);
            metadata = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
            metadata.edit().putString("FlutterSecureSAlgorithmKey", "RSA_ECB_PKCS1Padding")
                    .putString("FlutterSecureSAlgorithmStorage", legacyAlgorithm)
                    .putBoolean("ENCRYPTED_PREFERENCES_MIGRATED", true).commit();
            data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
            keys = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        }

        String entry(String name) { return config.getSharedPreferencesKeyPrefix() + "_" + name; }

        void writeLegacy(String name, String value) throws Exception {
            StorageCipher cipher;
            if (legacyAlgorithm.equals("AES_CBC_PKCS7Padding")) {
                cipher = new StorageCipherImplementationAES18(context, oldRsa, null, config);
            } else {
                cipher = new StorageCipherImplementationGCM(context, oldRsa, null, config);
            }
            data.edit().putString(entry(name),
                    Base64.encodeToString(cipher.encrypt(value.getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT)).commit();
        }

        StorageCipherFactory factory() {
            return new StorageCipherFactory(metadata, config.getPrefOptionKeyCipherAlgorithm(),
                    config.getPrefOptionStorageCipherAlgorithm(), config) {
                public KeyCipher getSavedKeyCipher(Context ignored) { return oldRsa; }
                public KeyCipher getCurrentKeyCipher(Context ignored) { return newRsa; }
            };
        }

        Exception migrate(StorageCipherFactory factory) throws Exception {
            FlutterSecureStorage storage = new FlutterSecureStorage(context);
            setField(storage, "config", config);
            setField(storage, "storageCipherFactory", factory);
            Exception[] error = {null};
            Method migrate = FlutterSecureStorage.class.getDeclaredMethod("migrateNonBiometricWithBackup",
                    NamespacedConfigSource.class, SharedPreferences.class, SecurePreferencesCallback.class);
            migrate.setAccessible(true);
            migrate.invoke(storage, metadata, data, new SecurePreferencesCallback<Void>() {
                public void onSuccess(Void unused) {}
                public void onError(Exception failure) { error[0] = failure; }
            });
            return error[0];
        }

        void assertReadable(String name, String value) throws Exception {
            Map<String, Object> options = new HashMap<>();
            if (config.hasStorageNamespace()) {
                options.put("storageNamespace", config.getStorageNamespace());
            } else {
                options.put("sharedPreferencesName", config.getEffectiveDataPrefsName());
            }
            com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig current =
                    new com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig(options);
            com.it_nomads.fluttersecurestorage.ciphers.StorageCipher reopened =
                    new com.it_nomads.fluttersecurestorage.ciphers.StorageCipherImplementationGCM(
                            context, newRsa, null, current);
            assertArrayEquals(value.getBytes(StandardCharsets.UTF_8),
                    reopened.decrypt(Base64.decode(data.getString(entry(name), null), Base64.DEFAULT)));
        }
    }

    private static void setField(FlutterSecureStorage storage, String name, Object value) throws Exception {
        Field field = FlutterSecureStorage.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(storage, value);
    }

    private static final class RsaWrapper implements KeyCipher, com.it_nomads.fluttersecurestorage.ciphers.KeyCipher {
        private final KeyPair pair;
        private final String transformation;
        private boolean deleted;

        RsaWrapper(String transformation) throws Exception {
            this.transformation = transformation;
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            pair = generator.generateKeyPair();
        }

        public Cipher getCipher(Context context) { return null; }

        public void deleteKey() { deleted = true; }

        public byte[] wrap(Key key) throws Exception {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.WRAP_MODE, pair.getPublic());
            return cipher.wrap(key);
        }

        public Key unwrap(byte[] input, String algorithm) throws Exception {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.UNWRAP_MODE, pair.getPrivate());
            return cipher.unwrap(input, algorithm, Cipher.SECRET_KEY);
        }
    }
}
