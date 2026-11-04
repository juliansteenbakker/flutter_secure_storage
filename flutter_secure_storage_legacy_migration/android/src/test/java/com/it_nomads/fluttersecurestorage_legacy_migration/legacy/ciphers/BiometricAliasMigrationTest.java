package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricPrompt;
import android.util.Base64;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.*;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.*;
import org.junit.runner.RunWith;
import org.robolectric.*;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class BiometricAliasMigrationTest {
    @Before public void setup() {
        Security.addProvider(new BouncyCastleProvider());
        Security.removeProvider("AndroidKeyStore");
        Security.addProvider(new Provider("AndroidKeyStore", 1.0, "test alias storage") {{
            put("KeyStore.AndroidKeyStore", AliasStore.class.getName());
        }});
        AliasStore.entries.clear();
        AliasStore.certificates.clear();
    }
    @After public void cleanup() { Security.removeProvider("AndroidKeyStore"); }

    @Test public void cancellationLeavesADurableReadableCheckpoint() throws Exception {
        Fixture fixture = new Fixture("cancel", true);
        assertNotNull(fixture.migrate(true));
        assertEquals("token-value", fixture.readCheckpoint());
        assertEquals("RSA_ECB_OAEPwithSHA_256andMGF1Padding",
                fixture.metadata.getString("FlutterSecureSAlgorithmKey", null));
    }

    @Test public void repeatedCancellationThenSuccessReopensWithVersion11() throws Exception {
        Fixture fixture = new Fixture("repeat", true);
        assertNotNull(fixture.migrate(true));
        assertEquals("token-value", fixture.readCheckpoint());
        assertNotNull(fixture.migrate(true));
        assertEquals("token-value", fixture.readCheckpoint());
        assertNull(fixture.migrate(false));
        assertEquals("token-value", fixture.readWithVersion11());
        assertTrue(AliasStore.entries.get(fixture.pkcsAlias) instanceof SecretKey);
    }

    @Test public void successDoesNotLetLegacyRsaConstructionDeleteTheBiometricKey() throws Exception {
        Fixture fixture = new Fixture("reopen", true);
        assertNull(fixture.migrate(false));
        Key target = AliasStore.entries.get(fixture.pkcsAlias);
        assertTrue(target instanceof SecretKey);
        assertThrows(Exception.class, () -> new Pkcs(fixture.context, fixture.config));
        assertSame(target, AliasStore.entries.get(fixture.pkcsAlias));
        assertEquals("token-value", fixture.readWithVersion11());
    }

    @Test public void sharedRsaAliasSurvivesUntilTheOtherLegacyStoreMigrates() throws Exception {
        Fixture owner = new Fixture("shared-owner", false);
        Fixture sibling = new Fixture("shared-sibling", false);
        Key original = AliasStore.entries.get(owner.pkcsAlias);
        assertNotNull(owner.migrate(false));
        assertSame(original, AliasStore.entries.get(owner.pkcsAlias));
        assertEquals("token-value", owner.readCheckpoint());
        assertEquals("token-value", sibling.readCheckpoint());
        assertNull(sibling.migrateTo(sibling.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"), false));
        assertNull(owner.migrate(false));
        assertEquals("token-value", owner.readWithVersion11());
        assertEquals("token-value", sibling.readCheckpoint());
    }

    @Test public void actualV9GcmStoreCanMigrateToBiometricsAndReopen() throws Exception {
        Fixture fixture = new Fixture("v9-biometric", true, true);
        assertNotNull(fixture.migrate(true));
        assertEquals("token-value", fixture.readCheckpoint());
        assertNull(fixture.migrate(false));
        assertEquals("token-value", fixture.readWithVersion11());
    }

    @Test public void interruptionBeforeBiometricKeyCreationResumesFromOaep() throws Exception {
        Fixture fixture = new Fixture("checkpoint-interruption", true);
        fixture.interruptBeforeBiometric = true;
        assertNotNull(fixture.migrate(false));
        assertEquals("token-value", fixture.readCheckpoint());
        assertNull(AliasStore.entries.get(fixture.pkcsAlias));
        fixture.interruptBeforeBiometric = false;
        assertNull(fixture.migrate(false));
        assertEquals("token-value", fixture.readWithVersion11());
    }

    @Test public void sharedLegacyStoreWithOnlyAnXmlBackupStillProtectsItsRsaKey() throws Exception {
        Fixture owner = new Fixture("backup-owner", false);
        Fixture sibling = new Fixture("backup-sibling", false);
        File source = new File(owner.context.getApplicationInfo().dataDir, "shared_prefs/backup-sibling.xml");
        assertTrue(source.renameTo(new File(source.getPath() + ".bak")));
        Key original = AliasStore.entries.get(owner.pkcsAlias);
        assertNotNull(owner.migrate(false));
        assertSame(original, AliasStore.entries.get(owner.pkcsAlias));
        assertEquals("token-value", sibling.readCheckpoint());
    }

    @Test public void authenticatedCleanupResumesAfterItsStatusWasCommitted() throws Exception {
        Fixture fixture = new Fixture("authenticated-cleanup", true, false, true);
        fixture.stopAfterCleanupStatus = true;
        assertNotNull(fixture.migrate(false));
        assertEquals(MigrationBackup.STATUS_CLEANUP, MigrationBackup.getBackupStatus(fixture.metadata, fixture.config));
        int authentications = fixture.authenticationCalls;
        assertNull(fixture.migrate(false));
        assertEquals(authentications + 1, fixture.authenticationCalls);
        assertEquals("token-value", fixture.readWithVersion11());
        assertFalse(MigrationBackup.hasPendingMigration(fixture.data,
                fixture.context.getSharedPreferences(fixture.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE),
                fixture.metadata, fixture.config));
    }

    @Test public void cancellingCleanupPreservesItsBackupsAndAllowsAnotherRetry() throws Exception {
        Fixture fixture = new Fixture("cancel-cleanup", true, false, true);
        fixture.stopAfterCleanupStatus = true;
        assertNotNull(fixture.migrate(false));
        Map<String, ?> data = new HashMap<>(fixture.data.getAll());
        SharedPreferences keys = fixture.context.getSharedPreferences(fixture.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        Map<String, ?> wrapped = new HashMap<>(keys.getAll());
        int authentications = fixture.authenticationCalls;
        assertNotNull(fixture.migrate(true));
        assertEquals(authentications + 1, fixture.authenticationCalls);
        assertEquals(data, fixture.data.getAll());
        assertEquals(wrapped, keys.getAll());
        assertEquals(MigrationBackup.STATUS_CLEANUP, MigrationBackup.getBackupStatus(fixture.metadata, fixture.config));
        assertNull(fixture.migrate(false));
        assertEquals("token-value", fixture.readWithVersion11());
    }

    @Test public void resettingDefaultStorePreservesSharedLegacyKeys() throws Exception {
        Fixture owner = new Fixture("FlutterSecureStorage", false);
        Fixture sibling = new Fixture("custom-legacy-store", false);
        owner.data.edit().putString(owner.entry, "corrupt-entry").commit();
        Map<String, ?> wrapped = new HashMap<>(owner.context.getSharedPreferences(
                owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).getAll());
        Key rsa = AliasStore.entries.get(owner.pkcsAlias);
        owner.reset(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"));
        assertTrue(owner.data.getAll().isEmpty());
        assertEquals(wrapped, owner.context.getSharedPreferences(
                owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).getAll());
        assertSame(rsa, AliasStore.entries.get(owner.pkcsAlias));
        assertEquals("token-value", sibling.readCheckpoint());
        FlutterSecureStorageConfig target = sibling.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");
        assertNull(sibling.migrateTo(target, false));
        assertEquals("token-value", sibling.readCheckpoint());
        assertNull(owner.migrateTo(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"), false));
        assertEquals("token-value", sibling.readCheckpoint());
    }

    @Test public void resettingDefaultStorePreservesSharedOaepKeys() throws Exception {
        Fixture owner = new Fixture("FlutterSecureStorage", false);
        Fixture sibling = new Fixture("custom-current-store", false);
        FlutterSecureStorageConfig target = sibling.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");
        assertNull(sibling.migrateTo(target, false));
        owner.data.edit().putString(owner.entry, "corrupt-entry").commit();
        Map<String, ?> wrapped = new HashMap<>(owner.context.getSharedPreferences(
                owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).getAll());
        Key oaep = AliasStore.entries.get(owner.context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP");
        owner.reset(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"));
        assertEquals(wrapped, owner.context.getSharedPreferences(
                owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).getAll());
        assertSame(oaep, AliasStore.entries.get(owner.context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP"));
        assertEquals("token-value", sibling.readCheckpoint());
        assertNull(owner.migrateTo(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"), false));
        assertEquals("token-value", sibling.readCheckpoint());
    }

    @Test public void soleDefaultStoreResetClearsItsUnreadableWrappedKeys() throws Exception {
        Fixture owner = new Fixture("FlutterSecureStorage", false);
        owner.context.getSharedPreferences(owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "corrupt-wrapped-key").commit();
        owner.reset(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"));
        assertTrue(owner.context.getSharedPreferences(
                owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).getAll().isEmpty());
        assertFalse(AliasStore.entries.containsKey(owner.pkcsAlias));
        assertNull(owner.migrateTo(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"), false));
    }

    @Test public void namespacedResetDoesNotDeleteAnotherNamespacesKeys() throws Exception {
        Fixture owner = new Fixture("reset-isolated-owner", true);
        Fixture sibling = new Fixture("reset-isolated-sibling", true);
        Key siblingRsa = AliasStore.entries.get(sibling.pkcsAlias);
        owner.reset(owner.config);
        assertTrue(owner.data.getAll().isEmpty());
        assertTrue(owner.context.getSharedPreferences(
                owner.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).getAll().isEmpty());
        assertFalse(AliasStore.entries.containsKey(owner.pkcsAlias));
        assertSame(siblingRsa, AliasStore.entries.get(sibling.pkcsAlias));
        assertEquals("token-value", sibling.readCheckpoint());
    }

    @Test
    @Config(sdk = {24, 25, 26, 27})
    public void pendingBiometricMigrationCompletesWithoutSecurityBelowApi28() throws Exception {
        Fixture fixture = new Fixture("old-api-biometric", true);
        fixture.useNativeAuthentication = true;
        assertNull(fixture.migrate(false));
        assertTrue(fixture.authenticationCalls > 0);
        assertEquals("token-value", fixture.readWithVersion11());
    }

    @Test
    @Config(sdk = {24, 25, 26, 27})
    public void enforcedBiometricsBelowApi28ReturnsAnErrorAndPreservesTheCheckpoint() throws Exception {
        Fixture fixture = new Fixture("old-api-enforced", true, false, true);
        fixture.useNativeAuthentication = true;
        Exception failure = fixture.migrate(false);
        assertNotNull(failure);
        assertEquals("token-value", fixture.readCheckpoint());
    }

    @Test public void sharedRsaAliasSurvivesWhenSiblingHasOnlySeparateBackups() throws Exception {
        Fixture owner = new Fixture("backup-shared-owner", false);
        Fixture sibling = new Fixture("backup-shared-sibling", false);
        SharedPreferences wrapped = sibling.context.getSharedPreferences(
                sibling.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        MigrationBackup.createBackup(sibling.data, wrapped, sibling.metadata, sibling.config,
                sibling.config.getSharedPreferencesKeyPrefix());
        MigrationBackup.deleteOriginalData(sibling.data, wrapped, sibling.metadata,
                sibling.config.getSharedPreferencesKeyPrefix());
        Key original = AliasStore.entries.get(owner.pkcsAlias);
        assertNotNull(owner.migrate(false));
        assertSame(original, AliasStore.entries.get(owner.pkcsAlias));
        assertFalse(sibling.metadata.getDataBackupPreferences().getAll().isEmpty());
        assertNull(sibling.migrateTo(sibling.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"), false));
        assertEquals("token-value", sibling.readCheckpoint());
        assertNull(owner.migrate(false));
        assertEquals("token-value", owner.readWithVersion11());
    }

    @Test public void resetPreservesKeysNeededByAnInterruptedSiblingBackup() throws Exception {
        Fixture owner = new Fixture("FlutterSecureStorage", false);
        Fixture sibling = new Fixture("reset-backup-sibling", false);
        SharedPreferences wrapped = sibling.context.getSharedPreferences(
                sibling.config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        MigrationBackup.createBackup(sibling.data, wrapped, sibling.metadata, sibling.config,
                sibling.config.getSharedPreferencesKeyPrefix());
        MigrationBackup.deleteOriginalData(sibling.data, wrapped, sibling.metadata,
                sibling.config.getSharedPreferencesKeyPrefix());
        assertTrue(sibling.data.getAll().isEmpty());
        Key original = AliasStore.entries.get(owner.pkcsAlias);
        owner.reset(owner.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"));
        assertSame(original, AliasStore.entries.get(owner.pkcsAlias));
        assertNull(sibling.migrateTo(sibling.config.withCipherAlgorithms(
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding"), false));
        assertEquals("token-value", sibling.readCheckpoint());
    }

    private static final class Fixture {
        final Context context = RuntimeEnvironment.getApplication();
        final FlutterSecureStorageConfig config;
        final NamespacedConfigSource metadata;
        final SharedPreferences data;
        final String pkcsAlias;
        final String entry;
        boolean useNativeAuthentication;
        boolean interruptBeforeBiometric;
        boolean stopAfterCleanupStatus;
        int authenticationCalls;
        Fixture(String name, boolean namespaced) throws Exception {
            this(name, namespaced, false);
        }
        Fixture(String name, boolean namespaced, boolean v9Gcm) throws Exception {
            this(name, namespaced, v9Gcm, false);
        }
        Fixture(String name, boolean namespaced, boolean v9Gcm, boolean enforce) throws Exception {
            Map<String, Object> options = new HashMap<>();
            options.put(namespaced ? "storageNamespace" : "sharedPreferencesName", name);
            options.put("keyCipherAlgorithm", "AES_GCM_NoPadding");
            options.put("migrateWithBackup", "true");
            options.put("resetOnError", "false");
            options.put("enforceBiometrics", Boolean.toString(enforce));
            config = new FlutterSecureStorageConfig(options);
            pkcsAlias = context.getPackageName() + ".FlutterSecureStoragePluginKey" + config.getKeyAliasSuffix();
            seedRsa(pkcsAlias);
            metadata = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
            metadata.edit().putString("FlutterSecureSAlgorithmKey", "RSA_ECB_PKCS1Padding")
                    .putString("FlutterSecureSAlgorithmStorage", v9Gcm ? "AES_GCM_NoPadding" : "AES_CBC_PKCS7Padding")
                    .putBoolean("ENCRYPTED_PREFERENCES_MIGRATED", true).commit();
            data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
            entry = config.getSharedPreferencesKeyPrefix() + "_token";
            StorageCipher old = v9Gcm
                    ? new StorageCipherImplementationGCM(context, new Pkcs(context, config), null, config)
                    : new StorageCipherImplementationAES18(context, new Pkcs(context, config), null, config);
            if (v9Gcm) {
                SharedPreferences wrapped = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
                wrapped.edit().putString(StorageCipherImplementationGCM.LEGACY_V9_KEY,
                        wrapped.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null))
                        .remove(StorageCipherImplementationGCM.WRAPPED_KEY_PREF).commit();
            }
            data.edit().putString(entry, Base64.encodeToString(old.encrypt(
                    "token-value".getBytes(StandardCharsets.UTF_8)), Base64.DEFAULT)).commit();
        }
        void reset(FlutterSecureStorageConfig target) throws Exception {
            Method reset = com.it_nomads.fluttersecurestorage_legacy_migration.FlutterSecureStorageLegacyMigrationPlugin.class
                    .getDeclaredMethod("resetStorage", Context.class, FlutterSecureStorageConfig.class,
                            SharedPreferences.class, SharedPreferences.class);
            reset.setAccessible(true);
            reset.invoke(new com.it_nomads.fluttersecurestorage_legacy_migration.FlutterSecureStorageLegacyMigrationPlugin(),
                    context, target, data, context.getSharedPreferences(
                            "FlutterSecureStorageLegacyMigrationBackup:" + target.getEffectiveDataPrefsName(),
                            Context.MODE_PRIVATE));
        }
        Exception migrate(boolean cancel) throws Exception {
            return migrateTo(config, cancel);
        }
        Exception migrateTo(FlutterSecureStorageConfig target, boolean cancel) throws Exception {
            Exception[] failure = {null};
            boolean[] complete = {false};
            android.content.ContextWrapper operationContext = new android.content.ContextWrapper(context) {
                public Context getApplicationContext() { return this; }
                public SharedPreferences getSharedPreferences(String name, int mode) {
                    SharedPreferences original = super.getSharedPreferences(name, mode);
                    if (!name.equals("FlutterSecureStorageConfiguration:" + config.getEffectiveDataPrefsName())) {
                        return original;
                    }
                    return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                            new Class<?>[]{SharedPreferences.class}, (proxy, method, arguments) -> {
                                Object value = method.invoke(original, arguments);
                                if (!method.getName().equals("edit")) { return value; }
                                SharedPreferences.Editor editor = (SharedPreferences.Editor) value;
                                return Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                                        new Class<?>[]{SharedPreferences.Editor.class}, (editorProxy, editMethod, editArguments) -> {
                                            Object result = editMethod.invoke(editor, editArguments);
                                            if (editMethod.getName().equals("commit") && Boolean.TRUE.equals(result)
                                                    && stopAfterCleanupStatus
                                                    && AliasStore.entries.get(pkcsAlias) instanceof SecretKey
                                                    && MigrationBackup.STATUS_CLEANUP.equals(MigrationBackup.getBackupStatus(metadata, config))) {
                                                stopAfterCleanupStatus = false;
                                                throw new IllegalStateException("Process stopped after persisting cleanup status");
                                            }
                                            return result instanceof SharedPreferences.Editor ? editorProxy : result;
                                        });
                            });
                }
            };
            FlutterSecureStorage storage = new FlutterSecureStorage(operationContext) {
                protected StorageCipherFactory createStorageCipherFactory(NamespacedConfigSource source) {
                    try {
                        Field field = FlutterSecureStorage.class.getDeclaredField("config");
                        field.setAccessible(true);
                        FlutterSecureStorageConfig active = (FlutterSecureStorageConfig) field.get(this);
                        return new StorageCipherFactory(source, active.getPrefOptionKeyCipherAlgorithm(),
                                active.getPrefOptionStorageCipherAlgorithm(), active) {
                            public KeyCipher getSavedKeyCipher(Context ignored) throws Exception {
                                return key(getSavedKeyAlgorithm(), active);
                            }
                            public KeyCipher getCurrentKeyCipher(Context ignored) throws Exception {
                                return key(getCurrentKeyAlgorithm(), active);
                            }
                        };
                    } catch (Exception error) { throw new IllegalStateException(error); }
                }
                protected void authenticateUser(Cipher cipher,
                        SecurePreferencesCallback<BiometricPrompt.AuthenticationResult> callback) throws Exception {
                    authenticationCalls++;
                    if (useNativeAuthentication) {
                        super.authenticateUser(cipher, callback);
                        return;
                    }
                    try {
                        if (MigrationBackup.STATUS_CLEANUP.equals(MigrationBackup.getBackupStatus(metadata, config))) {
                            assertEquals("token-value", readWithVersion11());
                        } else {
                            assertEquals("token-value", readCheckpoint());
                        }
                        if (cancel) { callback.onError(new IOException("Authentication cancelled")); }
                        else { callback.onSuccess(null); }
                    } catch (Exception error) { callback.onError(error); }
                }
            };
            storage.initializeCustomStorage(target, new SecurePreferencesCallback<Void>() {
                public void onSuccess(Void ignored) { complete[0] = true; }
                public void onError(Exception error) { failure[0] = error; }
            });
            assertTrue(complete[0] || failure[0] != null);
            return failure[0];
        }
        KeyCipher key(KeyCipherAlgorithm algorithm, FlutterSecureStorageConfig active) throws Exception {
            if (algorithm == KeyCipherAlgorithm.AES_GCM_NoPadding) {
                if (interruptBeforeBiometric) { throw new IOException("Process stopped before biometric key creation"); }
                return new Aes(context, active);
            }
            if (algorithm == KeyCipherAlgorithm.RSA_ECB_PKCS1Padding) { return new Pkcs(context, active); }
            seedRsa(context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP" + active.getKeyAliasSuffix());
            return new Oaep(context, active);
        }
        String readCheckpoint() throws Exception {
            StorageCipherFactory factory = new StorageCipherFactory(metadata, config.getPrefOptionKeyCipherAlgorithm(),
                    config.getPrefOptionStorageCipherAlgorithm(), config);
            KeyCipher wrapping = key(factory.getSavedKeyAlgorithm(), config);
            StorageCipher cipher = "AES_CBC_PKCS7Padding".equals(metadata.getString("FlutterSecureSAlgorithmStorage", null))
                    ? new StorageCipherImplementationAES18(context, wrapping, null, config)
                    : new StorageCipherImplementationGCM(context, wrapping, null, config);
            return new String(cipher.decrypt(Base64.decode(data.getString(entry, null), Base64.DEFAULT)), StandardCharsets.UTF_8);
        }
        String readWithVersion11() throws Exception {
            Map<String, Object> options = new HashMap<>();
            if (config.hasStorageNamespace()) {
                options.put("storageNamespace", config.getStorageNamespace());
            } else {
                options.put("sharedPreferencesName", config.getEffectiveDataPrefsName());
            }
            options.put("keyCipherAlgorithm", "AES_GCM_NoPadding");
            com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig current =
                    new com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig(options);
            Class<?> type = Class.forName("com.it_nomads.fluttersecurestorage.ciphers.KeyCipherImplementationAES23");
            Constructor<?> constructor = type.getDeclaredConstructor(Context.class, current.getClass());
            constructor.setAccessible(true);
            com.it_nomads.fluttersecurestorage.ciphers.KeyCipher wrapping =
                    (com.it_nomads.fluttersecurestorage.ciphers.KeyCipher) constructor.newInstance(context, current);
            com.it_nomads.fluttersecurestorage.ciphers.StorageCipher cipher =
                    new com.it_nomads.fluttersecurestorage.ciphers.StorageCipherImplementationAES23(
                            context, wrapping, wrapping.getCipher(context), current);
            return new String(cipher.decrypt(Base64.decode(data.getString(entry, null), Base64.DEFAULT)), StandardCharsets.UTF_8);
        }
    }
    private static class Pkcs extends KeyCipherImplementationRSA18 {
        Pkcs(Context context, FlutterSecureStorageConfig config) throws Exception { super(context, config); }
        protected Cipher getRSACipher() throws Exception { return Cipher.getInstance("RSA/ECB/PKCS1Padding"); }
    }
    private static class Oaep extends KeyCipherImplementationRSAOAEP {
        Oaep(Context context, FlutterSecureStorageConfig config) throws Exception { super(context, config); }
        protected Cipher getRSACipher() throws Exception { return Cipher.getInstance("RSA/ECB/OAEPPadding"); }
    }
    private static class Aes extends KeyCipherImplementationAES23 {
        Aes(Context context, FlutterSecureStorageConfig config) throws Exception { super(context, config); }
        public void generateSymmetricKey() throws Exception {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            AliasStore.entries.put(keyAlias, generator.generateKey());
        }
    }
    private static void seedRsa(String alias) throws Exception {
        if (AliasStore.entries.containsKey(alias)) { return; }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        AliasStore.entries.put(alias, pair.getPrivate());
        AliasStore.certificates.put(alias, new Certificate("X.509") {
            public byte[] getEncoded() { return new byte[0]; }
            public void verify(PublicKey key) {}
            public void verify(PublicKey key, String provider) {}
            public String toString() { return "test certificate"; }
            public PublicKey getPublicKey() { return pair.getPublic(); }
        });
    }
    public static final class AliasStore extends KeyStoreSpi {
        static final Map<String, Key> entries = new HashMap<>();
        static final Map<String, Certificate> certificates = new HashMap<>();
        public Key engineGetKey(String alias, char[] password) { return entries.get(alias); }
        public Certificate[] engineGetCertificateChain(String alias) { return new Certificate[]{certificates.get(alias)}; }
        public Certificate engineGetCertificate(String alias) { return certificates.get(alias); }
        public Date engineGetCreationDate(String alias) { return new Date(0); }
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) { entries.put(alias, key); }
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) { throw new UnsupportedOperationException(); }
        public void engineSetCertificateEntry(String alias, Certificate certificate) { certificates.put(alias, certificate); }
        public void engineDeleteEntry(String alias) { entries.remove(alias); certificates.remove(alias); }
        public Enumeration<String> engineAliases() { return Collections.enumeration(entries.keySet()); }
        public boolean engineContainsAlias(String alias) { return entries.containsKey(alias); }
        public int engineSize() { return entries.size(); }
        public boolean engineIsKeyEntry(String alias) { return entries.containsKey(alias); }
        public boolean engineIsCertificateEntry(String alias) { return certificates.containsKey(alias); }
        public String engineGetCertificateAlias(Certificate certificate) { return null; }
        public void engineStore(OutputStream output, char[] password) {}
        public void engineLoad(InputStream input, char[] password) {}
    }
}
