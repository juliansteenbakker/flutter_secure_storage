package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorage;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage.SecurePreferencesCallback;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Collections;
import java.util.HashMap;
import javax.crypto.spec.SecretKeySpec;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class KeyCipherKeyPreservationTest {
    private Provider original;
    private int originalPosition;
    private static int generated;
    private static boolean privateKeyAvailable;
    private static boolean wrongKeyType;
    private static boolean certificateAvailable;
    private static boolean allowGeneration;
    private static boolean detectRepeatedCertificateLookup;
    private static int certificateLookups;
    private static int deleted;
    private static boolean failDeletion;
    private static boolean certificateOnGeneration;
    private static boolean detectRepeatedReset;

    @Before public void installProvider() {
        original = Security.getProvider("AndroidKeyStore");
        if (original != null) {
            Provider[] providers = Security.getProviders();
            for (int i = 0; i < providers.length; i++) {
                if (providers[i] == original) originalPosition = i + 1;
            }
            Security.removeProvider("AndroidKeyStore");
        }
        Security.addProvider(new TestProvider());
        generated = 0;
        privateKeyAvailable = true;
        wrongKeyType = false;
        certificateAvailable = false;
        allowGeneration = false;
        detectRepeatedCertificateLookup = false;
        certificateLookups = 0;
        deleted = 0;
        failDeletion = false;
        certificateOnGeneration = false;
        detectRepeatedReset = false;
    }

    @After public void restoreProvider() {
        Security.removeProvider("AndroidKeyStore");
        if (original != null) Security.insertProviderAt(original, originalPosition);
    }

    @Test public void missingCertificateDoesNotReplaceExistingPrivateKey() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        new KeyCipherImplementationRSAOAEP(context, new FlutterSecureStorageConfig(new HashMap<>()));
        assertEquals(0, generated);
    }

    @Test public void missingPrivateKeyPreservesExistingWrappedKey() {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());
        var preferences = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        preferences.edit().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF,
                "synthetic-wrapped-key").commit();
        privateKeyAvailable = false;

        assertThrows(InvalidKeyException.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
        assertEquals(0, generated);
        assertEquals("synthetic-wrapped-key", preferences.getString(
                StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null));
    }

    @Test public void freshStorageCreatesAKeyPair() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().commit();
        privateKeyAvailable = false;
        allowGeneration = true;

        new KeyCipherImplementationRSAOAEP(context, config);
        assertEquals(1, generated);
    }

    @Test public void missingPrivateKeyPreservesBackupWrappedKey() {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());
        var preferences = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        String backupKey = StorageCipherImplementationGCM.WRAPPED_KEY_PREF + "_BACKUP";
        preferences.edit().clear().putString(backupKey, "synthetic-backup").commit();
        privateKeyAvailable = false;

        assertThrows(InvalidKeyException.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
        assertEquals(0, generated);
        assertEquals("synthetic-backup", preferences.getString(backupKey, null));
    }

    @Test public void missingPrivateKeyPreservesNamespacedWrappedKey() {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_STORAGE_NAMESPACE, "isolated");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        var preferences = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        preferences.edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF,
                "synthetic-namespaced-key").commit();
        privateKeyAvailable = false;

        assertThrows(InvalidKeyException.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
        assertEquals(0, generated);
        assertEquals("synthetic-namespaced-key", preferences.getString(
                StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null));
    }

    @Test public void existingCertificateWithoutPrivateKeyIsNotReplaced() {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().commit();
        privateKeyAvailable = false;
        certificateAvailable = true;

        assertThrows(InvalidKeyException.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
        assertEquals(0, generated);
    }

    @Test public void retryUsesRestoredPrivateKeyWithoutReplacingIt() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());
        var preferences = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        preferences.edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        privateKeyAvailable = false;
        assertThrows(InvalidKeyException.class, () -> new KeyCipherImplementationRSAOAEP(context, config));

        privateKeyAvailable = true;
        new KeyCipherImplementationRSAOAEP(context, config);
        assertEquals(0, generated);
        assertEquals("wrapped", preferences.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null));
    }

    @Test public void wrongKeyTypeIsNotReplaced() {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());
        wrongKeyType = true;
        assertThrows(InvalidKeyException.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
        assertEquals(0, generated);
    }

    @Test public void initializationWithResetDisabledPreservesExistingData() {
        assertResetDisabledPreservesData(false);
    }

    @Test public void initializationWithMigrationAndResetDisabledPreservesExistingData() {
        assertResetDisabledPreservesData(true);
    }

    private void assertResetDisabledPreservesData(boolean migrate) {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "false");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, Boolean.toString(migrate));
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        var keyPrefs = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        var dataPrefs = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        String dataKey = config.getSharedPreferencesKeyPrefix() + "_synthetic";
        keyPrefs.edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        dataPrefs.edit().clear().putString(dataKey, "ciphertext").commit();
        privateKeyAvailable = false;
        Exception[] error = new Exception[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) { throw new AssertionError("Expected failure"); }
            @Override public void onError(Exception e) { error[0] = e; }
        });

        assertNotNull(error[0]);
        assertFalse(error[0].getMessage().contains("call deleteAll()"));
        assertEquals(0, generated);
        assertEquals("wrapped", keyPrefs.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null));
        assertEquals("ciphertext", dataPrefs.getString(dataKey, null));
    }

    @Test public void initializationWithResetEnabledCanClearUnrecoverableData() {
        assertResetEnabledClearsData(false);
    }

    @Test public void initializationWithMigrationAndResetEnabledCanClearUnrecoverableData() {
        assertResetEnabledClearsData(true);
    }

    private void assertResetEnabledClearsData(boolean migrate) {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, Boolean.toString(migrate));
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        var keyPrefs = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        var dataPrefs = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        String dataKey = config.getSharedPreferencesKeyPrefix() + "_synthetic";
        keyPrefs.edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        dataPrefs.edit().clear().putString(dataKey, "ciphertext").commit();
        privateKeyAvailable = false;
        allowGeneration = true;
        Exception[] error = new Exception[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) {}
            @Override public void onError(Exception e) { error[0] = e; }
        });

        assertNull(dataPrefs.getString(dataKey, null));
        assertNull(keyPrefs.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null));
        assertTrue(generated > 0);
        // The synthetic generator does not create a usable certificate for the retry.
        assertNotNull(error[0]);
    }

    @Test public void resetRemovesCertificateWhenPrivateKeyIsUnavailable() {
        assertResetRemovesCertificate(true);
    }

    @Test public void resetRemovesCertificateWithoutWrappedKey() {
        assertResetRemovesCertificate(false);
    }

    private void assertResetRemovesCertificate(boolean hasWrappedKey) {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, "false");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        var keyPrefs = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        keyPrefs.edit().clear().commit();
        if (hasWrappedKey) {
            keyPrefs.edit().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        }
        privateKeyAvailable = false;
        certificateAvailable = true;
        detectRepeatedCertificateLookup = true;
        allowGeneration = true;
        Exception[] error = new Exception[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) {}
            @Override public void onError(Exception e) { error[0] = e; }
        });

        assertTrue(deleted > 0);
        assertTrue(generated > 0);
        assertNotNull(error[0]); // Synthetic generator does not produce a usable certificate.
    }

    @Test public void resetPreservesDataWhenKeystoreDeletionFails() {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, "false");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        var keyPrefs = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        var dataPrefs = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        String dataKey = config.getSharedPreferencesKeyPrefix() + "_synthetic";
        keyPrefs.edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        dataPrefs.edit().clear().putString(dataKey, "ciphertext").commit();
        privateKeyAvailable = false;
        certificateAvailable = true;
        failDeletion = true;
        detectRepeatedCertificateLookup = true;
        Exception[] error = new Exception[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) { throw new AssertionError("Expected failure"); }
            @Override public void onError(Exception e) { error[0] = e; }
        });

        assertNotNull(error[0]);
        assertEquals(0, generated);
        assertEquals("wrapped", keyPrefs.getString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, null));
        assertEquals("ciphertext", dataPrefs.getString(dataKey, null));
    }

    @Test public void resetCanRecoverWhenCertificateAndWrappedKeyAreMissing() {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, "false");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().commit();
        privateKeyAvailable = true;
        certificateAvailable = false;
        allowGeneration = true;
        certificateOnGeneration = true;
        Exception[] error = new Exception[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) {}
            @Override public void onError(Exception e) { error[0] = e; }
        });

        assertTrue(deleted > 0);
        assertTrue(generated > 0);
        assertNotNull(error[0]); // Synthetic certificate has no public key.
    }

    @Test public void missingCertificateDoesNotDeletePrivateKeyWhenResetDisabled() {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "false");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, "false");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().commit();
        privateKeyAvailable = true;
        certificateAvailable = false;
        Exception[] error = new Exception[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) { throw new AssertionError("Expected failure"); }
            @Override public void onError(Exception e) { error[0] = e; }
        });

        assertNotNull(error[0]);
        assertEquals(0, deleted);
        assertEquals(0, generated);
    }

    @Test public void failedResetDoesNotRetryIndefinitely() {
        Context context = RuntimeEnvironment.getApplication();
        var options = new HashMap<String, Object>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, "false");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        privateKeyAvailable = false;
        allowGeneration = true;
        detectRepeatedReset = true;
        Exception[] error = new Exception[1];
        int[] callbackCount = new int[1];

        new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<Void>() {
            @Override public void onSuccess(Void unused) { callbackCount[0]++; throw new AssertionError("Expected failure"); }
            @Override public void onError(Exception e) { callbackCount[0]++; error[0] = e; }
        });

        assertEquals(1, deleted);
        assertEquals(1, callbackCount[0]);
        assertNotNull(error[0]);
    }

    public static final class TestProvider extends Provider {
        public TestProvider() {
            super("AndroidKeyStore", 1.0, "Synthetic keystore for regression tests");
            put("KeyStore.AndroidKeyStore", TestKeyStore.class.getName());
            put("KeyPairGenerator.RSA", TestGenerator.class.getName());
        }
    }

    public static final class TestGenerator extends KeyPairGeneratorSpi {
        @Override public void initialize(int size, SecureRandom random) {}
        @Override public void initialize(AlgorithmParameterSpec spec, SecureRandom random) {}
        @Override public KeyPair generateKeyPair() {
            generated++;
            if (allowGeneration) {
                if (certificateOnGeneration) {
                    privateKeyAvailable = true;
                    certificateAvailable = true;
                }
                return new KeyPair(null, null);
            }
            throw new AssertionError("Existing key must not be replaced");
        }
    }

    public static final class TestKeyStore extends KeyStoreSpi {
        @Override public Key engineGetKey(String alias, char[] password) {
            if (!privateKeyAvailable) return null;
            if (wrongKeyType) return new SecretKeySpec(new byte[16], "AES");
            return new PrivateKey() {
                public String getAlgorithm() { return "RSA"; }
                public String getFormat() { return null; }
                public byte[] getEncoded() { return null; }
            };
        }
        @Override public Certificate engineGetCertificate(String alias) {
            if (detectRepeatedCertificateLookup && ++certificateLookups > 2 && certificateAvailable) {
                throw new AssertionError("Reset retried without removing the existing alias");
            }
            if (!certificateAvailable) return null;
            return new Certificate("synthetic") {
                @Override public byte[] getEncoded() { return new byte[0]; }
                @Override public void verify(PublicKey key) {}
                @Override public void verify(PublicKey key, String provider) {}
                @Override public String toString() { return "synthetic"; }
                @Override public PublicKey getPublicKey() { return null; }
            };
        }
        @Override public Certificate[] engineGetCertificateChain(String alias) { return null; }
        @Override public Date engineGetCreationDate(String alias) { return null; }
        @Override public void engineSetKeyEntry(String a, Key k, char[] p, Certificate[] c) {}
        @Override public void engineSetKeyEntry(String a, byte[] k, Certificate[] c) {}
        @Override public void engineSetCertificateEntry(String a, Certificate c) {}
        @Override public void engineDeleteEntry(String alias) throws KeyStoreException {
            if (failDeletion) throw new KeyStoreException("Synthetic keystore deletion failure");
            if (detectRepeatedReset && deleted > 0) throw new AssertionError("Reset was repeated");
            deleted++;
            certificateAvailable = false;
            privateKeyAvailable = false;
        }
        @Override public Enumeration<String> engineAliases() { return Collections.emptyEnumeration(); }
        @Override public boolean engineContainsAlias(String alias) { return false; }
        @Override public int engineSize() { return 0; }
        @Override public boolean engineIsKeyEntry(String alias) { return false; }
        @Override public boolean engineIsCertificateEntry(String alias) { return false; }
        @Override public String engineGetCertificateAlias(Certificate cert) { return null; }
        @Override public void engineStore(OutputStream stream, char[] password) {}
        @Override public void engineLoad(InputStream stream, char[] password) {}
    }
}
