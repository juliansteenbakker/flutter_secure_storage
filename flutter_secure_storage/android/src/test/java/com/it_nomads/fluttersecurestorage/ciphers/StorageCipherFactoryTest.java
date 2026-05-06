package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage.NamespacedConfigSource;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.util.HashMap;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class StorageCipherFactoryTest {

    // Must match the private constants in StorageCipherFactory
    private static final String PREF_KEY_ALGORITHM     = "FlutterSecureSAlgorithmKey";
    private static final String PREF_STORAGE_ALGORITHM = "FlutterSecureSAlgorithmStorage";
    private static final String NAMESPACED_PREFS_NAME  = "FlutterSecureStorageConfiguration:TestNamespace";

    private NamespacedConfigSource configSource;
    private SharedPreferences namespacedPrefs;
    private FlutterSecureStorageConfig config;

    @Before
    public void setUp() {
        Context context = RuntimeEnvironment.getApplication();
        configSource = new NamespacedConfigSource(context, "TestNamespace");
        namespacedPrefs = context.getSharedPreferences(NAMESPACED_PREFS_NAME, Context.MODE_PRIVATE);
        namespacedPrefs.edit().clear().commit();
        // Clear legacy global config to ensure test isolation
        context.getSharedPreferences("FlutterSecureStorageConfiguration", Context.MODE_PRIVATE).edit().clear().commit();
        config = new FlutterSecureStorageConfig(new HashMap<>());
    }

    private StorageCipherFactory factory(String keyAlg, String storageAlg) {
        return new StorageCipherFactory(configSource, keyAlg, storageAlg, config);
    }

    private void saveAlgorithms(String keyAlg, String storageAlg) {
        configSource.edit()
                .putString(PREF_KEY_ALGORITHM, keyAlg)
                .putString(PREF_STORAGE_ALGORITHM, storageAlg)
                .commit();
    }

    // -------------------------------------------------------------------------
    // First launch — no saved algorithm markers
    // -------------------------------------------------------------------------

    @Test
    public void noSavedMarkers_savedAlgorithmsDefaultToLegacy() {
        // With no markers, saved algorithms are the v9.2.4 defaults.
        // Current is OAEP+GCM, so re-encryption must be required.
        assertTrue(factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .requiresReEncryption());
    }

    @Test
    public void noSavedMarkers_writesCurrentAlgorithmsToPrefs() {
        factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");

        assertEquals("RSA_ECB_OAEPwithSHA_256andMGF1Padding", namespacedPrefs.getString(PREF_KEY_ALGORITHM, null));
        assertEquals("AES_GCM_NoPadding",                     namespacedPrefs.getString(PREF_STORAGE_ALGORITHM, null));
    }

    @Test
    public void noSavedMarkers_withLegacyCurrentAlgorithms_doesNotRequireReEncryption() {
        // App never changed defaults — current == saved legacy defaults, nothing to migrate.
        assertFalse(factory("RSA_ECB_PKCS1Padding", "AES_CBC_PKCS7Padding")
                .requiresReEncryption());
    }

    // -------------------------------------------------------------------------
    // Saved markers present — algorithm change detection
    // -------------------------------------------------------------------------

    @Test
    public void savedMatchesCurrent_doesNotRequireReEncryption() {
        saveAlgorithms("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");

        assertFalse(factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .requiresReEncryption());
    }

    @Test
    public void keyAlgorithmChanged_requiresReEncryption() {
        saveAlgorithms("RSA_ECB_PKCS1Padding", "AES_GCM_NoPadding");

        assertTrue(factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .requiresReEncryption());
    }

    @Test
    public void storageAlgorithmChanged_requiresReEncryption() {
        saveAlgorithms("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_CBC_PKCS7Padding");

        assertTrue(factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .requiresReEncryption());
    }

    // -------------------------------------------------------------------------
    // changedKeyAlgorithm
    // -------------------------------------------------------------------------

    @Test
    public void changedKeyAlgorithm_trueWhenKeyAlgorithmChanged() {
        saveAlgorithms("RSA_ECB_PKCS1Padding", "AES_GCM_NoPadding");

        assertTrue(factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .changedKeyAlgorithm());
    }

    @Test
    public void changedKeyAlgorithm_falseWhenOnlyStorageAlgorithmChanged() {
        saveAlgorithms("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_CBC_PKCS7Padding");

        StorageCipherFactory f = factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");

        assertFalse(f.changedKeyAlgorithm());
        assertTrue(f.requiresReEncryption()); // storage still changed
    }

    @Test
    public void changedKeyAlgorithm_falseWhenNothingChanged() {
        saveAlgorithms("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");

        assertFalse(factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .changedKeyAlgorithm());
    }

    // -------------------------------------------------------------------------
    // Legacy algorithm name compatibility
    // -------------------------------------------------------------------------

    @Test
    public void legacyBiometricKeyName_resolvedToCurrentEnum() {
        saveAlgorithms("AES_GCM_NoPadding_BIOMETRIC", "AES_GCM_NoPadding_BIOMETRIC");

        // Legacy names resolve to the same enum values as current names — no migration needed
        assertFalse(factory("AES_GCM_NoPadding", "AES_GCM_NoPadding")
                .requiresReEncryption());
    }

    @Test
    public void legacyBiometricKeyName_changedKeyAlgorithm_false() {
        saveAlgorithms("AES_GCM_NoPadding_BIOMETRIC", "AES_GCM_NoPadding");

        assertFalse(factory("AES_GCM_NoPadding", "AES_GCM_NoPadding")
                .changedKeyAlgorithm());
    }

    // -------------------------------------------------------------------------
    // storeCurrentAlgorithms
    // -------------------------------------------------------------------------

    @Test
    public void storeCurrentAlgorithms_writesCorrectValues() {
        saveAlgorithms("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");

        Context context = RuntimeEnvironment.getApplication();
        SharedPreferences target = context.getSharedPreferences("TargetPrefs", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = target.edit();

        factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .storeCurrentAlgorithms(editor);
        editor.commit();

        assertEquals("RSA_ECB_OAEPwithSHA_256andMGF1Padding", target.getString(PREF_KEY_ALGORITHM, null));
        assertEquals("AES_GCM_NoPadding",                     target.getString(PREF_STORAGE_ALGORITHM, null));
    }

    // -------------------------------------------------------------------------
    // migrateWithBackup — constructor does not write algorithm markers
    // -------------------------------------------------------------------------

    @Test
    public void noSavedMarkers_migrateWithBackup_doesNotWriteAlgorithmsToPrefs() {
        // When migrateWithBackup=true and no markers exist, the constructor must
        // NOT write the current algorithms (step 7 of the migration flow does that).
        HashMap<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_WITH_BACKUP, "true");
        FlutterSecureStorageConfig backupConfig = new FlutterSecureStorageConfig(options);

        new StorageCipherFactory(configSource,
                "RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding",
                backupConfig);

        assertNull(namespacedPrefs.getString(PREF_KEY_ALGORITHM, null));
        assertNull(namespacedPrefs.getString(PREF_STORAGE_ALGORITHM, null));
    }

    @Test
    public void storeCurrentAlgorithms_doesNotWriteSavedAlgorithms() {
        // Saved = PKCS1/CBC, current = OAEP/GCM — stored values should reflect current, not saved
        saveAlgorithms("RSA_ECB_PKCS1Padding", "AES_CBC_PKCS7Padding");

        Context context = RuntimeEnvironment.getApplication();
        SharedPreferences target = context.getSharedPreferences("TargetPrefs2", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = target.edit();

        factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .storeCurrentAlgorithms(editor);
        editor.commit();

        assertEquals("RSA_ECB_OAEPwithSHA_256andMGF1Padding", target.getString(PREF_KEY_ALGORITHM, null));
        assertEquals("AES_GCM_NoPadding",                     target.getString(PREF_STORAGE_ALGORITHM, null));
    }

    // -------------------------------------------------------------------------
    // createStorageCipher — exercises the three dispatch branches
    // -------------------------------------------------------------------------

    /**
     * Minimal KeyCipher that wraps/unwraps using raw key bytes.
     * Allows StorageCipherImplementation constructors to work without Android KeyStore.
     */
    private static class FakeKeyCipher implements KeyCipher {
        @Override public byte[] wrap(Key key) { return key.getEncoded(); }
        @Override public Key unwrap(byte[] wrappedKey, String algorithm) {
            return new SecretKeySpec(wrappedKey, algorithm);
        }
        @Override public Cipher getCipher(Context context) { return null; }
        @Override public void deleteKey() {}
    }

    @Test
    public void createStorageCipher_gcmAlgorithm_withNonKeyStoreKeyCipher_returnsGcmImplementation()
            throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        StorageCipher result = factory("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding")
                .createStorageCipher(context, new FakeKeyCipher(), null, StorageCipherAlgorithm.AES_GCM_NoPadding);
        assertNotNull(result);
        assertTrue(result instanceof StorageCipherImplementationGCM);
    }

    @Test
    public void createStorageCipher_cbcAlgorithm_returnsCbcImplementation() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        StorageCipher result = factory("RSA_ECB_PKCS1Padding", "AES_GCM_NoPadding")
                .createStorageCipher(context, new FakeKeyCipher(), null, StorageCipherAlgorithm.AES_CBC_PKCS7Padding);
        assertNotNull(result);
        assertTrue(result instanceof StorageCipherImplementationAES18);
    }
}
