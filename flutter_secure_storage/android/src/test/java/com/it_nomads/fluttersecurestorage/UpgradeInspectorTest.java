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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class UpgradeInspectorTest {

    private static final String PREFS_NAME = "UpgradeInspectorTestData";
    private static final String KEY_PREFIX = "TestPrefix";
    private static final String ALGORITHM_KEY_MARKER = "FlutterSecureSAlgorithmKey";
    private static final String ALGORITHM_STORAGE_MARKER = "FlutterSecureSAlgorithmStorage";

    private Context context;
    private SharedPreferences dataPrefs;
    private NamespacedConfigSource configSource;

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        dataPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        dataPrefs.edit().clear().commit();
        configSource = new NamespacedConfigSource(context, PREFS_NAME);
        configSource.edit().clear().commit();
    }

    private FlutterSecureStorageConfig config(boolean resetOnError) {
        Map<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_NAME, PREFS_NAME);
        options.put(FlutterSecureStorageConfig.PREF_OPTION_PREFIX, KEY_PREFIX);
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, String.valueOf(resetOnError));
        return new FlutterSecureStorageConfig(options);
    }

    private void storeEntry(String key, String value) {
        dataPrefs.edit().putString(KEY_PREFIX + "_" + key, value).commit();
    }

    private void storeMarkers(String keyAlgorithm, String storageAlgorithm) {
        configSource.edit()
                .putString(ALGORITHM_KEY_MARKER, keyAlgorithm)
                .putString(ALGORITHM_STORAGE_MARKER, storageAlgorithm)
                .commit();
    }

    private Map<String, Object> inspect(boolean resetOnError) {
        return UpgradeInspector.inspect(context, config(resetOnError));
    }

    @Test
    public void emptyStorageIsOk() {
        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_OK, status.get("state"));
        assertEquals(UpgradeInspector.REASON_NONE, status.get("reason"));
        assertEquals(0, status.get("entryCount"));
        assertFalse((Boolean) status.get("willDiscardOnNextAccess"));
    }

    @Test
    public void dataWithoutAlgorithmMarkersIsUnreadable() {
        storeEntry("token", "ciphertext");

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertEquals(UpgradeInspector.REASON_MISSING_ALGORITHM_MARKERS, status.get("reason"));
        assertEquals(1, status.get("entryCount"));
        assertTrue((Boolean) status.get("willDiscardOnNextAccess"));
    }

    @Test
    public void encryptedSharedPreferencesStoreIsReportedAsUnreadable() {
        dataPrefs.edit()
                .putString("__androidx_security_crypto_encrypted_prefs_key_keyset__", "keyset")
                .putString("__androidx_security_crypto_encrypted_prefs_value_keyset__", "keyset")
                .putString("AencryptedKeyNameA", "AencryptedValueA")
                .putString("AencryptedKeyNameB", "AencryptedValueB")
                .commit();

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertEquals(UpgradeInspector.REASON_LEGACY_BACKEND_PRESENT, status.get("reason"));
        assertEquals(2, status.get("entryCount"));
        // v11 doesn't delete the Tink store, so a downgrade can still migrate it.
        assertFalse((Boolean) status.get("willDiscardOnNextAccess"));
    }

    @Test
    public void emptyEncryptedSharedPreferencesStoreIsOk() {
        dataPrefs.edit()
                .putString("__androidx_security_crypto_encrypted_prefs_key_keyset__", "keyset")
                .putString("__androidx_security_crypto_encrypted_prefs_value_keyset__", "keyset")
                .commit();

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_OK, status.get("state"));
        assertEquals(0, status.get("entryCount"));
    }

    @Test
    public void resetOnErrorDisabledMeansDataIsNotDiscarded() {
        storeEntry("token", "ciphertext");

        Map<String, Object> status = inspect(false);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertFalse((Boolean) status.get("willDiscardOnNextAccess"));
    }

    @Test
    public void ciphersRemovedInV11AreReportedAsSuch() {
        storeEntry("token", "ciphertext");
        storeMarkers("RSA_ECB_PKCS1Padding", "AES_CBC_PKCS7Padding");

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertEquals(UpgradeInspector.REASON_REMOVED_CIPHER, status.get("reason"));
        assertTrue(((String) status.get("details")).contains("RSA_ECB_PKCS1Padding"));
    }

    @Test
    public void removedStorageCipherAloneIsEnough() {
        storeEntry("token", "ciphertext");
        storeMarkers("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_CBC_PKCS7Padding");

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertEquals(UpgradeInspector.REASON_REMOVED_CIPHER, status.get("reason"));
    }

    @Test
    public void unrecognisedMarkersAreReportedRatherThanThrown() {
        storeEntry("token", "ciphertext");
        storeMarkers("SomethingElseEntirely", "AES_GCM_NoPadding");

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertEquals(UpgradeInspector.REASON_REMOVED_CIPHER, status.get("reason"));
    }

    @Test
    public void authenticatedDataIsNotReadDuringAProbe() {
        storeEntry("token", "ciphertext");
        storeMarkers("AES_GCM_NoPadding", "AES_GCM_NoPadding");

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_UNKNOWN, status.get("state"));
        assertEquals(UpgradeInspector.REASON_AUTHENTICATION_REQUIRED, status.get("reason"));
        assertFalse((Boolean) status.get("willDiscardOnNextAccess"));
    }

    @Test
    public void dataWithoutKeyMaterialIsOrphaned() {
        storeEntry("token", "ciphertext");
        storeMarkers("RSA_ECB_OAEPwithSHA_256andMGF1Padding", "AES_GCM_NoPadding");

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_UNREADABLE, status.get("state"));
        assertEquals(UpgradeInspector.REASON_MISSING_KEY_MATERIAL, status.get("reason"));
    }

    @Test
    public void discardedMarkerIsReportedOnceThenCleared() {
        configSource.edit()
                .putString(UpgradeInspector.DISCARDED_MARKER_KEY, UpgradeInspector.REASON_DECRYPT_FAILED)
                .commit();

        Map<String, Object> first = inspect(true);
        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_DISCARDED, first.get("state"));
        assertEquals(UpgradeInspector.REASON_DECRYPT_FAILED, first.get("reason"));

        Map<String, Object> second = inspect(true);
        assertEquals(UpgradeInspector.STATE_OK, second.get("state"));
        assertNull(configSource.getString(UpgradeInspector.DISCARDED_MARKER_KEY, null));
    }

    @Test
    public void discardedMarkerTakesPrecedenceOverRemainingData() {
        storeEntry("token", "ciphertext");
        configSource.edit()
                .putString(UpgradeInspector.DISCARDED_MARKER_KEY, UpgradeInspector.REASON_DECRYPT_FAILED)
                .commit();

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_LEGACY_DATA_DISCARDED, status.get("state"));
    }

    @Test
    public void backupEntriesAreNotCounted() {
        dataPrefs.edit().putString(KEY_PREFIX + "_token_BACKUP", "ciphertext").commit();

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_OK, status.get("state"));
        assertEquals(0, status.get("entryCount"));
    }

    @Test
    public void entriesOutsideThePrefixAreNotCounted() {
        dataPrefs.edit().putString("SomeOtherPluginKey", "value").commit();

        Map<String, Object> status = inspect(true);

        assertEquals(UpgradeInspector.STATE_OK, status.get("state"));
        assertEquals(0, status.get("entryCount"));
    }

    @Test
    public void allMatchingEntriesAreCounted() {
        storeEntry("token", "a");
        storeEntry("refresh", "b");
        storeEntry("pin", "c");

        Map<String, Object> status = inspect(true);

        assertEquals(3, status.get("entryCount"));
    }

    @Test
    public void inspectingDoesNotWriteAlgorithmMarkers() {
        storeEntry("token", "ciphertext");

        inspect(true);

        assertNull(configSource.getString(ALGORITHM_KEY_MARKER, null));
        assertNull(configSource.getString(ALGORITHM_STORAGE_MARKER, null));
    }

    @Test
    public void inspectingDoesNotTouchStoredData() {
        storeEntry("token", "ciphertext");
        storeMarkers("RSA_ECB_PKCS1Padding", "AES_CBC_PKCS7Padding");

        inspect(true);

        assertEquals("ciphertext", dataPrefs.getString(KEY_PREFIX + "_token", null));
    }
}
