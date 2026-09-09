package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class LegacyNamespaceKeyRecoveryTest {

    private static final String NAME = "FlutterSecureStorage";
    private static final String PLAIN_KEY_PREFS = "FlutterSecureKeyStorage";
    private static final String NS_KEY_PREFS = "FlutterSecureKeyStorage:" + NAME;
    private static final String WRAPPED = StorageCipherImplementationGCM.WRAPPED_KEY_PREF;
    // Default FlutterSecureStorageConfig key prefix.
    private static final String KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";

    private Context context;
    private SharedPreferences plainKeyPrefs;
    private SharedPreferences namespacedKeyPrefs;
    private SharedPreferences dataPrefs;

    /** Round-trips raw key bytes so recovery runs without Android KeyStore. */
    private static class FakeKeyCipher implements KeyCipher {
        @Override public byte[] wrap(Key key) { return key.getEncoded(); }
        @Override public Key unwrap(byte[] wrappedKey, String algorithm) {
            return new SecretKeySpec(wrappedKey, algorithm);
        }
        @Override public Cipher getCipher(Context context) { return null; }
        @Override public void deleteKey() {}
    }

    private final LegacyNamespaceKeyRecovery.KeyCipherProvider fakeProvider = c -> new FakeKeyCipher();

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        plainKeyPrefs = context.getSharedPreferences(PLAIN_KEY_PREFS, Context.MODE_PRIVATE);
        namespacedKeyPrefs = context.getSharedPreferences(NS_KEY_PREFS, Context.MODE_PRIVATE);
        dataPrefs = context.getSharedPreferences(NAME, Context.MODE_PRIVATE);
        plainKeyPrefs.edit().clear().commit();
        namespacedKeyPrefs.edit().clear().commit();
        dataPrefs.edit().clear().commit();
    }

    private FlutterSecureStorageConfig plainConfig() {
        return new FlutterSecureStorageConfig(new HashMap<>());
    }

    private FlutterSecureStorageConfig namespacedConfig() {
        Map<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_STORAGE_NAMESPACE, NAME);
        return new FlutterSecureStorageConfig(options);
    }

    private void storeKey(SharedPreferences prefs, String base64) {
        prefs.edit().putString(WRAPPED, base64).commit();
    }

    private void storeData() {
        dataPrefs.edit().putString(KEY_PREFIX + "_token", "ciphertext").commit();
    }

    private boolean run(FlutterSecureStorageConfig config) {
        return LegacyNamespaceKeyRecovery.recoverIfNeeded(context, config, fakeProvider);
    }

    private static byte[] decode(SharedPreferences prefs) {
        return Base64.decode(prefs.getString(WRAPPED, null), Base64.DEFAULT);
    }

    // -------------------------------------------------------------------------
    // recover: namespaced -> plain (downgrade)
    // -------------------------------------------------------------------------

    @Test
    public void recoversNamespacedKeyIntoPlainLocation() {
        storeKey(namespacedKeyPrefs, "QUJD");
        storeData();

        assertTrue(run(plainConfig()));

        assertArrayEquals(decode(namespacedKeyPrefs), decode(plainKeyPrefs));
        assertEquals("QUJD", namespacedKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void recoverDoesNothingWhenPlainKeyAlreadyPresent() {
        storeKey(plainKeyPrefs, "existing");
        storeKey(namespacedKeyPrefs, "QUJD");
        storeData();

        assertFalse(run(plainConfig()));
        assertEquals("existing", plainKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void recoverDoesNothingWithoutNamespacedKey() {
        storeData();

        assertFalse(run(plainConfig()));
        assertNull(plainKeyPrefs.getString(WRAPPED, null));
    }

    // -------------------------------------------------------------------------
    // adopt: plain -> namespaced (added storageNamespace over existing data)
    // -------------------------------------------------------------------------

    @Test
    public void adoptsPlainKeyIntoNamespacedLocation() {
        storeKey(plainKeyPrefs, "QUJD");
        storeData();

        assertTrue(run(namespacedConfig()));

        assertArrayEquals(decode(plainKeyPrefs), decode(namespacedKeyPrefs));
        assertEquals("QUJD", plainKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void adoptDoesNothingWhenNamespacedKeyAlreadyPresent() {
        storeKey(plainKeyPrefs, "QUJD");
        storeKey(namespacedKeyPrefs, "existing");
        storeData();

        assertFalse(run(namespacedConfig()));
        assertEquals("existing", namespacedKeyPrefs.getString(WRAPPED, null));
    }

    // -------------------------------------------------------------------------
    // shared guards
    // -------------------------------------------------------------------------

    @Test
    public void doesNothingWhenDataPrefsAreEmpty() {
        storeKey(plainKeyPrefs, "QUJD");

        assertFalse(run(namespacedConfig()));
        assertNull(namespacedKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void isIdempotent() {
        storeKey(namespacedKeyPrefs, "QUJD");
        storeData();

        assertTrue(run(plainConfig()));
        String afterFirst = plainKeyPrefs.getString(WRAPPED, null);
        assertFalse(run(plainConfig()));
        assertEquals(afterFirst, plainKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void leavesTargetUntouchedWhenUnwrapFails() {
        storeKey(namespacedKeyPrefs, "QUJD");
        storeData();
        LegacyNamespaceKeyRecovery.KeyCipherProvider failing = c -> {
            throw new IllegalStateException("no key");
        };

        assertFalse(LegacyNamespaceKeyRecovery.recoverIfNeeded(context, plainConfig(), failing));
        assertNull(plainKeyPrefs.getString(WRAPPED, null));
    }
}
