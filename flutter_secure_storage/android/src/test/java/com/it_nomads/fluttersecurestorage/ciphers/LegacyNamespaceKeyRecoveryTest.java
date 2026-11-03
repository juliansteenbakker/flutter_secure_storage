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
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class LegacyNamespaceKeyRecoveryTest {

    private static final String NAME = "FlutterSecureStorage";
    private static final String PLAIN_KEY_PREFS = "FlutterSecureKeyStorage";
    private static final String NS_KEY_PREFS = "FlutterSecureKeyStorage:" + NAME;
    private static final String WRAPPED = StorageCipherImplementationGCM.WRAPPED_KEY_PREF;
    // Default FlutterSecureStorageConfig key prefix.
    private static final String KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    private static final String SAMPLE_KEY_BASE64 = "AAECAwQFBgcICQoLDA0ODw==";

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

    /**
     * Stores a real AES/GCM-encrypted entry so the decrypt-verification step can succeed
     * against it. The key bytes must match what the fake KeyCipher unwraps to.
     */
    private void storeEncryptedData(byte[] aesKeyBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(aesKeyBytes, "AES");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] payload = cipher.doFinal("secret-value".getBytes());
        byte[] combined = new byte[iv.length + payload.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(payload, 0, combined, iv.length, payload.length);
        dataPrefs.edit()
                .putString(KEY_PREFIX + "_token", Base64.encodeToString(combined, Base64.DEFAULT))
                .commit();
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
    public void recoversNamespacedKeyIntoPlainLocation() throws Exception {
        storeKey(namespacedKeyPrefs, SAMPLE_KEY_BASE64);
        storeEncryptedData(Base64.decode(SAMPLE_KEY_BASE64, Base64.DEFAULT));

        assertTrue(run(plainConfig()));

        assertArrayEquals(decode(namespacedKeyPrefs), decode(plainKeyPrefs));
        assertEquals(SAMPLE_KEY_BASE64, namespacedKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void recoverDoesNothingWhenPlainKeyAlreadyPresent() {
        storeKey(plainKeyPrefs, "existing");
        storeKey(namespacedKeyPrefs, SAMPLE_KEY_BASE64);
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
    public void adoptsPlainKeyIntoNamespacedLocation() throws Exception {
        storeKey(plainKeyPrefs, SAMPLE_KEY_BASE64);
        storeEncryptedData(Base64.decode(SAMPLE_KEY_BASE64, Base64.DEFAULT));

        assertTrue(run(namespacedConfig()));

        assertArrayEquals(decode(plainKeyPrefs), decode(namespacedKeyPrefs));
        assertEquals(SAMPLE_KEY_BASE64, plainKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void adoptDoesNothingWhenNamespacedKeyAlreadyPresent() {
        storeKey(plainKeyPrefs, SAMPLE_KEY_BASE64);
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
        storeKey(plainKeyPrefs, SAMPLE_KEY_BASE64);

        assertFalse(run(namespacedConfig()));
        assertNull(namespacedKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void isIdempotent() throws Exception {
        storeKey(namespacedKeyPrefs, SAMPLE_KEY_BASE64);
        storeEncryptedData(Base64.decode(SAMPLE_KEY_BASE64, Base64.DEFAULT));

        assertTrue(run(plainConfig()));
        String afterFirst = plainKeyPrefs.getString(WRAPPED, null);
        assertFalse(run(plainConfig()));
        assertEquals(afterFirst, plainKeyPrefs.getString(WRAPPED, null));
    }

    @Test
    public void publicOverloadReturnsFalseWhenNothingToRecover() {
        storeData();

        assertFalse(LegacyNamespaceKeyRecovery.recoverIfNeeded(context, plainConfig()));
    }

    @Test
    public void rethrowsVirtualMachineError() {
        storeKey(namespacedKeyPrefs, SAMPLE_KEY_BASE64);
        storeData();
        LegacyNamespaceKeyRecovery.KeyCipherProvider oom = c -> {
            throw new OutOfMemoryError("boom");
        };

        try {
            LegacyNamespaceKeyRecovery.recoverIfNeeded(context, plainConfig(), oom);
            fail("expected OutOfMemoryError to propagate");
        } catch (OutOfMemoryError expected) {
            // A VirtualMachineError must not be swallowed.
        }
    }

    @Test
    public void leavesTargetUntouchedWhenUnwrapFails() {
        storeKey(namespacedKeyPrefs, SAMPLE_KEY_BASE64);
        storeData();
        LegacyNamespaceKeyRecovery.KeyCipherProvider failing = c -> {
            throw new IllegalStateException("no key");
        };

        assertFalse(LegacyNamespaceKeyRecovery.recoverIfNeeded(context, plainConfig(), failing));
        assertNull(plainKeyPrefs.getString(WRAPPED, null));
    }

    // -------------------------------------------------------------------------
    // A sibling instance's own, valid key under the same preference name must
    // still be rejected rather than relocated.
    // -------------------------------------------------------------------------

    @Test
    public void rejectsAWrongButValidlyShapedKey() throws Exception {
        byte[] wrongKey = new byte[16];
        java.util.Arrays.fill(wrongKey, (byte) 0xFF);
        storeKey(namespacedKeyPrefs, Base64.encodeToString(wrongKey, Base64.DEFAULT));
        // Real data is encrypted with a DIFFERENT key than the one stored above.
        storeEncryptedData(Base64.decode(SAMPLE_KEY_BASE64, Base64.DEFAULT));

        assertFalse(run(plainConfig()));
        assertNull(plainKeyPrefs.getString(WRAPPED, null));
    }
}
