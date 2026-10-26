package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage.ciphers.KeyCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherImplementationGCM;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * encryptedSharedPreferences=true with migrateOnAlgorithmChange=false, after
 * EncryptedSharedPreferences failed to initialize: the store runs on the plain
 * SharedPreferences file, so values must still go through the storage cipher.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class FlutterSecureStorageFallbackTest {

    private static final String KEY = "accessToken";
    private static final String VALUE = "secret-token";

    /** Round-trips raw key bytes so the storage cipher runs without Android KeyStore. */
    private static class FakeKeyCipher implements KeyCipher {
        @Override
        public byte[] wrap(Key key) {
            return key.getEncoded();
        }

        @Override
        public Key unwrap(byte[] wrappedKey, String algorithm) {
            return new SecretKeySpec(wrappedKey, algorithm);
        }

        @Override
        public Cipher getCipher(Context context) {
            return null;
        }

        @Override
        public void deleteKey() {
        }
    }

    private SharedPreferences plainPreferences;
    private StorageCipher storageCipher;
    private FlutterSecureStorage storage;

    @Before
    public void setUp() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Map<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_ENCRYPTED_SHARED_PREFERENCES, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, "false");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "false");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);

        plainPreferences = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        storageCipher = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, config);
        storage = new FlutterSecureStorage(context, config, plainPreferences, storageCipher);
    }

    @Test
    public void write_encryptsValueOnPlainFallback() throws Exception {
        String prefixedKey = storage.addPrefixToKey(KEY);

        storage.write(prefixedKey, VALUE);

        String stored = plainPreferences.getString(prefixedKey, null);
        assertFalse("value was stored in plain text", VALUE.equals(stored));
        String decrypted = new String(storageCipher.decrypt(Base64.decode(stored, 0)), StandardCharsets.UTF_8);
        assertEquals(VALUE, decrypted);
    }

    @Test
    public void read_decryptsValueOnPlainFallback() throws Exception {
        String prefixedKey = storage.addPrefixToKey(KEY);
        storeEncrypted(prefixedKey, VALUE);

        assertEquals(VALUE, storage.read(prefixedKey));
    }

    @Test
    public void readAll_decryptsValuesOnPlainFallback() throws Exception {
        storeEncrypted(storage.addPrefixToKey(KEY), VALUE);

        assertEquals(VALUE, storage.readAll().get(KEY));
    }

    private void storeEncrypted(String prefixedKey, String value) throws Exception {
        byte[] encrypted = storageCipher.encrypt(value.getBytes(StandardCharsets.UTF_8));
        plainPreferences.edit().putString(prefixedKey, Base64.encodeToString(encrypted, 0)).commit();
    }
}
