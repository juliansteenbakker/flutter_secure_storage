package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.security.Key;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotEquals;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class StorageCipherTest {

    private Context context;
    private FlutterSecureStorageConfig defaultConfig;

    /**
     * Fake KeyCipher that wraps/unwraps by encoding the raw key bytes.
     * Allows testing StorageCipher without AndroidKeyStore.
     */
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

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        defaultConfig = new FlutterSecureStorageConfig(new HashMap<>());
    }

    // -------------------------------------------------------------------------
    // StorageCipherImplementationGCM
    // -------------------------------------------------------------------------

    @Test
    public void gcm_encryptDecrypt_roundTrip() throws Exception {
        StorageCipherImplementationGCM cipher = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "hello secure world".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = cipher.encrypt(plaintext);
        byte[] decrypted = cipher.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void gcm_encrypt_producesNonEmptyOutput() throws Exception {
        StorageCipherImplementationGCM cipher = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] encrypted = cipher.encrypt("test".getBytes(StandardCharsets.UTF_8));

        assertNotNull(encrypted);
        assertNotEquals(0, encrypted.length);
    }

    @Test
    public void gcm_encrypt_outputDiffersFromInput() throws Exception {
        StorageCipherImplementationGCM cipher = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.encrypt(plaintext);

        // Encrypted bytes must not equal plaintext
        boolean same = java.util.Arrays.equals(plaintext, encrypted);
        assertNotEquals(true, same);
    }

    @Test
    public void gcm_encrypt_differentCallsProduceDifferentCiphertext() throws Exception {
        StorageCipherImplementationGCM cipher = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "same input".getBytes(StandardCharsets.UTF_8);

        byte[] first = cipher.encrypt(plaintext);
        byte[] second = cipher.encrypt(plaintext);

        // GCM uses a random IV each time, so ciphertext must differ
        assertNotEquals(true, java.util.Arrays.equals(first, second));
    }

    @Test
    public void gcm_keyPersistedAcrossInstances() throws Exception {
        // First instance generates and stores the key
        StorageCipherImplementationGCM first = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "persistent key test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = first.encrypt(plaintext);

        // Second instance should load the same key from SharedPreferences
        StorageCipherImplementationGCM second = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] decrypted = second.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void gcm_deleteKey_removesKeyFromPreferences() throws Exception {
        StorageCipherImplementationGCM cipher = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        cipher.deleteKey(context);

        // After deletion, a new instance should generate a fresh key (not throw)
        StorageCipherImplementationGCM fresh = new StorageCipherImplementationGCM(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "after delete".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plaintext, fresh.decrypt(fresh.encrypt(plaintext)));
    }

    // -------------------------------------------------------------------------
    // StorageCipherImplementationAES18
    // -------------------------------------------------------------------------

    @Test
    public void aes18_encryptDecrypt_roundTrip() throws Exception {
        StorageCipherImplementationAES18 cipher = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "hello secure world".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = cipher.encrypt(plaintext);
        byte[] decrypted = cipher.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void aes18_encrypt_producesNonEmptyOutput() throws Exception {
        StorageCipherImplementationAES18 cipher = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] encrypted = cipher.encrypt("test".getBytes(StandardCharsets.UTF_8));

        assertNotNull(encrypted);
        assertNotEquals(0, encrypted.length);
    }

    @Test
    public void aes18_encrypt_outputDiffersFromInput() throws Exception {
        StorageCipherImplementationAES18 cipher = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.encrypt(plaintext);

        assertNotEquals(true, java.util.Arrays.equals(plaintext, encrypted));
    }

    @Test
    public void aes18_encrypt_differentCallsProduceDifferentCiphertext() throws Exception {
        StorageCipherImplementationAES18 cipher = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "same input".getBytes(StandardCharsets.UTF_8);

        byte[] first = cipher.encrypt(plaintext);
        byte[] second = cipher.encrypt(plaintext);

        // CBC uses a random IV each time, so ciphertext must differ
        assertNotEquals(true, java.util.Arrays.equals(first, second));
    }

    @Test
    public void aes18_keyPersistedAcrossInstances() throws Exception {
        // First instance generates and stores the key
        StorageCipherImplementationAES18 first = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "persistent key test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = first.encrypt(plaintext);

        // Second instance should load the same key from SharedPreferences
        StorageCipherImplementationAES18 second = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] decrypted = second.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void aes18_deleteKey_removesKeyFromPreferences() throws Exception {
        StorageCipherImplementationAES18 cipher = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        cipher.deleteKey(context);

        // After deletion, a new instance should generate a fresh key (not throw)
        StorageCipherImplementationAES18 fresh = new StorageCipherImplementationAES18(context, new FakeKeyCipher(), null, defaultConfig);
        byte[] plaintext = "after delete".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plaintext, fresh.decrypt(fresh.encrypt(plaintext)));
    }
}
