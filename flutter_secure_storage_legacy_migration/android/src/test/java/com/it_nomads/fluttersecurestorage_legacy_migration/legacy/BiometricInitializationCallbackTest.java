package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.Context;
import android.hardware.biometrics.BiometricPrompt;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.KeyCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherFactory;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.Map;
import javax.crypto.Cipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class BiometricInitializationCallbackTest {
    @Test
    public void cipherInitializationFailureAfterAuthenticationReturnsOnlyOneError() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(Map.of(
                "storageNamespace", "callback-failure", "keyCipherAlgorithm", "AES_GCM_NoPadding",
                "enforceBiometrics", "true", "migrateWithBackup", "true", "resetOnError", "false"));
        NamespacedConfigSource source = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
        source.edit().putString("FlutterSecureSAlgorithmKey", "AES_GCM_NoPadding")
                .putString("FlutterSecureSAlgorithmStorage", "AES_GCM_NoPadding").commit();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        IOException failure = new IOException("Cannot unwrap biometric application key");
        int[] authentications = {0};
        int[] cipherInitializations = {0};
        FlutterSecureStorage storage = new FlutterSecureStorage(context) {
            public boolean isDeviceSecure() { return true; }
            protected void authenticateUser(Cipher supplied,
                    SecurePreferencesCallback<BiometricPrompt.AuthenticationResult> callback) throws Exception {
                assertSame(cipher, supplied);
                authentications[0]++;
                callback.onSuccess(authenticationResult(cipher));
            }
            protected StorageCipherFactory createStorageCipherFactory(NamespacedConfigSource markers) {
                return new StorageCipherFactory(markers, config.getPrefOptionKeyCipherAlgorithm(),
                        config.getPrefOptionStorageCipherAlgorithm(), config) {
                    public KeyCipher getCurrentKeyCipher(Context ignored) {
                        return new KeyCipher() {
                            public Cipher getCipher(Context ignoredContext) { return cipher; }
                            public void deleteKey() {}
                            public byte[] wrap(Key key) { throw new UnsupportedOperationException(); }
                            public Key unwrap(byte[] wrapped, String algorithm) { throw new UnsupportedOperationException(); }
                        };
                    }
                    public StorageCipher getCurrentStorageCipher(Context ignored, Cipher supplied) throws Exception {
                        assertSame(cipher, supplied);
                        cipherInitializations[0]++;
                        throw failure;
                    }
                };
            }
        };
        Field configField = FlutterSecureStorage.class.getDeclaredField("config");
        configField.setAccessible(true);
        configField.set(storage, config);
        int[] successes = {0};
        int[] errors = {0};
        Method initialize = FlutterSecureStorage.class.getDeclaredMethod("initializeStorageCipher",
                NamespacedConfigSource.class, SecurePreferencesCallback.class);
        initialize.setAccessible(true);
        initialize.invoke(storage, source, new SecurePreferencesCallback<Void>() {
            public void onSuccess(Void unused) { successes[0]++; }
            public void onError(Exception error) {
                assertSame(failure, error);
                errors[0]++;
            }
        });
        assertEquals(1, authentications[0]);
        assertEquals(1, cipherInitializations[0]);
        assertEquals(1, errors[0]);
        assertEquals(0, successes[0]);
    }

    private static BiometricPrompt.AuthenticationResult authenticationResult(Cipher cipher) throws Exception {
        BiometricPrompt.CryptoObject crypto = new BiometricPrompt.CryptoObject(cipher);
        for (Constructor<?> constructor : BiometricPrompt.AuthenticationResult.class.getDeclaredConstructors()) {
            Class<?>[] types = constructor.getParameterTypes();
            Object[] arguments = new Object[types.length];
            boolean hasCrypto = false;
            for (int index = 0; index < types.length; index++) {
                if (types[index].isInstance(crypto)) {
                    arguments[index] = crypto;
                    hasCrypto = true;
                } else if (types[index] == int.class) {
                    arguments[index] = 0;
                }
            }
            if (hasCrypto) {
                constructor.setAccessible(true);
                return (BiometricPrompt.AuthenticationResult) constructor.newInstance(arguments);
            }
        }
        throw new IllegalStateException("Authentication result constructor not found");
    }
}
