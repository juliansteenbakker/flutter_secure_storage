package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class RsaResetIntegrationTest {
    private static final Map<String, KeyPair> KEYS = new HashMap<>();
    private static final List<String> EVENTS = new ArrayList<>();
    private static String hiddenPrivateKeyAlias;
    private Provider originalStore;
    private Provider originalCipher;
    private int originalStorePosition;
    private int originalCipherPosition;

    @Before public void installProviders() {
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            if (providers[i].getName().equals("AndroidKeyStore")) {
                originalStore = providers[i];
                originalStorePosition = i + 1;
            } else if (providers[i].getName().equals("AndroidKeyStoreBCWorkaround")) {
                originalCipher = providers[i];
                originalCipherPosition = i + 1;
            }
        }
        Security.removeProvider("AndroidKeyStore");
        Security.removeProvider("AndroidKeyStoreBCWorkaround");
        Security.addProvider(new FakeStoreProvider());
        Security.addProvider(new FakeCipherProvider());
        KEYS.clear();
        EVENTS.clear();
        hiddenPrivateKeyAlias = null;
    }

    @After public void restoreProviders() {
        Security.removeProvider("AndroidKeyStore");
        Security.removeProvider("AndroidKeyStoreBCWorkaround");
        if (originalStore != null && originalCipher != null && originalCipherPosition < originalStorePosition) {
            Security.insertProviderAt(originalCipher, originalCipherPosition);
            Security.insertProviderAt(originalStore, originalStorePosition);
        } else {
            if (originalStore != null) Security.insertProviderAt(originalStore, originalStorePosition);
            if (originalCipher != null) Security.insertProviderAt(originalCipher, originalCipherPosition);
        }
    }

    @Test public void resetsCertificateOnlyAliasWithoutMigration() throws Exception { verifyReset(false, false); }
    @Test public void resetsCertificateOnlyAliasWithMigration() throws Exception { verifyReset(true, false); }
    @Test public void resetsNamespacedAliasWithoutMigration() throws Exception { verifyReset(false, true); }
    @Test public void resetsNamespacedAliasWithMigration() throws Exception { verifyReset(true, true); }
    @Test public void retriesExistingDataWithoutMigration() throws Exception { verifyRetry(false); }
    @Test public void retriesExistingDataWithMigration() throws Exception { verifyRetry(true); }

    private void verifyReset(boolean migrate, boolean namespaced) throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        Map<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "true");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, Boolean.toString(migrate));
        if (namespaced) options.put(FlutterSecureStorageConfig.PREF_OPTION_STORAGE_NAMESPACE, "reset-fixture");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        String alias = context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP" + config.getKeyAliasSuffix();
        String foreignAlias = alias + ".other";
        KeyPair oldPair = newRsaPair();
        KeyPair foreignPair = newRsaPair();
        KEYS.put(alias, new KeyPair(oldPair.getPublic(), null));
        KEYS.put(foreignAlias, foreignPair);
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit().clear().putString(StorageCipherImplementationGCM.WRAPPED_KEY_PREF, "wrapped").commit();
        context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE)
                .edit().clear().commit();

        FlutterSecureStorage storage = new FlutterSecureStorage(context);
        RecordingCallback<Void> initialized = new RecordingCallback<>();
        storage.initialize(config, initialized);
        initialized.assertSuccess();
        assertEquals(2, EVENTS.size());
        assertEquals("delete:" + alias, EVENTS.get(0));
        assertEquals("generate:" + alias, EVENTS.get(1));
        assertEquals(foreignPair, KEYS.get(foreignAlias));
        assertNotNull(KEYS.get(alias).getPrivate());

        String key = storage.addPrefixToKey("synthetic");
        RecordingCallback<Void> written = new RecordingCallback<>();
        storage.write(key, "value", written);
        written.assertSuccess();
        RecordingCallback<String> read = new RecordingCallback<>();
        storage.read(key, read);
        read.assertSuccess();
        assertEquals("value", read.value);
        assertEquals(2, EVENTS.size());
    }

    private static KeyPair newRsaPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private void verifyRetry(boolean migrate) {
        Context context = RuntimeEnvironment.getApplication();
        Map<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_DELETE_ON_FAILURE, "false");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, Boolean.toString(migrate));
        options.put(FlutterSecureStorageConfig.PREF_OPTION_STORAGE_NAMESPACE, "retry-fixture");
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE).edit().clear().commit();
        context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE).edit().clear().commit();
        String alias = context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP" + config.getKeyAliasSuffix();

        FlutterSecureStorage original = new FlutterSecureStorage(context);
        RecordingCallback<Void> first = new RecordingCallback<>();
        original.initialize(config, first);
        first.assertSuccess();
        String key = original.addPrefixToKey("synthetic");
        RecordingCallback<Void> written = new RecordingCallback<>();
        original.write(key, "value", written);
        written.assertSuccess();
        assertEquals(Collections.singletonList("generate:" + alias), EVENTS);

        hiddenPrivateKeyAlias = alias;
        RecordingCallback<Void> failed = new RecordingCallback<>();
        new FlutterSecureStorage(context).initialize(config, failed);
        assertEquals(1, failed.calls);
        assertNotNull(failed.error);
        assertEquals(Collections.singletonList("generate:" + alias), EVENTS);

        hiddenPrivateKeyAlias = null;
        FlutterSecureStorage retry = new FlutterSecureStorage(context);
        RecordingCallback<Void> initialized = new RecordingCallback<>();
        retry.initialize(config, initialized);
        initialized.assertSuccess();
        RecordingCallback<String> read = new RecordingCallback<>();
        retry.read(key, read);
        read.assertSuccess();
        assertEquals("value", read.value);
        assertEquals(Collections.singletonList("generate:" + alias), EVENTS);
    }

    private static final class RecordingCallback<T> implements SecurePreferencesCallback<T> {
        int calls;
        T value;
        Exception error;
        @Override public void onSuccess(T value) { calls++; this.value = value; }
        @Override public void onError(Exception error) { calls++; this.error = error; }
        void assertSuccess() {
            assertEquals(1, calls);
            assertNull(error);
        }
    }

    public static final class FakeStoreProvider extends Provider {
        public FakeStoreProvider() {
            super("AndroidKeyStore", 1.0, "Stateful test keystore");
            put("KeyStore.AndroidKeyStore", FakeKeyStore.class.getName());
            put("KeyPairGenerator.RSA", FakeKeyPairGenerator.class.getName());
        }
    }

    public static final class FakeCipherProvider extends Provider {
        public FakeCipherProvider() {
            super("AndroidKeyStoreBCWorkaround", 1.0, "Test RSA cipher");
            put("Cipher.RSA/ECB/OAEPPadding", FakeRsaCipher.class.getName());
        }
    }

    public static final class FakeKeyPairGenerator extends KeyPairGeneratorSpi {
        private String alias;
        @Override public void initialize(int size, SecureRandom random) { throw new UnsupportedOperationException(); }
        @Override public void initialize(AlgorithmParameterSpec spec, SecureRandom random) {
            alias = ((KeyGenParameterSpec) spec).getKeystoreAlias();
        }
        @Override public KeyPair generateKeyPair() {
            try {
                KeyPair pair = newRsaPair();
                KEYS.put(alias, pair);
                EVENTS.add("generate:" + alias);
                return pair;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static final class FakeKeyStore extends KeyStoreSpi {
        @Override public Key engineGetKey(String alias, char[] password) {
            if (alias.equals(hiddenPrivateKeyAlias)) return null;
            KeyPair pair = KEYS.get(alias);
            return pair == null ? null : pair.getPrivate();
        }
        @Override public Certificate engineGetCertificate(String alias) {
            KeyPair pair = KEYS.get(alias);
            if (pair == null || pair.getPublic() == null) return null;
            PublicKey publicKey = pair.getPublic();
            return new Certificate("synthetic") {
                @Override public byte[] getEncoded() { return publicKey.getEncoded(); }
                @Override public void verify(PublicKey key) {}
                @Override public void verify(PublicKey key, String provider) {}
                @Override public String toString() { return "synthetic"; }
                @Override public PublicKey getPublicKey() { return publicKey; }
            };
        }
        @Override public void engineDeleteEntry(String alias) {
            EVENTS.add("delete:" + alias);
            KEYS.remove(alias);
        }
        @Override public Certificate[] engineGetCertificateChain(String alias) { return null; }
        @Override public Date engineGetCreationDate(String alias) { return null; }
        @Override public void engineSetKeyEntry(String a, Key k, char[] p, Certificate[] c) {}
        @Override public void engineSetKeyEntry(String a, byte[] k, Certificate[] c) {}
        @Override public void engineSetCertificateEntry(String a, Certificate c) {}
        @Override public Enumeration<String> engineAliases() { return Collections.enumeration(KEYS.keySet()); }
        @Override public boolean engineContainsAlias(String alias) { return KEYS.containsKey(alias); }
        @Override public int engineSize() { return KEYS.size(); }
        @Override public boolean engineIsKeyEntry(String alias) { return KEYS.containsKey(alias); }
        @Override public boolean engineIsCertificateEntry(String alias) { return false; }
        @Override public String engineGetCertificateAlias(Certificate cert) { return null; }
        @Override public void engineStore(OutputStream stream, char[] password) {}
        @Override public void engineLoad(InputStream stream, char[] password) {}
    }

    public static final class FakeRsaCipher extends CipherSpi {
        private final Cipher delegate;
        public FakeRsaCipher() throws Exception { delegate = Cipher.getInstance("RSA/ECB/OAEPPadding", "SunJCE"); }
        @Override protected void engineSetMode(String mode) {}
        @Override protected void engineSetPadding(String padding) {}
        @Override protected int engineGetBlockSize() { return delegate.getBlockSize(); }
        @Override protected int engineGetOutputSize(int inputLen) { return delegate.getOutputSize(inputLen); }
        @Override protected byte[] engineGetIV() { return delegate.getIV(); }
        @Override protected AlgorithmParameters engineGetParameters() { return delegate.getParameters(); }
        @Override protected void engineInit(int mode, Key key, SecureRandom random) throws InvalidKeyException {
            delegate.init(mode, key, random);
        }
        @Override protected void engineInit(int mode, Key key, AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidKeyException, InvalidAlgorithmParameterException { delegate.init(mode, key, params, random); }
        @Override protected void engineInit(int mode, Key key, AlgorithmParameters params, SecureRandom random)
                throws InvalidKeyException, InvalidAlgorithmParameterException { delegate.init(mode, key, params, random); }
        @Override protected byte[] engineUpdate(byte[] input, int offset, int length) {
            return delegate.update(input, offset, length);
        }
        @Override protected int engineUpdate(byte[] input, int offset, int length, byte[] output, int outOffset)
                throws ShortBufferException { return delegate.update(input, offset, length, output, outOffset); }
        @Override protected byte[] engineDoFinal(byte[] input, int offset, int length)
                throws IllegalBlockSizeException, BadPaddingException { return delegate.doFinal(input, offset, length); }
        @Override protected int engineDoFinal(byte[] input, int offset, int length, byte[] output, int outOffset)
                throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
            return delegate.doFinal(input, offset, length, output, outOffset);
        }
        @Override protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
            return delegate.wrap(key);
        }
        @Override protected Key engineUnwrap(byte[] bytes, String algorithm, int type)
                throws InvalidKeyException, NoSuchAlgorithmException { return delegate.unwrap(bytes, algorithm, type); }
    }
}
