package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class KeyCipherKeyPreservationTest {
    private Provider original;
    private static int generated;
    private static boolean privateKeyAvailable;
    private static boolean certificateAvailable;
    private static boolean allowGeneration;

    @Before public void installProvider() {
        original = Security.getProvider("AndroidKeyStore");
        if (original != null) Security.removeProvider("AndroidKeyStore");
        Security.addProvider(new TestProvider());
        generated = 0;
        privateKeyAvailable = true;
        certificateAvailable = false;
        allowGeneration = false;
    }

    @After public void restoreProvider() {
        Security.removeProvider("AndroidKeyStore");
        if (original != null) Security.addProvider(original);
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

        assertThrows(Exception.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
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

        assertThrows(Exception.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
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

        assertThrows(Exception.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
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

        assertThrows(Exception.class, () -> new KeyCipherImplementationRSAOAEP(context, config));
        assertEquals(0, generated);
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
            if (allowGeneration) return new KeyPair(null, null);
            throw new AssertionError("Existing key must not be replaced");
        }
    }

    public static final class TestKeyStore extends KeyStoreSpi {
        @Override public Key engineGetKey(String alias, char[] password) {
            if (!privateKeyAvailable) return null;
            return new PrivateKey() {
                public String getAlgorithm() { return "RSA"; }
                public String getFormat() { return null; }
                public byte[] getEncoded() { return null; }
            };
        }
        @Override public Certificate engineGetCertificate(String alias) {
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
        @Override public void engineDeleteEntry(String alias) {}
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
