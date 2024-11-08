package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

class RSACipher18Implementation implements KeyCipher {

    private static final String KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore";
    private static final String TYPE_RSA = "RSA";
    protected final String keyAlias;
    protected final Context context;


    public RSACipher18Implementation(Context context) throws Exception {
        this.context = context;
        keyAlias = createKeyAlias();
        createRSAKeysIfNeeded(context);
    }

    protected String createKeyAlias() {
        return context.getPackageName() + ".FlutterSecureStoragePluginKey";
    }

    @Override
    public byte[] wrap(Key key) throws Exception {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = getRSACipher();
        cipher.init(Cipher.WRAP_MODE, publicKey, getAlgorithmParameterSpec());

        return cipher.wrap(key);
    }

    @Override
    public Key unwrap(byte[] wrappedKey, String algorithm) throws Exception {
        PrivateKey privateKey = getPrivateKey();
        Cipher cipher = getRSACipher();
        cipher.init(Cipher.UNWRAP_MODE, privateKey, getAlgorithmParameterSpec());

        return cipher.unwrap(wrappedKey, algorithm, Cipher.SECRET_KEY);
    }

    private PrivateKey getPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Key key = ks.getKey(keyAlias, null);
        if (key == null) {
            throw new Exception("No key found under alias: " + keyAlias);
        }

        if (!(key instanceof PrivateKey)) {
            throw new Exception("Not an instance of a PrivateKey");
        }

        return (PrivateKey) key;
    }

    private PublicKey getPublicKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Certificate cert = ks.getCertificate(keyAlias);
        if (cert == null) {
            throw new Exception("No certificate found under alias: " + keyAlias);
        }

        PublicKey key = cert.getPublicKey();
        if (key == null) {
            throw new Exception("No key found under alias: " + keyAlias);
        }

        return key;
    }

    protected Cipher getRSACipher() throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL"); // error in android 6: InvalidKeyException: Need RSA private or public key
        } else {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround"); // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
        }
    }

    protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return null;
    }

    private void createRSAKeysIfNeeded(Context context) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Key privateKey = ks.getKey(keyAlias, null);
        if (privateKey == null) {
            createKeys(context);
        }
    }

    /**
     * Sets default locale.
     */
    private void setLocale(Locale locale) {
        Locale.setDefault(locale);
        Configuration config = context.getResources().getConfiguration();
        config.setLocale(locale);
        context.createConfigurationContext(config);
    }

    private void createKeys(Context context) throws Exception {
        final Locale localeBeforeFakingEnglishLocale = Locale.getDefault();
        try {
            setLocale(Locale.ENGLISH);
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);

            KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(TYPE_RSA, KEYSTORE_PROVIDER_ANDROID);

            AlgorithmParameterSpec spec;

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                spec = makeAlgorithmParameterSpecLegacy(context, start, end);
            } else {
                spec = makeAlgorithmParameterSpec(context, start, end);
            }

            kpGenerator.initialize(spec);
            kpGenerator.generateKeyPair();
        } finally {
            setLocale(localeBeforeFakingEnglishLocale);
        }
    }

    // Flutter gives deprecation warning without suppress
    @SuppressWarnings("deprecation")
    private AlgorithmParameterSpec makeAlgorithmParameterSpecLegacy(Context context, Calendar start, Calendar end) {
        return new android.security.KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyAlias)
                .setSubject(new X500Principal("CN=" + keyAlias))
                .setSerialNumber(BigInteger.valueOf(1))
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    protected AlgorithmParameterSpec makeAlgorithmParameterSpec(Context context, Calendar start, Calendar end) {
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                .setCertificateSubject(new X500Principal("CN=" + keyAlias))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setCertificateSerialNumber(BigInteger.valueOf(1))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime());
        return builder.build();
    }
}
