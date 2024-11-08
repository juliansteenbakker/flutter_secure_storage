package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.x500.X500Principal;

public class RSACipherOAEPImplementation extends RSACipher18Implementation {

    public RSACipherOAEPImplementation(Context context) throws Exception {
        super(context);
    }

    @Override
    protected String createKeyAlias() {
        return context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP";
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected AlgorithmParameterSpec makeAlgorithmParameterSpec(Context context, Calendar start, Calendar end) {
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                .setCertificateSubject(new X500Principal("CN=" + keyAlias))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setCertificateSerialNumber(BigInteger.valueOf(1))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime());
        return builder.build();
    }

    @Override
    protected Cipher getRSACipher() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPPadding", "AndroidKeyStoreBCWorkaround");
    }

    protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }
}
