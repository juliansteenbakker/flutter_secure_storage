package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class StorageCipherGCMImplementation extends StorageCipher18Implementation {

    private static final int AUTHENTICATION_TAG_SIZE = 128;

    public StorageCipherGCMImplementation(Context context, KeyCipher keyCipher) throws Exception {
        super(context, keyCipher);
    }

    @Override
    protected String getAESPreferencesKey() {
        return "VGhpcyBpcyB0aGUga2V5IGZvcihBIHNlY3XyZZBzdG9yYWdlIEFFUyBLZXkK";
    }

    @Override
    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    protected int getIvSize() {
        return 12;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    protected AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
    }

}
