package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import java.security.Key;

import javax.crypto.Cipher;

public interface KeyCipher {
    // For symmetric keys
    Cipher getCipher(Context context) throws Exception;

    void deleteKey() throws Exception;

    // For asymmetric keys
    byte[] wrap(Key key) throws Exception;
    Key unwrap(byte[] wrappedKey, String algorithm) throws Exception;
}
