package com.it_nomads.fluttersecurestorage.ciphers;

import java.security.Key;

public interface KeyCipher {
    byte[] wrap(Key key) throws Exception;

    Key unwrap(byte[] wrappedKey, String algorithm) throws Exception;
}
