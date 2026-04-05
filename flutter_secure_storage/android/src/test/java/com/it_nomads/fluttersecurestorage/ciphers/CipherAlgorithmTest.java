package com.it_nomads.fluttersecurestorage.ciphers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class CipherAlgorithmTest {

    // -------------------------------------------------------------------------
    // KeyCipherAlgorithm.fromString
    // -------------------------------------------------------------------------

    @Test
    public void keyCipher_fromString_RSA_ECB_PKCS1Padding() {
        assertEquals(KeyCipherAlgorithm.RSA_ECB_PKCS1Padding, KeyCipherAlgorithm.fromString("RSA_ECB_PKCS1Padding"));
    }

    @Test
    public void keyCipher_fromString_RSA_ECB_OAEPwithSHA_256andMGF1Padding() {
        assertEquals(
            KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
            KeyCipherAlgorithm.fromString("RSA_ECB_OAEPwithSHA_256andMGF1Padding")
        );
    }

    @Test
    public void keyCipher_fromString_AES_GCM_NoPadding() {
        assertEquals(KeyCipherAlgorithm.AES_GCM_NoPadding, KeyCipherAlgorithm.fromString("AES_GCM_NoPadding"));
    }

    @Test
    public void keyCipher_fromString_legacyBiometricName_mapsToAES_GCM() {
        // Legacy name used before the rename — must still resolve to the correct value
        assertEquals(
            KeyCipherAlgorithm.AES_GCM_NoPadding,
            KeyCipherAlgorithm.fromString("AES_GCM_NoPadding_BIOMETRIC")
        );
    }

    @Test
    public void keyCipher_fromString_unknownName_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> KeyCipherAlgorithm.fromString("UNKNOWN_ALGORITHM"));
    }

    @Test
    public void keyCipher_fromString_emptyString_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> KeyCipherAlgorithm.fromString(""));
    }

    // -------------------------------------------------------------------------
    // StorageCipherAlgorithm.fromString
    // -------------------------------------------------------------------------

    @Test
    public void storageCipher_fromString_AES_CBC_PKCS7Padding() {
        assertEquals(StorageCipherAlgorithm.AES_CBC_PKCS7Padding, StorageCipherAlgorithm.fromString("AES_CBC_PKCS7Padding"));
    }

    @Test
    public void storageCipher_fromString_AES_GCM_NoPadding() {
        assertEquals(StorageCipherAlgorithm.AES_GCM_NoPadding, StorageCipherAlgorithm.fromString("AES_GCM_NoPadding"));
    }

    @Test
    public void storageCipher_fromString_legacyBiometricName_mapsToAES_GCM() {
        // Legacy name used before the rename — must still resolve to the correct value
        assertEquals(
            StorageCipherAlgorithm.AES_GCM_NoPadding,
            StorageCipherAlgorithm.fromString("AES_GCM_NoPadding_BIOMETRIC")
        );
    }

    @Test
    public void storageCipher_fromString_unknownName_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> StorageCipherAlgorithm.fromString("UNKNOWN_ALGORITHM"));
    }

    @Test
    public void storageCipher_fromString_emptyString_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> StorageCipherAlgorithm.fromString(""));
    }

    // -------------------------------------------------------------------------
    // Enum completeness — guards against accidental removal of values
    // -------------------------------------------------------------------------

    @Test
    public void keyCipher_hasExpectedNumberOfValues() {
        assertEquals(3, KeyCipherAlgorithm.values().length);
    }

    @Test
    public void storageCipher_hasExpectedNumberOfValues() {
        assertEquals(2, StorageCipherAlgorithm.values().length);
    }
}
