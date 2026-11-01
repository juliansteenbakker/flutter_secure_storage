package com.it_nomads.fluttersecurestorage_legacy_migration;

import android.security.keystore.UserNotAuthenticatedException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import javax.crypto.BadPaddingException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class MigrationFailureTest {
    @Test
    public void missingWrappedKeysAndBadCiphertextCanUseSilentRecovery() {
        assertTrue(FlutterSecureStorageLegacyMigrationPlugin.isUnreadableStorage(
                new IllegalStateException("Missing saved wrapped key")));
        assertTrue(FlutterSecureStorageLegacyMigrationPlugin.isUnreadableStorage(
                new Exception("Migration failed", new BadPaddingException())));
        assertTrue(FlutterSecureStorageLegacyMigrationPlugin.isUnreadableStorage(
                new Exception("Failed to decrypt secure-storage backup: token", new IllegalArgumentException())));
    }

    @Test
    public void commitAndAuthenticationFailuresRemainRetryable() {
        assertFalse(FlutterSecureStorageLegacyMigrationPlugin.isUnreadableStorage(
                new IllegalStateException("Could not persist wrapped key")));
        assertFalse(FlutterSecureStorageLegacyMigrationPlugin.isUnreadableStorage(
                new Exception("Migration failed", new IOException())));
        assertFalse(FlutterSecureStorageLegacyMigrationPlugin.isUnreadableStorage(
                new Exception("Failed to decrypt secure-storage backup: token", new UserNotAuthenticatedException())));
    }
}
