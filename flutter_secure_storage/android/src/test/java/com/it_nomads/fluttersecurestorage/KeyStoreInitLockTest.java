package com.it_nomads.fluttersecurestorage;

import android.content.Context;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class KeyStoreInitLockTest {

    private static final SecurePreferencesCallback<Void> NOOP = new SecurePreferencesCallback<>() {
        @Override
        public void onSuccess(Void result) {
        }

        @Override
        public void onError(Exception e) {
        }
    };

    @Test(timeout = 5000)
    public void secondInitializationOfTheSameKeyStoreWaitsForTheFirstCallback() throws Exception {
        KeyStoreInitLock.Held<Void> first = KeyStoreInitLock.acquire("FlutterSecureKeyStorage", NOOP);
        CountDownLatch secondAcquired = new CountDownLatch(1);
        Thread second = new Thread(() -> {
            KeyStoreInitLock.acquire("FlutterSecureKeyStorage", NOOP).onSuccess(null);
            secondAcquired.countDown();
        });
        second.start();

        assertFalse(secondAcquired.await(300, TimeUnit.MILLISECONDS));

        first.onSuccess(null);

        assertTrue(secondAcquired.await(2, TimeUnit.SECONDS));
        second.join();
    }

    @Test(timeout = 5000)
    public void differentKeyStoresDoNotWaitForEachOther() {
        KeyStoreInitLock.Held<Void> first = KeyStoreInitLock.acquire("FlutterSecureKeyStorage:a", NOOP);
        KeyStoreInitLock.Held<Void> second = KeyStoreInitLock.acquire("FlutterSecureKeyStorage:b", NOOP);

        first.onSuccess(null);
        second.onSuccess(null);
    }

    @Test(timeout = 5000)
    public void errorCallbackReleasesAndForwardsOnce() {
        AtomicInteger errors = new AtomicInteger();
        KeyStoreInitLock.Held<Void> held = KeyStoreInitLock.acquire("FlutterSecureKeyStorage:c",
                new SecurePreferencesCallback<>() {
                    @Override
                    public void onSuccess(Void result) {
                    }

                    @Override
                    public void onError(Exception e) {
                        errors.incrementAndGet();
                    }
                });

        held.onError(new Exception("boom"));
        held.release();

        assertEquals(1, errors.get());
        KeyStoreInitLock.acquire("FlutterSecureKeyStorage:c", NOOP).release();
    }

    @Test(timeout = 10000)
    public void failedInitializeDoesNotLeaveTheKeyStoreLocked() throws Exception {
        Context context = RuntimeEnvironment.getApplication();
        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(new HashMap<>());

        for (int i = 0; i < 2; i++) {
            CountDownLatch done = new CountDownLatch(1);
            try {
                new FlutterSecureStorage(context).initialize(config, new SecurePreferencesCallback<>() {
                    @Override
                    public void onSuccess(Void result) {
                        done.countDown();
                    }

                    @Override
                    public void onError(Exception e) {
                        done.countDown();
                    }
                });
            } catch (RuntimeException ignored) {
                done.countDown();
            }
            assertTrue(done.await(3, TimeUnit.SECONDS));
        }
    }
}
