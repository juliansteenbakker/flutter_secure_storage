package com.it_nomads.fluttersecurestorage;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lets one {@link FlutterSecureStorage} initialize a key store at a time, process-wide.
 *
 * <p>Each Flutter engine gets its own plugin instance, so a foreground engine and a
 * background one (for example a WorkManager engine) can initialize the same store at
 * the same time. Initialization can delete and regenerate the KeyStore key pair and
 * the wrapped key (migration, {@code resetOnError}, first use). When two instances do
 * that at once, the wrapped key in SharedPreferences can end up wrapped with a pair
 * that is no longer in the KeyStore, and every later launch fails with
 * "Failed to unwrap key".
 *
 * <p>The lock is held until the initialization callback fires, so it also covers
 * initializations that finish asynchronously after biometric authentication.
 */
final class KeyStoreInitLock {

    private static final Map<String, Semaphore> LOCKS = new HashMap<>();

    private KeyStoreInitLock() {
    }

    /**
     * Blocks until no other initialization of {@code keyStoreName} is running, then
     * returns a callback that releases the lock before delegating to {@code callback}.
     * Call {@link Held#release()} if initialization throws before reaching a callback.
     */
    static <T> Held<T> acquire(String keyStoreName, SecurePreferencesCallback<T> callback) {
        Semaphore lock;
        synchronized (LOCKS) {
            lock = LOCKS.get(keyStoreName);
            if (lock == null) {
                lock = new Semaphore(1);
                LOCKS.put(keyStoreName, lock);
            }
        }
        lock.acquireUninterruptibly();
        return new Held<>(lock, callback);
    }

    static final class Held<T> implements SecurePreferencesCallback<T> {
        private final Semaphore lock;
        private final SecurePreferencesCallback<T> callback;
        private final AtomicBoolean released = new AtomicBoolean();

        private Held(Semaphore lock, SecurePreferencesCallback<T> callback) {
            this.lock = lock;
            this.callback = callback;
        }

        void release() {
            if (released.compareAndSet(false, true)) {
                lock.release();
            }
        }

        @Override
        public void onSuccess(T result) {
            release();
            callback.onSuccess(result);
        }

        @Override
        public void onError(Exception e) {
            release();
            callback.onError(e);
        }
    }
}
