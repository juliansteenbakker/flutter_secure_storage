package com.it_nomads.fluttersecurestorage_legacy_migration;

import android.os.Handler;
import android.os.HandlerThread;

import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

final class MigrationCoordinator {
    private static MigrationCoordinator instance;
    private final Executor executor;
    private final Queue<Consumer<Runnable>> pending = new ArrayDeque<>();
    private boolean active;

    MigrationCoordinator(Executor executor) {
        this.executor = executor;
    }

    static synchronized MigrationCoordinator shared() {
        if (instance == null) {
            HandlerThread thread = new HandlerThread("secure_storage_migration_coordinator");
            thread.start();
            Handler handler = new Handler(thread.getLooper());
            instance = new MigrationCoordinator(command -> handler.post(command));
        }
        return instance;
    }

    synchronized void submit(Consumer<Runnable> operation) {
        pending.add(operation);
        startNext();
    }

    private synchronized void startNext() {
        if (active || pending.isEmpty()) {
            return;
        }
        active = true;
        Consumer<Runnable> operation = pending.remove();
        AtomicBoolean completed = new AtomicBoolean();
        executor.execute(() -> operation.accept(() -> {
            if (!completed.compareAndSet(false, true)) {
                return;
            }
            synchronized (MigrationCoordinator.this) {
                active = false;
                startNext();
            }
        }));
    }
}
