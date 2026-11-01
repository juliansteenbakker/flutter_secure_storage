package com.it_nomads.fluttersecurestorage_legacy_migration;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MigrationCoordinatorTest {
    @Test
    public void asynchronousCompletionBlocksOtherEngineOperations() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            MigrationCoordinator coordinator = new MigrationCoordinator(executor);
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch second = new CountDownLatch(1);
            Runnable[] completion = new Runnable[1];
            coordinator.submit(done -> {
                completion[0] = done;
                entered.countDown();
            });
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            coordinator.submit(done -> {
                second.countDown();
                done.run();
            });
            assertFalse(second.await(100, TimeUnit.MILLISECONDS));
            completion[0].run();
            assertTrue(second.await(5, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void duplicateCallbacksDoNotReleaseAnotherOperation() {
        MigrationCoordinator coordinator = new MigrationCoordinator(Runnable::run);
        List<String> calls = new ArrayList<>();
        Runnable[] completions = new Runnable[2];
        coordinator.submit(done -> { calls.add("migration"); completions[0] = done; });
        coordinator.submit(done -> { calls.add("recovery-read"); completions[1] = done; });
        coordinator.submit(done -> { calls.add("reset"); done.run(); });
        completions[0].run();
        completions[0].run();
        assertEquals(List.of("migration", "recovery-read"), calls);
        completions[1].run();
        assertEquals(List.of("migration", "recovery-read", "reset"), calls);
    }
}
