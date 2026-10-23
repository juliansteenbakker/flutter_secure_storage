package com.it_nomads.fluttersecurestorage_legacy_migration;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.Base64;
import android.security.keystore.UserNotAuthenticatedException;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import java.io.IOException;
import java.io.File;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import androidx.annotation.NonNull;

import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorage;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.MigrationBackup;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.MigrationVerification;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.LegacyBackendEntries;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.SecurePreferencesCallback;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers.StorageCipherFactory;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;

public final class FlutterSecureStorageLegacyMigrationPlugin
        implements FlutterPlugin, MethodChannel.MethodCallHandler {
    private static final String BACKUP_PREFS_PREFIX =
            "FlutterSecureStorageLegacyMigrationBackup:";
    private static final String TAG = "SecureStorageRecovery";

    private MethodChannel channel;
    private Context context;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding binding) {
        context = binding.getApplicationContext();
        channel = new MethodChannel(binding.getBinaryMessenger(),
                "plugins.it_nomads.com/flutter_secure_storage_legacy_migration");
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
        channel = null;
        context = null;
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull MethodChannel.Result result) {
        Context operationContext = context;
        MigrationCoordinator.shared().submit(done -> {
            MethodChannel.Result coordinatedResult = new MethodChannel.Result() {
                public void success(Object value) {
                    try {
                        result.success(value);
                    } finally {
                        done.run();
                    }
                }

                public void error(String code, String message, Object details) {
                    try {
                        result.error(code, message, details);
                    } finally {
                        done.run();
                    }
                }

                public void notImplemented() {
                    try {
                        result.notImplemented();
                    } finally {
                        done.run();
                    }
                }
            };
            try {
                handleMethodCall(call, coordinatedResult, operationContext);
            } catch (Exception error) {
                reportError(coordinatedResult, error);
            }
        });
    }

    private void handleMethodCall(MethodCall call, MethodChannel.Result result, Context context) {
        if ("readLegacyEntries".equals(call.method)) {
            readLegacyEntries(call, result, context);
            return;
        }
        if (!"migrate".equals(call.method) && !"hasPendingMigration".equals(call.method)
                && !"resetStorage".equals(call.method) && !"completeMigration".equals(call.method)
                && !"getSelectedEntryCount".equals(call.method)) {
            result.notImplemented();
            return;
        }
        if (!(call.arguments instanceof Map<?, ?>)) {
            result.error("invalid_options", "Migration options must be a map", null);
            return;
        }

        Map<String, Object> options = new HashMap<>();
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) call.arguments).entrySet()) {
            if (!(entry.getKey() instanceof String) || !(entry.getValue() instanceof String)) {
                result.error("invalid_options", "Migration options must contain strings", null);
                return;
            }
            options.put((String) entry.getKey(), entry.getValue());
        }
        options.remove("legacyBackendPresent");
        options.put("resetOnError", "false");
        options.put("migrateOnAlgorithmChange", "true");

        Runnable operation = () -> {
            SharedPreferences dataPrefs = null;
            SharedPreferences backupPrefs = null;
            try {
                FlutterSecureStorageConfig initialConfig = new FlutterSecureStorageConfig(options);
                dataPrefs = context.getSharedPreferences(
                        initialConfig.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
                backupPrefs = context.getSharedPreferences(
                        BACKUP_PREFS_PREFIX + initialConfig.getEffectiveDataPrefsName(),
                        Context.MODE_PRIVATE);
                if ("resetStorage".equals(call.method)) {
                    resetStorage(context, initialConfig, dataPrefs, backupPrefs);
                    mainHandler.post(() -> result.success(null));
                    return;
                }
                if ("completeMigration".equals(call.method)) {
                    new FlutterSecureStorage(context).completeVerifiedMigration(initialConfig);
                    if (!backupPrefs.edit().clear().commit()) {
                        throw new IOException("Could not clear verified migration backup");
                    }
                    mainHandler.post(() -> result.success(null));
                    return;
                }
                int legacyCount = countLegacyEntries(dataPrefs,
                        initialConfig.getSharedPreferencesKeyPrefix());
                SharedPreferences keyPrefs = context.getSharedPreferences(
                        initialConfig.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
                NamespacedConfigSource configSource = new NamespacedConfigSource(
                        context, initialConfig.getEffectiveDataPrefsName());
                boolean pendingBackup = MigrationBackup.hasPendingMigration(
                        dataPrefs, keyPrefs, configSource, initialConfig);
                FlutterSecureStorage storage = new FlutterSecureStorage(context);
                if ("getSelectedEntryCount".equals(call.method)) {
                    int count = storage.selectedEntryKeys(initialConfig, backupPrefs.getAll()).size();
                    mainHandler.post(() -> result.success(count));
                    return;
                }
                if ("hasPendingMigration".equals(call.method)) {
                    boolean selectedLegacy = legacyCount > 0
                            && !storage.selectedEncryptedEntries(initialConfig).isEmpty();
                    boolean pending = selectedLegacy || storage.hasLegacyCustomEntries(initialConfig)
                            || pendingBackup || !backupPrefs.getAll().isEmpty()
                            || MigrationVerification.hasPending(context, initialConfig);
                    mainHandler.post(() -> result.success(pending));
                    return;
                }

                restoreStagedEntries(dataPrefs, backupPrefs);
                options.put("migrateWithBackup", "true");
                FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
                java.util.Set<String> expectedKeys = storage.selectedEntryKeys(config, backupPrefs.getAll());
                SharedPreferences finalDataPrefs = dataPrefs;
                SharedPreferences finalBackupPrefs = backupPrefs;
                storage.initializeCustomStorage(config, new SecurePreferencesCallback<>() {
                    @Override
                    public void onSuccess(Void unused) {
                        try {
                            storage.copyLegacyEncryptedEntries();
                            Map<String, String> recovered = storage.readAll();
                            if (!recovered.keySet().containsAll(expectedKeys)) {
                                throw new IllegalStateException("Selected secure-storage entries were not recovered");
                            }
                            int count = recovered.size();
                            if (MigrationBackup.hasPendingMigration(
                                            finalDataPrefs, keyPrefs, configSource, config)) {
                                throw new IllegalStateException(
                                        "Legacy encrypted preferences entries remain after migration");
                            }
                            storage.recordMigrationVerification();
                            mainHandler.post(() -> result.success(count));
                        } catch (Exception error) {
                            restoreAndReport(finalDataPrefs, finalBackupPrefs, result, error);
                        }
                    }

                    @Override
                    public void onError(Exception error) {
                        restoreAndReport(finalDataPrefs, finalBackupPrefs, result, error);
                    }
                });
            } catch (Exception error) {
                if ("resetStorage".equals(call.method)) {
                    reportError(result, error);
                } else {
                    restoreAndReport(dataPrefs, backupPrefs, result, error);
                }
            }
        };
        operation.run();
    }

    private void readLegacyEntries(MethodCall call, MethodChannel.Result result, Context context) {
        if (!(call.arguments instanceof Map<?, ?> args)
                || !(args.get("options") instanceof Map<?, ?> rawOptions)
                || !(args.get("keys") instanceof List<?> rawKeys)) {
            result.error("invalid_options", "Recovery requires options and keys", null);
            return;
        }
        Map<String, Object> options = new HashMap<>();
        for (Map.Entry<?, ?> entry : rawOptions.entrySet()) {
            if (!(entry.getKey() instanceof String) || !(entry.getValue() instanceof String)) {
                result.error("invalid_options", "Recovery options must contain strings", null);
                return;
            }
            options.put((String) entry.getKey(), entry.getValue());
        }
        for (Object key : rawKeys) {
            if (!(key instanceof String)) {
                result.error("invalid_options", "Recovery keys must be strings", null);
                return;
            }
        }
        @SuppressWarnings("unchecked")
        List<String> keys = (List<String>) rawKeys;
        Runnable operation = () -> {
            try {
                options.put("migrateWithBackup", "true");
                FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);
                FlutterSecureStorage storage = new FlutterSecureStorage(context);
                Map<String, String> recovered = new HashMap<>();
                try {
                    recovered.putAll(storage.readLegacyCustomEntries(config, keys));
                } catch (Exception error) {
                    Log.w(TAG, "Could not recover custom cipher entries", error);
                }
                try {
                    Map<String, String> encrypted = storage.readLegacyEncryptedEntries(config, keys);
                    for (Map.Entry<String, String> entry : encrypted.entrySet()) {
                        recovered.putIfAbsent(entry.getKey(), entry.getValue());
                    }
                } catch (Exception error) {
                    Log.w(TAG, "Could not recover encrypted preferences entries", error);
                }
                mainHandler.post(() -> result.success(recovered));
            } catch (Exception error) {
                reportError(result, error);
            }
        };
        operation.run();
    }

    private int countLegacyEntries(SharedPreferences dataPrefs, String prefix) {
        return LegacyBackendEntries.count(dataPrefs, prefix);
    }

    private void restoreStagedEntries(SharedPreferences dataPrefs, SharedPreferences backupPrefs) {
        Map<String, ?> staged = backupPrefs.getAll();
        if (staged.isEmpty()) {
            return;
        }
        SharedPreferences.Editor restore = dataPrefs.edit();
        for (Map.Entry<String, ?> entry : staged.entrySet()) {
            if (entry.getValue() instanceof String) {
                if (!dataPrefs.contains(entry.getKey())) {
                    restore.putString(entry.getKey(), (String) entry.getValue());
                }
            }
        }
        if (!restore.commit()) {
            throw new IllegalStateException("Could not restore staged secure-storage entries");
        }
    }

    private void restoreAndReport(SharedPreferences dataPrefs, SharedPreferences backupPrefs,
                                  MethodChannel.Result result, Exception error) {
        if (dataPrefs != null && backupPrefs != null) {
            try {
                restoreStagedEntries(dataPrefs, backupPrefs);
            } catch (Exception restoreError) {
                error.addSuppressed(restoreError);
            }
        }
        reportError(result, error);
    }

    private void resetStorage(Context context, FlutterSecureStorageConfig config, SharedPreferences dataPrefs,
                              SharedPreferences backupPrefs) throws Exception {
        boolean clearKeys = config.hasStorageNamespace() || !hasPotentialSharedStores(context, config);
        if (!dataPrefs.edit().clear().commit()) {
            throw new IllegalStateException("Could not clear secure-storage entries");
        }
        SharedPreferences keyPrefs = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        if (clearKeys && !keyPrefs.edit().clear().commit()) {
            throw new IllegalStateException("Could not clear secure-storage wrapped keys");
        }
        if (!backupPrefs.edit().clear().commit()) {
            throw new IllegalStateException("Could not clear secure-storage migration backup");
        }
        NamespacedConfigSource configSource = new NamespacedConfigSource(
                context, config.getEffectiveDataPrefsName());
        if (!configSource.getDataBackupPreferences().edit().clear().commit()) {
            throw new IOException("Could not clear secure-storage cipher backup");
        }
        StorageCipherFactory cipherFactory = new StorageCipherFactory(
                configSource, config.getPrefOptionKeyCipherAlgorithm(),
                config.getPrefOptionStorageCipherAlgorithm(), config);
        SharedPreferences.Editor configEditor = configSource.edit().clear();
        configEditor.putString("FlutterSecureStorageBackupStatus", "");
        cipherFactory.storeCurrentAlgorithms(configEditor);
        if (!configEditor.commit()) {
            throw new IllegalStateException("Could not clear secure-storage migration progress");
        }

        MigrationVerification.clear(context, config);
        if (!clearKeys) {
            return;
        }
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        String[] aliases = {
                context.getPackageName() + ".FlutterSecureStoragePluginKey"
                        + config.getKeyAliasSuffix(),
                context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP"
                        + config.getKeyAliasSuffix()
        };
        for (String alias : aliases) {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        }
    }

    private boolean hasPotentialSharedStores(Context context, FlutterSecureStorageConfig config) {
        File[] files = new File(context.getApplicationInfo().dataDir, "shared_prefs").listFiles();
        if (files == null) {
            return true;
        }
        for (File file : files) {
            String filename = file.getName();
            if (!filename.endsWith(".xml") && !filename.endsWith(".xml.bak")) {
                continue;
            }
            String name = filename.substring(0, filename.endsWith(".xml.bak")
                    ? filename.length() - 8 : filename.length() - 4);
            if (name.equals(config.getEffectiveDataPrefsName())
                    || name.equals(MigrationBackup.DATA_BACKUP_PREFS_PREFIX + config.getEffectiveDataPrefsName())
                    || name.equals("FlutterSecureKeyStorage") || name.startsWith("FlutterSecureKeyStorage:")
                    || name.equals("FlutterSecureStorageConfiguration")
                    || name.startsWith("FlutterSecureStorageConfiguration:")
                    || name.startsWith("FlutterSecureStorageLegacyWrappedKeys:")
                    || name.startsWith(BACKUP_PREFS_PREFIX)
                    || name.startsWith("FlutterSecureStorageMigrationVerification:")) {
                continue;
            }
            SharedPreferences other = context.getSharedPreferences(name, Context.MODE_PRIVATE);
            for (Map.Entry<String, ?> entry : other.getAll().entrySet()) {
                String key = entry.getKey();
                if (!(entry.getValue() instanceof String) || !key.contains("_")
                        || key.startsWith("__androidx_security_crypto_encrypted_prefs_")) {
                    continue;
                }
                try {
                    if (Base64.decode((String) entry.getValue(), Base64.DEFAULT).length >= 17) {
                        return true;
                    }
                } catch (IllegalArgumentException ignored) {
                    continue;
                }
            }
        }
        return false;
    }

    static boolean isUnreadableStorage(Exception error) {
        boolean unreadable = false;
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof IOException || cause instanceof UserNotAuthenticatedException) {
                return false;
            }
            if (cause instanceof BadPaddingException || cause instanceof IllegalBlockSizeException
                    || cause instanceof KeyPermanentlyInvalidatedException) {
                unreadable = true;
            }
            String message = cause.getMessage();
            if ("Missing saved wrapped key".equals(message)
                    || "Missing legacy wrapped-key material".equals(message)
                    || (message != null && message.startsWith("Failed to decrypt secure-storage backup:"))) {
                unreadable = true;
            }
        }
        return unreadable;
    }

    private void reportError(MethodChannel.Result result, Exception error) {
        String code = isUnreadableStorage(error) ? "legacy_data_unreadable" : "migration_failed";
        mainHandler.post(() -> result.error(code, error.getMessage(), null));
    }
}
