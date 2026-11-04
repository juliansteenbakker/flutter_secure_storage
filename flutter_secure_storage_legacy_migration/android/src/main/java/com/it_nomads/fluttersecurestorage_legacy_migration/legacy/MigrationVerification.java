package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public final class MigrationVerification {
    private MigrationVerification() {}

    private static SharedPreferences preferences(Context context, FlutterSecureStorageConfig config) {
        try {
            String scope = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(
                    config.getSharedPreferencesKeyPrefix().getBytes(StandardCharsets.UTF_8)),
                    Base64.URL_SAFE | Base64.NO_WRAP);
            return context.getSharedPreferences("FlutterSecureStorageMigrationVerification:"
                    + config.getEffectiveDataPrefsName() + ":" + scope, Context.MODE_PRIVATE);
        } catch (java.security.NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is required for migration verification", error);
        }
    }

    public static boolean hasPending(Context context, FlutterSecureStorageConfig config) {
        return preferences(context, config).contains("digest");
    }

    public static void record(Context context, FlutterSecureStorageConfig config, Set<String> keys)
            throws Exception {
        if (!preferences(context, config).edit().putString("digest", digest(context, config))
                .putStringSet("keys", new HashSet<>(keys)).commit()) {
            throw new IOException("Could not persist migration verification");
        }
    }

    public static Set<String> verify(Context context, FlutterSecureStorageConfig config,
            boolean hasSelectedLegacy) throws Exception {
        SharedPreferences proof = preferences(context, config);
        if (!proof.contains("digest")) {
            SharedPreferences data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
            SharedPreferences keys = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
            NamespacedConfigSource markers = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
            if (!hasSelectedLegacy && !MigrationBackup.hasPendingMigration(data, keys, markers, config)) {
                return new HashSet<>();
            }
        }
        if (!digest(context, config).equals(proof.getString("digest", null))) {
            throw new IOException("Secure storage changed after migration verification");
        }
        return new HashSet<>(proof.getStringSet("keys", new HashSet<>()));
    }

    public static void clear(Context context, FlutterSecureStorageConfig config) throws IOException {
        if (!preferences(context, config).edit().clear().commit()) {
            throw new IOException("Could not clear migration verification");
        }
    }

    private static String digest(Context context, FlutterSecureStorageConfig config) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Map<String, Object> values = new TreeMap<>();
        SharedPreferences data = context.getSharedPreferences(config.getEffectiveDataPrefsName(), Context.MODE_PRIVATE);
        for (Map.Entry<String, ?> entry : data.getAll().entrySet()) {
            values.put("data:" + entry.getKey(), entry.getValue());
        }
        SharedPreferences keys = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        for (Map.Entry<String, ?> entry : keys.getAll().entrySet()) {
            values.put("key:" + entry.getKey(), entry.getValue());
        }
        NamespacedConfigSource markers = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
        values.put("algorithm:key", markers.getString("FlutterSecureSAlgorithmKey", ""));
        values.put("algorithm:storage", markers.getString("FlutterSecureSAlgorithmStorage", ""));
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            byte[] key = entry.getKey().getBytes(StandardCharsets.UTF_8);
            byte[] value = String.valueOf(entry.getValue()).getBytes(StandardCharsets.UTF_8);
            digest.update(java.nio.ByteBuffer.allocate(4).putInt(key.length).array());
            digest.update(key);
            digest.update(java.nio.ByteBuffer.allocate(4).putInt(value.length).array());
            digest.update(value);
        }
        return Base64.encodeToString(digest.digest(), Base64.NO_WRAP);
    }
}
