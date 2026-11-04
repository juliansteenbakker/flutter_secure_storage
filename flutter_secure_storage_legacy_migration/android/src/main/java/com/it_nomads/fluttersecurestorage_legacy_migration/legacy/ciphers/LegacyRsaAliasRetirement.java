package com.it_nomads.fluttersecurestorage_legacy_migration.legacy.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.FlutterSecureStorageConfig;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.NamespacedConfigSource;
import com.it_nomads.fluttersecurestorage_legacy_migration.legacy.MigrationBackup;
import java.io.File;
import java.io.IOException;
import java.util.Map;

final class LegacyRsaAliasRetirement {
    private LegacyRsaAliasRetirement() {}

    static void verify(Context context, FlutterSecureStorageConfig config) throws IOException {
        NamespacedConfigSource markers = new NamespacedConfigSource(context, config.getEffectiveDataPrefsName());
        if (!KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding.name().equals(
                markers.getString("FlutterSecureSAlgorithmKey", null))) {
            throw new IOException("A durable OAEP checkpoint is required before replacing a legacy RSA alias");
        }
        if (config.hasStorageNamespace()) {
            return;
        }
        File directory = new File(context.getApplicationInfo().dataDir, "shared_prefs");
        File[] files = directory.listFiles();
        if (files == null) {
            throw new IOException("Could not inspect shared legacy RSA stores");
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
                    || name.startsWith("FlutterSecureStorageLegacyMigrationBackup:")
                    || name.startsWith("FlutterSecureStorageMigrationVerification:")) {
                continue;
            }
            String owner = name.startsWith(MigrationBackup.DATA_BACKUP_PREFS_PREFIX)
                    ? name.substring(MigrationBackup.DATA_BACKUP_PREFS_PREFIX.length()) : name;
            NamespacedConfigSource other = new NamespacedConfigSource(context, owner);
            String algorithm = other.getString("FlutterSecureSAlgorithmKey", null);
            if (algorithm != null && !KeyCipherAlgorithm.RSA_ECB_PKCS1Padding.name().equals(algorithm)) {
                continue;
            }
            SharedPreferences data = context.getSharedPreferences(name, Context.MODE_PRIVATE);
            for (Map.Entry<String, ?> entry : data.getAll().entrySet()) {
                if (!entry.getKey().contains("_") || !(entry.getValue() instanceof String)) {
                    continue;
                }
                try {
                    if (Base64.decode((String) entry.getValue(), Base64.DEFAULT).length >= 17) {
                        throw new IOException("Another legacy store may require the shared RSA alias: " + name);
                    }
                } catch (IllegalArgumentException ignored) {
                    continue;
                }
            }
        }
    }
}
