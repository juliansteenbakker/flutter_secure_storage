package com.it_nomads.fluttersecurestorage;

import androidx.annotation.NonNull;

import java.util.Map;

public class FlutterSecureStorageConfig {

    private static final String DEFAULT_PREF_NAME = "FlutterSecureStorage";
    private static final String DEFAULT_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    private static final Boolean DEFAULT_DELETE_ON_FAILURE = false;
    private static final Boolean DEFAULT_MIGRATE_ON_ALGORITHM_CHANGE = true;
    private static final Boolean DEFAULT_ENCRYPTED_SHARED_PREFERENCES = false;
    private static final Boolean DEFAULT_ENFORCE_BIOMETRICS = false;
    private static final String DEFAULT_BIOMETRIC_PROMPT_TITLE = "Authenticate to access";
    private static final String DEFAULT_BIOMETRIC_PROMPT_SUBTITLE = "Use biometrics to continue";
    private static final String DEFAULT_STORAGE_CIPHER_ALGORITHM = "AES_GCM_NoPadding";
    private static final String DEFAULT_KEY_CIPHER_ALGORITHM = "RSA_ECB_PKCS1Padding";

    public static final String PREF_OPTION_NAME = "sharedPreferencesName";
    public static final String PREF_OPTION_PREFIX = "preferencesKeyPrefix";
    public static final String PREF_OPTION_DELETE_ON_FAILURE = "resetOnError";
    public static final String PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE = "migrateOnAlgorithmChange";
    public static final String PREF_OPTION_ENCRYPTED_SHARED_PREFERENCES = "encryptedSharedPreferences";
    public static final String PREF_OPTION_ENFORCE_BIOMETRICS = "enforceBiometrics";
    public static final String PREF_OPTION_BIOMETRIC_PROMPT_TITLE = "biometricPromptTitle";
    public static final String PREF_OPTION_BIOMETRIC_PROMPT_SUBTITLE = "biometricPromptSubtitle";
    // Legacy keys kept for backwards compatibility.
    public static final String LEGACY_PREF_OPTION_BIOMETRIC_PROMPT_TITLE = "prefOptionBiometricPromptTitle";
    public static final String LEGACY_PREF_OPTION_BIOMETRIC_PROMPT_SUBTITLE = "prefOptionBiometricPromptSubtitle";
    public static final String PREF_OPTION_STORAGE_CIPHER_ALGORITHM = "storageCipherAlgorithm";
    public static final String PREF_OPTION_KEY_CIPHER_ALGORITHM = "keyCipherAlgorithm";

    private final String sharedPreferencesName;
    private final String sharedPreferencesKeyPrefix;
    private final boolean deleteOnFailure;
    private final boolean migrateOnAlgorithmChange;
    private final boolean useEncryptedSharedPreferences;
    private final boolean enforceBiometrics;
    private final String biometricPromptTitle;
    private final String biometricPromptSubtitle;
    private final String keyCipherAlgorithm;
    private final String storageCipherAlgorithm;

    public FlutterSecureStorageConfig(Map<String, Object> options) {
        final String baseSharedPreferencesName = getStringOption(options, PREF_OPTION_NAME, DEFAULT_PREF_NAME);
        final String baseSharedPreferencesKeyPrefix = getStringOption(options, PREF_OPTION_PREFIX, DEFAULT_KEY_PREFIX);
        this.deleteOnFailure = getBooleanOption(options, PREF_OPTION_DELETE_ON_FAILURE, DEFAULT_DELETE_ON_FAILURE);
        this.migrateOnAlgorithmChange = getBooleanOption(options, PREF_OPTION_MIGRATE_ON_ALGORITHM_CHANGE, DEFAULT_MIGRATE_ON_ALGORITHM_CHANGE);
        this.useEncryptedSharedPreferences = getBooleanOption(options, PREF_OPTION_ENCRYPTED_SHARED_PREFERENCES, DEFAULT_ENCRYPTED_SHARED_PREFERENCES);
        this.enforceBiometrics = getBooleanOption(options, PREF_OPTION_ENFORCE_BIOMETRICS, DEFAULT_ENFORCE_BIOMETRICS);
        final boolean hasCustomPrefName = getOptionalStringOption(options, PREF_OPTION_NAME) != null;
        final boolean hasCustomPrefPrefix = getOptionalStringOption(options, PREF_OPTION_PREFIX) != null;
        this.sharedPreferencesName = resolveEffectivePrefName(baseSharedPreferencesName, hasCustomPrefName);
        this.sharedPreferencesKeyPrefix = resolveEffectivePrefPrefix(baseSharedPreferencesKeyPrefix, hasCustomPrefPrefix);
        this.biometricPromptTitle = getStringOption(
                options,
                PREF_OPTION_BIOMETRIC_PROMPT_TITLE,
                LEGACY_PREF_OPTION_BIOMETRIC_PROMPT_TITLE,
                DEFAULT_BIOMETRIC_PROMPT_TITLE
        );
        this.biometricPromptSubtitle = getStringOption(
                options,
                PREF_OPTION_BIOMETRIC_PROMPT_SUBTITLE,
                LEGACY_PREF_OPTION_BIOMETRIC_PROMPT_SUBTITLE,
                DEFAULT_BIOMETRIC_PROMPT_SUBTITLE
        );
        this.storageCipherAlgorithm = getStringOption(options, PREF_OPTION_STORAGE_CIPHER_ALGORITHM, DEFAULT_STORAGE_CIPHER_ALGORITHM);
        this.keyCipherAlgorithm = getStringOption(options, PREF_OPTION_KEY_CIPHER_ALGORITHM, DEFAULT_KEY_CIPHER_ALGORITHM);
    }

    private String getStringOption(Map<String, Object> options, String key, String defaultValue) {
        String value = getOptionalStringOption(options, key);
        return value != null ? value : defaultValue;
    }

    private String getStringOption(Map<String, Object> options, String key, String fallbackKey, String defaultValue) {
        String value = getOptionalStringOption(options, key);
        if (value != null) {
            return value;
        }

        value = getOptionalStringOption(options, fallbackKey);
        return value != null ? value : defaultValue;
    }

    private String getOptionalStringOption(Map<String, Object> options, String key) {
        if (!options.containsKey(key)) {
            return null;
        }
        Object value = options.get(key);
        if (value instanceof String strValue && !strValue.isEmpty()) {
            return strValue;
        }
        return null;
    }

    private boolean getBooleanOption(Map<String, Object> options, String key, boolean defaultValue) {
        Object value = options.get(key);
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }

        return defaultValue;
    }

    private String resolveEffectivePrefName(String base, boolean hasCustomPrefName) {
        if (hasCustomPrefName || !enforceBiometrics) {
            return base;
        }
        return base + "__biometric";
    }

    private String resolveEffectivePrefPrefix(String base, boolean hasCustomPrefPrefix) {
        if (hasCustomPrefPrefix || !enforceBiometrics) {
            return base;
        }
        return base + "__biometric";
    }

    public String getSharedPreferencesName() { return sharedPreferencesName; }
    public String getSharedPreferencesKeyPrefix() { return sharedPreferencesKeyPrefix; }
    public boolean shouldDeleteOnFailure() { return deleteOnFailure; }
    public boolean shouldMigrateOnAlgorithmChange() { return migrateOnAlgorithmChange; }

    public boolean isUseEncryptedSharedPreferences() { return useEncryptedSharedPreferences; }
    public boolean getEnforceBiometrics() { return enforceBiometrics; }

    public String getBiometricPromptTitle() { return biometricPromptTitle; }
    public String getPrefOptionBiometricPromptSubtitle() { return biometricPromptSubtitle; }
    public String getPrefOptionStorageCipherAlgorithm() { return storageCipherAlgorithm; }
    public String getPrefOptionKeyCipherAlgorithm() { return keyCipherAlgorithm; }

    public String getStorageNamespace() {
        return sanitizeForSharedPreferencesName(sharedPreferencesName) + "__" +
                sanitizeForSharedPreferencesName(sharedPreferencesKeyPrefix);
    }

    public String getConfigPreferencesName() {
        return "FlutterSecureStorageConfiguration_" +
                getStorageNamespace();
    }

    public String getKeyStoragePreferencesName() {
        return "FlutterSecureKeyStorage_" +
                getStorageNamespace();
    }

    public String getNamespacedKey(String baseKey) {
        return baseKey + "_" + getStorageNamespace() + "__" + getCryptoProfile();
    }

    public String getRuntimeConfigSignature() {
        return getStorageNamespace() + "|" +
                getCryptoProfile() + "|" +
                useEncryptedSharedPreferences;
    }

    private String getCryptoProfile() {
        return sanitizeForSharedPreferencesName(
                keyCipherAlgorithm + "__" +
                        storageCipherAlgorithm + "__" +
                        enforceBiometrics
        );
    }

    private static String sanitizeForSharedPreferencesName(String value) {
        return value.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    @NonNull
    @Override
    public String toString() {
        return "FlutterSecureStorageConfig{" +
                "sharedPreferencesName='" + sharedPreferencesName + '\'' +
                ", sharedPreferencesKeyPrefix='" + sharedPreferencesKeyPrefix + '\'' +
                ", deleteOnFailure=" + deleteOnFailure +
                ", migrateOnAlgorithmChange=" + migrateOnAlgorithmChange +
                ", enforceBiometrics=" + enforceBiometrics +
                '}';
    }
}
