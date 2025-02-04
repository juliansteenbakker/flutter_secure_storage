package com.it_nomads.fluttersecurestorage;

import androidx.annotation.NonNull;

import java.util.Map;

public class FlutterSecureStorageConfig {

    private static final String DEFAULT_PREF_NAME = "FlutterSecureStorage";
    private static final String DEFAULT_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";

    public static final String PREF_OPTION_NAME = "sharedPreferencesName";
    public static final String PREF_OPTION_PREFIX = "preferencesKeyPrefix";
    public static final String PREF_OPTION_DELETE_ON_FAILURE = "resetOnError";
    public static final String PREF_OPTION_SHOULD_USE_BIOMETRICS = "shouldUseBiometrics";

    public static final String PREF_OPTION_BIOMETRIC_PROMPT_TITLE = "prefOptionBiometricPromptTitle";
    public static final String PREF_OPTION_BIOMETRIC_PROMPT_SUBTITLE = "prefOptionBiometricPromptSubtitle";

    private final String sharedPreferencesName;
    private final String sharedPreferencesKeyPrefix;
    private final boolean deleteOnFailure;
    private final boolean shouldUseBiometrics;

    private final String biometricPromptTitle;
    private final String biometricPromptSubtitle;

    public FlutterSecureStorageConfig(Map<String, Object> options) {
        this.sharedPreferencesName = getStringOption(options, PREF_OPTION_NAME, DEFAULT_PREF_NAME);
        this.sharedPreferencesKeyPrefix = getStringOption(options, PREF_OPTION_PREFIX, DEFAULT_KEY_PREFIX);
        this.deleteOnFailure = getBooleanOption(options, PREF_OPTION_DELETE_ON_FAILURE, false);
        this.biometricPromptTitle = getStringOption(options, PREF_OPTION_BIOMETRIC_PROMPT_TITLE, "Authenticate to access");
        this.biometricPromptSubtitle = getStringOption(options, PREF_OPTION_BIOMETRIC_PROMPT_SUBTITLE, "Use biometrics or device credentials");

        this.shouldUseBiometrics = getBooleanOption(options, PREF_OPTION_SHOULD_USE_BIOMETRICS, false);
    }

    private String getStringOption(Map<String, Object> options, String key, String defaultValue) {
        if (options.containsKey(key)) {
            Object value = options.get(key);
            if (value instanceof String strValue) {
                if (!strValue.isEmpty()) {
                    return strValue;
                }
            }
        }
        return defaultValue;
    }

    private boolean getBooleanOption(Map<String, Object> options, String key, boolean defaultValue) {
        Object value = options.get(key);
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }

        return defaultValue;
    }

    public String getSharedPreferencesName() { return sharedPreferencesName; }
    public String getSharedPreferencesKeyPrefix() { return sharedPreferencesKeyPrefix; }
    public boolean shouldDeleteOnFailure() { return deleteOnFailure; }

    public boolean shouldUseBiometrics() { return shouldUseBiometrics; }

    public String getBiometricPromptTitle() { return biometricPromptTitle; }
    public String getPrefOptionBiometricPromptSubtitle() { return biometricPromptSubtitle; }

    @NonNull
    @Override
    public String toString() {
        return "FlutterSecureStorageConfig{" +
                "sharedPreferencesName='" + sharedPreferencesName + '\'' +
                ", sharedPreferencesKeyPrefix='" + sharedPreferencesKeyPrefix + '\'' +
                ", deleteOnFailure=" + deleteOnFailure +
                '}';
    }
}
