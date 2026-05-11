package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Map;

/**
 * Helper class that provides dual-read fallback for config SharedPreferences.
 * Reads from namespaced config first, falls back to legacy global config if not found.
 * Writes always go to the namespaced config.
 */
public class NamespacedConfigSource {
    // Legacy global config name (used for backwards compatibility fallback reads only)
    private static final String LEGACY_GLOBAL_CONFIG_NAME = "FlutterSecureStorageConfiguration";
    
    private final SharedPreferences namespacedConfig;
    private final SharedPreferences legacyConfig;
    
    public NamespacedConfigSource(Context context, String sharedPreferencesName) {
        String namespacedName = getNamespacedConfigPrefsName(sharedPreferencesName);
        this.namespacedConfig = context.getSharedPreferences(namespacedName, Context.MODE_PRIVATE);
        this.legacyConfig = context.getSharedPreferences(LEGACY_GLOBAL_CONFIG_NAME, Context.MODE_PRIVATE);
    }
    
    /**
     * Returns the namespaced config SharedPreferences name for a given sharedPreferencesName.
     * Config markers (algorithm and migration flags) are now isolated per namespace.
     * 
     * @param sharedPreferencesName The namespace identifier
     * @return Namespaced config prefs name
     */
    private static String getNamespacedConfigPrefsName(String sharedPreferencesName) {
        // Use a delimiter to avoid collisions with legacy global name
        return "FlutterSecureStorageConfiguration:" + sharedPreferencesName;
    }
    
    /**
     * Reads a string value with fallback: namespaced first, then legacy global.
     */
    public String getString(String key, String defaultValue) {
        String value = namespacedConfig.getString(key, null);
        if (value != null) {
            return value;
        }
        return legacyConfig.getString(key, defaultValue);
    }
    
    /**
     * Reads a boolean value with fallback: namespaced first, then legacy global.
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        // Check if key exists in namespaced config (even if value is default)
        if (namespacedConfig.contains(key)) {
            return namespacedConfig.getBoolean(key, defaultValue);
        }
        return legacyConfig.getBoolean(key, defaultValue);
    }
    
    /**
     * Returns an editor for the namespaced config (writes always go to namespaced).
     */
    public SharedPreferences.Editor edit() {
        return namespacedConfig.edit();
    }
    
    /**
     * Checks if a key exists in either namespaced or legacy config.
     */
    public boolean contains(String key) {
        return namespacedConfig.contains(key) || legacyConfig.contains(key);
    }

    /**
     * Returns all entries from the namespaced config (writes always go here).
     */
    public Map<String, ?> getAll() {
        return namespacedConfig.getAll();
    }
}
