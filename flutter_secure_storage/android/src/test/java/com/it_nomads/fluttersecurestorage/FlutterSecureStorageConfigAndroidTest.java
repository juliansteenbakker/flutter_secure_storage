package com.it_nomads.fluttersecurestorage;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Robolectric-based tests for FlutterSecureStorageConfig behaviour that
 * requires Android (e.g. Log.w calls that throw in plain JUnit).
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class FlutterSecureStorageConfigAndroidTest {

    @Test
    public void bothNamespaceAndNonDefaultPrefsName_logsWarningWithoutThrowing() {
        // When both storageNamespace and a non-default sharedPreferencesName are set,
        // FlutterSecureStorageConfig logs a warning via Log.w. In Robolectric Log is
        // properly shadowed so this must not throw.
        Map<String, Object> options = new HashMap<>();
        options.put(FlutterSecureStorageConfig.PREF_OPTION_STORAGE_NAMESPACE, "MyNamespace");
        options.put(FlutterSecureStorageConfig.PREF_OPTION_NAME, "CustomPrefs");

        FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);

        // storageNamespace takes precedence; verify the config is correctly populated
        assertEquals("MyNamespace", config.getStorageNamespace());
        assertTrue(config.hasStorageNamespace());
        assertEquals("CustomPrefs", config.getSharedPreferencesName());
    }
}
