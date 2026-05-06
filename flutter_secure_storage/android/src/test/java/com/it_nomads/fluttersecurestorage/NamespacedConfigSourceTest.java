package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class NamespacedConfigSourceTest {

    private static final String NAMESPACED_PREFS = "FlutterSecureStorageConfiguration:TestNS";
    private static final String LEGACY_PREFS     = "FlutterSecureStorageConfiguration";

    private NamespacedConfigSource source;
    private SharedPreferences namespacedPrefs;
    private SharedPreferences legacyPrefs;

    @Before
    public void setUp() {
        Context context = RuntimeEnvironment.getApplication();
        source = new NamespacedConfigSource(context, "TestNS");
        namespacedPrefs = context.getSharedPreferences(NAMESPACED_PREFS, Context.MODE_PRIVATE);
        legacyPrefs     = context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE);
        namespacedPrefs.edit().clear().commit();
        legacyPrefs.edit().clear().commit();
    }

    // -------------------------------------------------------------------------
    // getString
    // -------------------------------------------------------------------------

    @Test
    public void getString_fromNamespacedPrefs() {
        namespacedPrefs.edit().putString("key", "namespaced").commit();
        assertEquals("namespaced", source.getString("key", "default"));
    }

    @Test
    public void getString_fallsBackToLegacy_whenNotInNamespaced() {
        legacyPrefs.edit().putString("key", "legacy").commit();
        assertEquals("legacy", source.getString("key", "default"));
    }

    @Test
    public void getString_namespacedTakesPrecedenceOverLegacy() {
        namespacedPrefs.edit().putString("key", "namespaced").commit();
        legacyPrefs.edit().putString("key", "legacy").commit();
        assertEquals("namespaced", source.getString("key", "default"));
    }

    @Test
    public void getString_returnsDefault_whenAbsentInBoth() {
        assertEquals("default", source.getString("missing", "default"));
    }

    // -------------------------------------------------------------------------
    // getBoolean
    // -------------------------------------------------------------------------

    @Test
    public void getBoolean_fromNamespacedPrefs() {
        namespacedPrefs.edit().putBoolean("flag", true).commit();
        assertTrue(source.getBoolean("flag", false));
    }

    @Test
    public void getBoolean_fallsBackToLegacy_whenNotInNamespaced() {
        legacyPrefs.edit().putBoolean("flag", true).commit();
        assertTrue(source.getBoolean("flag", false));
    }

    @Test
    public void getBoolean_returnsDefault_whenAbsentInBoth() {
        assertFalse(source.getBoolean("missing", false));
        assertTrue(source.getBoolean("missing", true));
    }

    @Test
    public void getBoolean_namespacedFalse_doesNotFallBackToLegacyTrue() {
        // Key exists in namespaced (as false) — legacy true should be ignored
        namespacedPrefs.edit().putBoolean("flag", false).commit();
        legacyPrefs.edit().putBoolean("flag", true).commit();
        assertFalse(source.getBoolean("flag", true));
    }

    // -------------------------------------------------------------------------
    // contains
    // -------------------------------------------------------------------------

    @Test
    public void contains_trueWhenKeyInNamespacedPrefs() {
        namespacedPrefs.edit().putString("key", "value").commit();
        assertTrue(source.contains("key"));
    }

    @Test
    public void contains_trueWhenKeyInLegacyPrefs() {
        legacyPrefs.edit().putString("key", "value").commit();
        assertTrue(source.contains("key"));
    }

    @Test
    public void contains_falseWhenAbsentInBoth() {
        assertFalse(source.contains("missing"));
    }

    // -------------------------------------------------------------------------
    // edit (writes go to namespaced, not legacy)
    // -------------------------------------------------------------------------

    @Test
    public void edit_writesToNamespacedPrefs() {
        source.edit().putString("key", "value").commit();
        assertEquals("value", namespacedPrefs.getString("key", null));
    }

    @Test
    public void edit_doesNotWriteToLegacyPrefs() {
        source.edit().putString("key", "value").commit();
        assertFalse(legacyPrefs.contains("key"));
    }
}
