package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public final class LegacyEncryptedPreferencesContext extends ContextWrapper {
    private final String name;

    public LegacyEncryptedPreferencesContext(Context context, String name) {
        super(context);
        this.name = name;
    }

    @Override
    public Context getApplicationContext() {
        return this;
    }

    @Override
    public SharedPreferences getSharedPreferences(String requestedName, int mode) {
        SharedPreferences original = super.getSharedPreferences(requestedName, mode);
        if (!name.equals(requestedName)) {
            return original;
        }
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, arguments) -> {
                    if ("getAll".equals(method.getName())) {
                        Map<String, Object> filtered = new HashMap<>();
                        for (Map.Entry<String, ?> entry : original.getAll().entrySet()) {
                            String key = entry.getKey();
                            boolean keyset = key.equals("__androidx_security_crypto_encrypted_prefs_key_keyset__")
                                    || key.equals("__androidx_security_crypto_encrypted_prefs_value_keyset__");
                            if (keyset || (!key.contains("_") && !key.startsWith("FlutterSecureSAlgorithm"))) {
                                filtered.put(entry.getKey(), entry.getValue());
                            }
                        }
                        return filtered;
                    }
                    try {
                        return method.invoke(original, arguments);
                    } catch (InvocationTargetException error) {
                        throw error.getCause();
                    }
                });
    }
}
