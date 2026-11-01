package com.it_nomads.fluttersecurestorage_legacy_migration.legacy;

public interface SecurePreferencesCallback<T> {
    void onSuccess(T result);
    void onError(Exception e);
}
