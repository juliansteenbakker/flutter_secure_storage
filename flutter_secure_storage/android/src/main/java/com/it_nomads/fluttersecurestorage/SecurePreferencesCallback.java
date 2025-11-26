package com.it_nomads.fluttersecurestorage;

public interface SecurePreferencesCallback<T> {
    void onSuccess(T result);
    void onError(Exception e);
}
