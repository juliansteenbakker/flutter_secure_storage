package com.it_nomads.fluttersecurestorage;

import androidx.annotation.NonNull;

class SecureStorageException extends Exception {
    static final String CODE_UNKNOWN = "SECURE_STORAGE_ERROR";
    static final String CODE_AUTH_CANCELLED = "AUTH_CANCELLED";
    static final String CODE_AUTH_FAILED = "AUTH_FAILED";
    static final String CODE_BIOMETRIC_UNAVAILABLE = "BIOMETRIC_UNAVAILABLE";
    static final String CODE_KEY_INVALIDATED = "KEY_INVALIDATED";
    static final String CODE_KEY_MISSING = "KEY_MISSING";
    static final String CODE_STORAGE_NOT_INITIALIZED = "STORAGE_NOT_INITIALIZED";

    private final String code;

    SecureStorageException(@NonNull String code, @NonNull String message) {
        super(message);
        this.code = code;
    }

    SecureStorageException(@NonNull String code, @NonNull String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    @NonNull
    String getCode() {
        return code;
    }

    static SecureStorageException from(Throwable throwable) {
        Throwable cursor = throwable;
        while (cursor != null) {
            if (cursor instanceof SecureStorageException) {
                return (SecureStorageException) cursor;
            }
            cursor = cursor.getCause();
        }
        return null;
    }
}
