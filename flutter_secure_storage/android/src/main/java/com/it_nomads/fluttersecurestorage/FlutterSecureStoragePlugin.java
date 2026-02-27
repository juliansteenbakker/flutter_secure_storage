package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

public class FlutterSecureStoragePlugin implements MethodCallHandler, FlutterPlugin {

    private static final String TAG = "FlutterSecureStoragePlugin";
    private MethodChannel channel;
    private FlutterSecureStorage secureStorage;
    private HandlerThread workerThread;
    private Handler workerThreadHandler;

    public void initInstance(BinaryMessenger messenger, Context context) {
        try {
            secureStorage = new FlutterSecureStorage(context);

            workerThread = new HandlerThread("com.it_nomads.fluttersecurestorage.worker");
            workerThread.start();
            workerThreadHandler = new Handler(workerThread.getLooper());

            channel = new MethodChannel(messenger, "plugins.it_nomads.com/flutter_secure_storage");
            channel.setMethodCallHandler(this);
        } catch (Exception e) {
            Log.e(TAG, "Registration failed", e);
        }
    }

    @Override
    public void onAttachedToEngine(FlutterPluginBinding binding) {
        initInstance(binding.getBinaryMessenger(), binding.getApplicationContext());
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        if (channel != null) {
            workerThread.quitSafely();
            workerThread = null;

            channel.setMethodCallHandler(null);
            channel = null;
        }
        secureStorage = null;
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result rawResult) {
        MethodResultWrapper result = new MethodResultWrapper(rawResult);
        // Run all method calls inside the worker thread instead of the platform thread.
        workerThreadHandler.post(new MethodRunner(call, result));
    }

    @SuppressWarnings("unchecked")
    private String getKeyFromCall(MethodCall call) {
        Map<String, Object> arguments = (Map<String, Object>) call.arguments;
        return secureStorage.addPrefixToKey((String) arguments.get("key"));
    }

    @SuppressWarnings("unchecked")
    private String getValueFromCall(MethodCall call) {
        Map<String, Object> arguments = (Map<String, Object>) call.arguments;
        return (String) arguments.get("value");
    }

    /**
     * MethodChannel.Result wrapper that responds on the platform thread.
     */
    static class MethodResultWrapper implements Result {

        private static final String TAG = "FlutterSecureStoragePlugin";
        private final Result methodResult;
        private final Handler handler = new Handler(Looper.getMainLooper());
        private final AtomicBoolean isCompleted = new AtomicBoolean(false);

        MethodResultWrapper(Result methodResult) {
            this.methodResult = methodResult;
        }

        @Override
        public void success(final Object result) {
            if (!isCompleted.compareAndSet(false, true)) {
                Log.w(TAG, "Ignoring duplicate success callback");
                return;
            }
            handler.post(() -> methodResult.success(result));
        }

        @Override
        public void error(@NonNull final String errorCode, final String errorMessage, final Object errorDetails) {
            if (!isCompleted.compareAndSet(false, true)) {
                Log.w(TAG, "Ignoring duplicate error callback");
                return;
            }
            handler.post(() -> methodResult.error(errorCode, errorMessage, errorDetails));
        }

        @Override
        public void notImplemented() {
            if (!isCompleted.compareAndSet(false, true)) {
                Log.w(TAG, "Ignoring duplicate notImplemented callback");
                return;
            }
            handler.post(methodResult::notImplemented);
        }
    }

    /**
     * Wraps the functionality of onMethodCall() in a Runnable for execution in the worker thread.
     */
    class MethodRunner implements Runnable {
        private final MethodCall call;
        private final Result result;

        MethodRunner(MethodCall call, Result result) {
            this.call = call;
            this.result = result;
        }

        @SuppressWarnings("unchecked")
        @Override
        public void run() {
            Map<String, Object> options = (Map<String, Object>) ((Map<String, Object>) call.arguments).get("options");
            FlutterSecureStorageConfig config = new FlutterSecureStorageConfig(options);

            secureStorage.initialize(config, new SecurePreferencesCallback<>() {
                @Override
                public void onSuccess(Void unused) {
                    try {
                        switch (call.method) {
                            case "write": {
                                String key = getKeyFromCall(call);
                                String value = getValueFromCall(call);

                                if (value != null) {
                                    secureStorage.write(key, value);
                                    result.success(null);
                                } else {
                                    result.error("null", null, null);
                                }
                                break;
                            }
                            case "read": {
                                String key = getKeyFromCall(call);

                                if (secureStorage.containsKey(key)) {
                                    String value = secureStorage.read(key);
                                    result.success(value);
                                } else {
                                    // Preserve plugin semantics: reading a missing key returns null.
                                    // Missing-key-as-error caused noisy stack traces and broke caller flow.
                                    result.success(null);
                                }
                                break;
                            }
                            case "readAll": {
                                result.success(secureStorage.readAll());
                                break;
                            }
                            case "containsKey": {
                                String key = getKeyFromCall(call);

                                boolean containsKey = secureStorage.containsKey(key);
                                result.success(containsKey);
                                break;
                            }
                            case "delete": {
                                String key = getKeyFromCall(call);

                                secureStorage.delete(key);
                                result.success(null);
                                break;
                            }
                            case "deleteAll": {
                                secureStorage.deleteAll();
                                result.success(null);
                                break;
                            }
                            case "isBiometricAvailable": {
                                boolean available = secureStorage.isBiometricAvailable();
                                result.success(available);
                                break;
                            }
                            case "isDeviceSecure": {
                                boolean secure = secureStorage.isDeviceSecure();
                                result.success(secure);
                                break;
                            }
                            default:
                                result.notImplemented();
                                break;
                        }
                    } catch (Exception e) {
                        if (config.shouldDeleteOnFailure()) {
                            try {
                                secureStorage.deleteAll();
                                result.success("Data has been reset");
                            } catch (Exception ex) {
                                handleException(ex);
                            }
                        } else {
                            handleException(e);
                        }
                    }
                }

                @Override
                public void onError(Exception e) {
                    if (isDeleteOperation(call.method) && isKeyInvalidatedError(e)) {
                        try {
                            Log.w(
                                    TAG,
                                    "Initialization failed with KEY_INVALIDATED during " + call.method +
                                            ". Forcing namespace reset for manual recovery."
                            );
                            secureStorage.forceResetCurrentStorage();
                            result.success(null);
                            return;
                        } catch (Exception resetError) {
                            handleException(resetError);
                            return;
                        }
                    }
                    handleException(e);
                }
            });
        }


        private void handleException(Exception e) {
            String errorCode = resolveErrorCode(e);
            String errorMessage = e.getMessage() != null ? e.getMessage() : "Unknown error";
            Log.e(TAG, "Secure storage error [" + errorCode + "]: " + errorMessage, e);
            result.error(errorCode, errorMessage, null);
        }

        private String resolveErrorCode(Exception e) {
            SecureStorageException storageException = SecureStorageException.from(e);
            return storageException != null
                    ? storageException.getCode()
                    : classifyErrorCode(e);
        }

        private boolean isDeleteOperation(String method) {
            return "delete".equals(method) || "deleteAll".equals(method);
        }

        private boolean isKeyInvalidatedError(Exception e) {
            return SecureStorageException.CODE_KEY_INVALIDATED.equals(resolveErrorCode(e));
        }

        private String classifyErrorCode(Exception e) {
            if (hasCauseType(e, "android.security.keystore.KeyPermanentlyInvalidatedException")) {
                return SecureStorageException.CODE_KEY_INVALIDATED;
            }
            if (hasCauseType(e, "android.security.keystore.UserNotAuthenticatedException")) {
                return SecureStorageException.CODE_AUTH_CANCELLED;
            }
            return SecureStorageException.CODE_UNKNOWN;
        }

        private boolean hasCauseType(Throwable throwable, String className) {
            Throwable cursor = throwable;
            while (cursor != null) {
                if (className.equals(cursor.getClass().getName())) {
                    return true;
                }
                cursor = cursor.getCause();
            }
            return false;
        }
    }
}
