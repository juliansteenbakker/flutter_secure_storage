package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

public class FlutterSecureStoragePlugin implements MethodCallHandler, FlutterPlugin {

    private static final String TAG = "FlutterSecureStoragePl";
    private MethodChannel channel;
    private FlutterSecureStorage secureStorage;
    private HandlerThread workerThread;
    private Handler workerThreadHandler;

    public void initInstance(BinaryMessenger messenger, Context context) {
        try {
            secureStorage = new FlutterSecureStorage(context, new HashMap<>());

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

        private final Result methodResult;
        private final Handler handler = new Handler(Looper.getMainLooper());

        MethodResultWrapper(Result methodResult) {
            this.methodResult = methodResult;
        }

        @Override
        public void success(final Object result) {
            handler.post(() -> methodResult.success(result));
        }

        @Override
        public void error(@NonNull final String errorCode, final String errorMessage, final Object errorDetails) {
            handler.post(() -> methodResult.error(errorCode, errorMessage, errorDetails));
        }

        @Override
        public void notImplemented() {
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
            boolean resetOnError = false;
            try {
                secureStorage.options = (Map<String, Object>) ((Map<String, Object>) call.arguments).get("options");
                secureStorage.ensureOptions();
                resetOnError = secureStorage.getResetOnError();
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
                    default:
                        result.notImplemented();
                        break;
                }
            } catch (FileNotFoundException e) {
                Log.i("Creating sharedPrefs", e.getLocalizedMessage());
            } catch (Exception e) {
                if (resetOnError) {
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

        private void handleException(Exception e) {
            StringWriter stringWriter = new StringWriter();
            e.printStackTrace(new PrintWriter(stringWriter));
            result.error("Exception encountered", call.method, stringWriter.toString());
        }
    }
}
