package com.it_nomads.fluttersecurestorage;

import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;

import androidx.annotation.NonNull;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

public class FlutterSecureStoragePlugin implements MethodCallHandler, FlutterPlugin {

    private MethodChannel channel;
    private FlutterSecureStorage secureStorage;
    private HandlerThread workerThread;
    private Handler workerThreadHandler;
    private FlutterPluginBinding binding;

    @Override
    public void onAttachedToEngine(FlutterPluginBinding binding) {
        this.binding = binding;
        workerThread = new HandlerThread("fluttersecurestorage.worker");
        workerThread.start();
        workerThreadHandler = new Handler(workerThread.getLooper());
        channel = new MethodChannel(binding.getBinaryMessenger(), "plugins.it_nomads.com/flutter_secure_storage");
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        if (channel != null) {
            if (workerThread != null) {
                workerThread.quitSafely();
                workerThread = null;
            }
            channel.setMethodCallHandler(null);
            channel = null;
        }
        secureStorage = null;
    }

    private boolean initSecureStorage(Result result, Map<String, Object> options) {
        if (secureStorage != null) return true;

        try {
            secureStorage = new FlutterSecureStorage(binding.getApplicationContext(), options);
            return true;
        } catch (Exception e) {
            if (result != null) {
                result.error(
                        "RESET_FAILED",  // Error code
                        "Failed to reset and initialize encrypted preferences", // Error message
                        e.toString()     // Details (stack trace or additional info)
                );
            }
            return false;
        }
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result rawResult) {
        MethodResultWrapper result = new MethodResultWrapper(rawResult);
        workerThreadHandler.post(new MethodRunner(call, result));
    }

    class MethodRunner implements Runnable {
        private final MethodCall call;
        private final Result result;

        MethodRunner(MethodCall call, Result result) {
            this.call = call;
            this.result = result;
        }

        @Override
        public void run() {
            try {
                handleMethodCall(call, result);
            } catch (Exception e) {
                handleException(e);
            }
        }

        private void handleMethodCall(MethodCall call, Result result) {
            String method = call.method;
            Map<String, Object> arguments = call.arguments();

            if (arguments == null) {
                result.error("InvalidArgument", "No arguments passed to method call", null);
                return;
            }

            Map<String, Object> options = extractMapFromObject(arguments.get("options"));

            boolean isInitialized = initSecureStorage(result, options);
            if (!isInitialized) return;

            switch (method) {
                case "write":
                    handleWrite(arguments, result);
                    break;
                case "read":
                    handleRead(arguments, result);
                    break;
                case "readAll":
                    handleReadAll(result);
                    break;
                case "containsKey":
                    handleContainsKey(arguments, result);
                    break;
                case "delete":
                    handleDelete(arguments, result);
                    break;
                case "deleteAll":
                    handleDeleteAll(result);
                    break;
                case "isStrongBoxSupported":
                    handleStrongBoxAvailable(result);
                    break;
                default:
                    result.notImplemented();
            }
        }

        private void handleWrite(Map<String, Object> args, Result result) {
            String key = (String) args.get("key");
            String value = (String) args.get("value");
            if (value != null) {
                secureStorage.write(key, value);
                result.success(null);
            } else {
                result.error("InvalidArgument", "Value is null", null);
            }
        }

        private void handleRead(Map<String, Object> args, Result result) {
            String key = (String) args.get("key");
            result.success(secureStorage.read(key));
        }

        private void handleReadAll(Result result) {
            result.success(secureStorage.readAll());
        }

        private void handleContainsKey(Map<String, Object> args, Result result) {
            String key = (String) args.get("key");
            result.success(secureStorage.containsKey(key));
        }

        private void handleDelete(Map<String, Object> args, Result result) {
            String key = (String) args.get("key");
            secureStorage.delete(key);
            result.success(null);
        }

        private void handleDeleteAll(Result result) {
            secureStorage.deleteAll();
            result.success(null);
        }

        private void handleStrongBoxAvailable(Result result) {
            result.success(secureStorage.isStrongBoxAvailable());
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> extractMapFromObject(Object object) {
            if (!(object instanceof Map)) {
                return new HashMap<>();
            }
            return (Map<String, Object>) object;
        }

        private void handleException(Exception e) {
            StringWriter stringWriter = new StringWriter();
            e.printStackTrace(new PrintWriter(stringWriter));
            result.error("Exception", "Error while executing method: " + call.method, stringWriter.toString());
        }
    }

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
}
