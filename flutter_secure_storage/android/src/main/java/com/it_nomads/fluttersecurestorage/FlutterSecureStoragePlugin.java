package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

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

    @Override
    public void onAttachedToEngine(FlutterPluginBinding binding) {
        initInstance(binding.getBinaryMessenger(), binding.getApplicationContext());
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

    private void initInstance(BinaryMessenger messenger, Context context) {
        try {
            secureStorage = new FlutterSecureStorage(context, new HashMap<>());
            workerThread = new HandlerThread("fluttersecurestorage.worker");
            workerThread.start();
            workerThreadHandler = new Handler(workerThread.getLooper());
            channel = new MethodChannel(messenger, "plugins.it_nomads.com/flutter_secure_storage");
            channel.setMethodCallHandler(this);
        } catch (Exception e) {
            Log.e(TAG, "Plugin initialization failed", e);
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
            Map<String, Object> args = extractArguments(call);

            switch (method) {
                case "write":
                    handleWrite(args, result);
                    break;
                case "read":
                    handleRead(args, result);
                    break;
                case "readAll":
                    handleReadAll(result);
                    break;
                case "containsKey":
                    handleContainsKey(args, result);
                    break;
                case "delete":
                    handleDelete(args, result);
                    break;
                case "deleteAll":
                    handleDeleteAll(result);
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
            if (secureStorage.containsKey(key)) {
                result.success(secureStorage.read(key));
            } else {
                result.success(null);
            }
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

        @SuppressWarnings("unchecked")
        private Map<String, Object> extractArguments(MethodCall call) {
            return (Map<String, Object>) call.arguments;
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
