//
//  SwiftFlutterSecureStoragePlugin.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Flutter
import UIKit

public class SwiftFlutterSecureStoragePlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private let flutterSecureStorageManager: FlutterSecureStorage = FlutterSecureStorage()
    private var secStoreAvailabilitySink: FlutterEventSink?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "plugins.it_nomads.com/flutter_secure_storage", binaryMessenger: registrar.messenger())
        let eventChannel = FlutterEventChannel(name: "plugins.it_nomads.com/flutter_secure_storage/events", binaryMessenger: registrar.messenger())
        let instance = SwiftFlutterSecureStoragePlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        registrar.addApplicationDelegate(instance)
        eventChannel.setStreamHandler(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        func handleResult(_ value: Any?) {
            DispatchQueue.main.async {
                result(value)
            }
        }

        DispatchQueue.global(qos: .userInitiated).async {
            switch (call.method) {
            case "read":
                self.read(call, handleResult)
            case "write":
                self.write(call, handleResult)
            case "delete":
                self.delete(call, handleResult)
            case "deleteAll":
                self.deleteAll(call, handleResult)
            case "readAll":
                self.readAll(call, handleResult)
            case "containsKey":
                self.containsKey(call, handleResult)
            case "isProtectedDataAvailable":
                // UIApplication is not thread safe
                DispatchQueue.main.async {
                    result(UIApplication.shared.isProtectedDataAvailable)
                }
            default:
                handleResult(FlutterMethodNotImplemented)
            }
        }
    }

    public func applicationProtectedDataDidBecomeAvailable(_ application: UIApplication) {
        guard let sink = secStoreAvailabilitySink else {
            return
        }

        sink(true)
    }

    public func applicationProtectedDataWillBecomeUnavailable(_ application: UIApplication) {
        guard let sink = secStoreAvailabilitySink else {
            return
        }

        sink(false)
    }

    public func onListen(withArguments arguments: Any?,
                         eventSink: @escaping FlutterEventSink) -> FlutterError? {
        self.secStoreAvailabilitySink = eventSink
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        self.secStoreAvailabilitySink = nil
        return nil
    }

    private func read(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "write requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.read(key: values.key!, groupId: values.groupId, accountName: values.accountName)
        handleResponse(response, result)
    }

    private func write(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        if (!((call.arguments as! [String : Any?])["value"] is String)){
            result(FlutterError.init(code: "Invalid Parameter", message: "key parameter must be String", details: nil))
            return;
        }

        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "write requires key parameter", details: nil))
            return
        }

        if (values.value == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "write requires value parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.write(key: values.key!, value: values.value!, groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility)

        handleResponse(response, result)
    }

    private func delete(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "delete requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.delete(key: values.key!, groupId: values.groupId, accountName: values.accountName)

        handleResponse(response, result)
    }

    private func deleteAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        let response = flutterSecureStorageManager.deleteAll(groupId: values.groupId, accountName: values.accountName)

        handleResponse(response, result)
    }

    private func readAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        let response = flutterSecureStorageManager.readAll(groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility)

        handleResponse(response, result)
    }

    private func containsKey(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "containsKey requires key parameter", details: nil))
        }

        let response = flutterSecureStorageManager.containsKey(key: values.key!, groupId: values.groupId, accountName: values.accountName)

        switch response {
        case .success(let exists):
            result(exists)
            break;
        case .failure(let err):
            var errorMessage = ""

            if #available(iOS 11.3, *) {
                if let errMsg = SecCopyErrorMessageString(err.status, nil) {
                    errorMessage = "Code: \(err.status), Message: \(errMsg)"
                } else {
                    errorMessage = "Unknown security result code: \(err.status)"
                }
            } else {
                errorMessage = "Unknown security result code: \(err.status)"
            }
            result(FlutterError.init(code: "Unexpected security result code", message: errorMessage, details: err.status))
            break;
        }
    }

    private func parseCall(_ call: FlutterMethodCall) -> FlutterSecureStorageRequest {
        let arguments = call.arguments as! [String : Any?]
        let options = arguments["options"] as! [String : Any?]

        let accountName = options["accountName"] as? String
        let groupId = options["groupId"] as? String
        let synchronizableString = options["synchronizable"] as? String

        let synchronizable: Bool = synchronizableString != nil ? Bool(synchronizableString!)! : false

        let key = arguments["key"] as? String
        let accessibility = options["accessibility"] as? String
        let value = arguments["value"] as? String

        return FlutterSecureStorageRequest(
            accountName: accountName,
            groupId: groupId,
            synchronizable: synchronizable,
            accessibility: accessibility,
            key: key,
            value: value
        )
    }

    private func handleResponse(_ response: FlutterSecureStorageResponse, _ result: @escaping FlutterResult) {
        if let status = response.status {
            if (status == noErr) {
                result(response.value)
            } else {
                var errorMessage = ""

                if #available(iOS 11.3, *) {
                    if let errMsg = SecCopyErrorMessageString(status, nil) {
                        errorMessage = "Code: \(status), Message: \(errMsg)"
                    } else {
                        errorMessage = "Unknown security result code: \(status)"
                    }
                } else {
                    errorMessage = "Unknown security result code: \(status)"
                }
                result(FlutterError.init(code: "Unexpected security result code", message: errorMessage, details: status))
            }
        } else {
            result(response.value)
        }
    }

    struct FlutterSecureStorageRequest {
        var accountName: String?
        var groupId: String?
        var synchronizable: Bool?
        var accessibility: String?
        var key: String?
        var value: String?
    }
}
