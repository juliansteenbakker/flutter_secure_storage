//
//  FlutterSecureStoragePlugin.swift
//  flutter_secure_storage_macos
//
//  Created by Julian Steenbakker on 09/12/2022.
//

import FlutterMacOS

public class FlutterSecureStoragePlugin: NSObject, FlutterPlugin {
    
    private let flutterSecureStorageManager: FlutterSecureStorage = FlutterSecureStorage()
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "plugins.it_nomads.com/flutter_secure_storage", binaryMessenger: registrar.messenger)
        let instance = FlutterSecureStoragePlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch (call.method) {
        case "read":
            read(call, result)
        case "write":
            write(call, result)
        case "delete":
            delete(call, result)
        case "deleteAll":
            deleteAll(call, result)
        case "readAll":
            readAll(call, result)
        case "containsKey":
            containsKey(call, result)
        case "isProtectedDataAvailable":
            // NSApplication is not thread safe
            DispatchQueue.main.async {
                if #available(macOS 12.0, *) {
                    result(NSApplication.shared.isProtectedDataAvailable)
                } else {
                    result(true)
                }
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    private func read(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "write requires key parameter", details: nil))
            return
        }
        
        let response = flutterSecureStorageManager.read(key: values.key!, groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility, useDataProtectionKeyChain: values.useDataProtectionKeyChain)
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
        
        let response = flutterSecureStorageManager.write(key: values.key!, value: values.value!, groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility, useDataProtectionKeyChain: values.useDataProtectionKeyChain)
        
        handleResponse(response, result)
    }
    
    private func delete(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "delete requires key parameter", details: nil))
            return
        }
        
        let response = flutterSecureStorageManager.delete(key: values.key!, groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility, useDataProtectionKeyChain: values.useDataProtectionKeyChain)
        
        handleResponse(response, result)
    }
    
    private func deleteAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        let response = flutterSecureStorageManager.deleteAll(groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility, useDataProtectionKeyChain: values.useDataProtectionKeyChain)
        
        handleResponse(response, result)
    }
    
    private func readAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        let response = flutterSecureStorageManager.readAll(groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility, useDataProtectionKeyChain: values.useDataProtectionKeyChain)
        
        handleResponse(response, result)
    }
    
    private func containsKey(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let values = parseCall(call)
        if (values.key == nil) {
            result(FlutterError.init(code: "Missing Parameter", message: "containsKey requires key parameter", details: nil))
        }
        
        let response = flutterSecureStorageManager.containsKey(key: values.key!, groupId: values.groupId, accountName: values.accountName, synchronizable: values.synchronizable, accessibility: values.accessibility, useDataProtectionKeyChain: values.useDataProtectionKeyChain)
        
        switch response {
        case .success(let exists):
            result(exists)
            break;
        case .failure(let err):
            var errorMessage = ""

            if let errMsg = SecCopyErrorMessageString(err.status, nil) as? String {
                errorMessage = "Code: \(err.status), Message: \(errMsg)"
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
        let useDataProtectionKeyChainString = options["useDataProtectionKeyChain"] as? String
        
        let synchronizable: Bool = synchronizableString != nil ? Bool(synchronizableString!)! : false
        let useDataProtectionKeyChain: Bool = useDataProtectionKeyChainString != nil ? Bool(useDataProtectionKeyChainString!)! : true
        
        let key = arguments["key"] as? String
        let accessibility = options["accessibility"] as? String
        let value = arguments["value"] as? String
        
        return FlutterSecureStorageRequest(
            accountName: accountName,
            groupId: groupId,
            synchronizable: synchronizable,
            useDataProtectionKeyChain: useDataProtectionKeyChain,
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

                if let errMsg = SecCopyErrorMessageString(status, nil) as? String {
                    errorMessage = "Code: \(status), Message: \(errMsg)"
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
        var synchronizable: Bool
        var useDataProtectionKeyChain: Bool
        var accessibility: String?
        var key: String?
        var value: String?
    }
    
}
