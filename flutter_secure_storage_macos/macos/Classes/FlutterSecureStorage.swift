//
//  FlutterSecureStorage.swift
//  flutter_secure_storage_macos
//
//  Created by Julian Steenbakker on 09/12/2022.
//

import Foundation

class FlutterSecureStorage{
    private func parseAccessibleAttr(accessibility: String?) -> CFString {
        guard let accessibility = accessibility else {
            return kSecAttrAccessibleWhenUnlocked
        }

        switch accessibility {
        case "passcode":
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case "unlocked":
            return kSecAttrAccessibleWhenUnlocked
        case "unlocked_this_device":
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case "first_unlock":
            return kSecAttrAccessibleAfterFirstUnlock
        case "first_unlock_this_device":
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        default:
            return kSecAttrAccessibleWhenUnlocked
        }
    }

    private func baseQuery(key: String?, groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool, returnData: Bool?) -> Dictionary<CFString, Any> {
        var keychainQuery: [CFString: Any] = [
            kSecClass : kSecClassGenericPassword,
            kSecAttrAccessible : parseAccessibleAttr(accessibility: accessibility),
            kSecAttrSynchronizable : synchronizable,
        ]
        if #available(macOS 10.15, *) {
            keychainQuery[kSecUseDataProtectionKeychain] = useDataProtectionKeyChain
        }

        if (key != nil) {
            keychainQuery[kSecAttrAccount] = key
        }

        if (groupId != nil) {
            keychainQuery[kSecAttrAccessGroup] = groupId
        }

        if (accountName != nil) {
            keychainQuery[kSecAttrService] = accountName
        }

        if (returnData != nil) {
            keychainQuery[kSecReturnData] = returnData
        }
        return keychainQuery
    }

    internal func containsKey(key: String, groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool) -> Result<Bool, OSSecError> {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain, returnData: false)

        let status = SecItemCopyMatching(keychainQuery as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return .success(true)
        case errSecItemNotFound:
            return .success(false)
        default:
            return .failure(OSSecError(status: status))
        }
    }

    internal func readAll(groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool) -> FlutterSecureStorageResponse {
        var keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain, returnData: true)

        keychainQuery[kSecMatchLimit] = kSecMatchLimitAll
        keychainQuery[kSecReturnAttributes] = true

        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )

        if (status == errSecItemNotFound) {
            // readAll() returns all elements, so return nil if the items does not exist
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        var results: [String: String] = [:]

        if (status == noErr) {
            (ref as! NSArray).forEach { item in
                let key: String = (item as! NSDictionary)[kSecAttrAccount] as! String
                let value: String = String(data: (item as! NSDictionary)[kSecValueData] as! Data, encoding: .utf8) ?? ""
                results[key] = value
            }
        }

        return FlutterSecureStorageResponse(status: status, value: results)
    }

    internal func read(key: String, groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain, returnData: true)

        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )

        // Return nil if the key is not found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        var value: String? = nil

        if (status == noErr) {
            value = String(data: ref as! Data, encoding: .utf8)
        }

        return FlutterSecureStorageResponse(status: status, value: value)
    }

    internal func deleteAll(groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain, returnData: nil)
        let status = SecItemDelete(keychainQuery as CFDictionary)

        if (status == errSecItemNotFound) {
            // deleteAll() deletes all items, so return nil if the items does not exist
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        return FlutterSecureStorageResponse(status: status, value: nil)
    }

    internal func delete(key: String, groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain, returnData: true)
        let status = SecItemDelete(keychainQuery as CFDictionary)

        // Return nil if the key is not found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        return FlutterSecureStorageResponse(status: status, value: nil)
    }

    internal func write(key: String, value: String, groupId: String?, accountName: String?, synchronizable: Bool, accessibility: String?, useDataProtectionKeyChain: Bool) -> FlutterSecureStorageResponse {
        var keyExists: Bool = false

    	switch containsKey(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain) {
        case .success(let exists):
            keyExists = exists
            break;
        case .failure(let err):
            return FlutterSecureStorageResponse(status: err.status, value: nil)
        }

        let attrAccessible = parseAccessibleAttr(accessibility: accessibility);
        var keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, useDataProtectionKeyChain: useDataProtectionKeyChain, returnData: nil)

        if (keyExists) {


            var update: [CFString: Any?] = [
                kSecValueData: value.data(using: String.Encoding.utf8),
                kSecAttrAccessible: attrAccessible,
                kSecAttrSynchronizable: synchronizable
            ]
            if #available(macOS 10.15, *) {
                update[kSecUseDataProtectionKeychain] = useDataProtectionKeyChain
            }

            let status = SecItemUpdate(keychainQuery as CFDictionary, update as CFDictionary)

            return FlutterSecureStorageResponse(status: status, value: nil)
        } else {
            keychainQuery[kSecValueData] = value.data(using: String.Encoding.utf8)
            keychainQuery[kSecAttrAccessible] = attrAccessible
            if #available(macOS 10.15, *) {
                keychainQuery[kSecUseDataProtectionKeychain] = useDataProtectionKeyChain
            }

            let status = SecItemAdd(keychainQuery as CFDictionary, nil)

            return FlutterSecureStorageResponse(status: status, value: nil)
        }
    }
}

struct FlutterSecureStorageResponse {
    var status: OSStatus?
    var value: Any?
}

struct OSSecError: Error {
    var status: OSStatus
}
