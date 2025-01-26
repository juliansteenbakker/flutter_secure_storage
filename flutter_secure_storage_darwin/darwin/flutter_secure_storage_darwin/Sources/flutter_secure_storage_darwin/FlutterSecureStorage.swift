//
//  FlutterSecureStorage.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Foundation

/// Represents the parameters for keychain queries.
struct KeychainQueryParameters {
    /// `kSecAttrAccount` (iOS/macOS): The account identifier for the item in the keychain.
    var key: String?
    
    /// `kSecAttrAccessGroup` (iOS only): The access group for the item, used for app group sharing.
    var accessGroup: String?
    
    /// `kSecAttrService` (iOS/macOS): The service or application name associated with the item.
    var service: String?
    
    /// `kSecAttrSynchronizable` (iOS/macOS): Indicates whether the item is synchronized with iCloud.
    var isSynchronizable: Bool?
    
    /// `kSecAttrAccessible` (iOS/macOS): The accessibility level of the item (e.g., when unlocked, after first unlock).
    var accessibilityLevel: String?
    
    /// `kSecUseDataProtectionKeychain` (macOS only): Indicates whether the data protection keychain is used.
    var usesDataProtectionKeychain: Bool
    
    /// `kSecReturnData` (iOS/macOS): Indicates whether the item's data should be returned in queries.
    var shouldReturnData: Bool?
    
    /// `kSecAttrLabel` (iOS/macOS): A user-visible label for the keychain item.
    var itemLabel: String?
    
    /// `kSecAttrDescription` (iOS/macOS): A description of the keychain item.
    var itemDescription: String?
    
    /// `kSecAttrComment` (iOS/macOS): A comment associated with the keychain item.
    var itemComment: String?
    
    /// `kSecAttrIsInvisible` (iOS/macOS): Indicates whether the item is hidden from user-visible lists.
    var isHidden: Bool?
    
    /// `kSecAttrIsNegative` (iOS/macOS): Indicates whether the item is a placeholder or negative entry.
    var isPlaceholder: Bool?
    
    /// `kSecAttrCreationDate` (iOS/macOS): The creation date of the keychain item.
    var creationDate: Date?
    
    /// `kSecAttrModificationDate` (iOS/macOS): The last modification date of the keychain item.
    var lastModifiedDate: Date?
    
    /// `kSecMatchLimit` (iOS/macOS): Specifies the maximum number of results to return in a query (e.g., one or all).
    var resultLimit: Int?
    
    /// `kSecReturnPersistentRef` (iOS/macOS): Indicates whether to return a persistent reference to the keychain item.
    var shouldReturnPersistentReference: Bool?
    
    /// `kSecUseAuthenticationUI` (iOS/macOS): Controls how authentication UI is presented during secure operations.
    var authenticationUIBehavior: String?
    
    /// `accessControlFlags` (iOS/macOS): Specifies access control settings (e.g., biometrics, passcode).
    var accessControlFlags: String?
}

/// Represents the response from a keychain operation.
struct FlutterSecureStorageResponse {
    var status: OSStatus // The status of the keychain operation.
    var value: Any?      // The value retrieved or modified in the keychain.
}

/// Represents an error in keychain operations.
struct OSSecError: Error {
    var status: OSStatus // The error code from the keychain.
    var message: String?
}

class FlutterSecureStorage {
    /// Parses the accessibility attribute into a CFString value.
    private func parseAccessibleAttr(_ accessibilityLevel: String?) -> CFString {
        switch accessibilityLevel {
        case "passcode": return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case "unlocked": return kSecAttrAccessibleWhenUnlocked
        case "unlocked_this_device": return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case "first_unlock": return kSecAttrAccessibleAfterFirstUnlock
        case "first_unlock_this_device": return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        default: return kSecAttrAccessibleWhenUnlocked
        }
    }
    
    /// Parses a string of comma-separated access control flags into SecAccessControlCreateFlags.
    private func parseAccessControlFlags(_ flagString: String?) -> SecAccessControlCreateFlags {
        guard let flagString = flagString else { return [] }
        var flags: SecAccessControlCreateFlags = []
        let flagList = flagString.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        for dirtyFlag in flagList {
            let flag = dirtyFlag.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
               
            switch flag {
            case "userPresence":
                flags.insert(.userPresence)
            case "biometryAny":
                flags.insert(.biometryAny)
            case "biometryCurrentSet":
                flags.insert(.biometryCurrentSet)
            case "devicePasscode":
                flags.insert(.devicePasscode)
            case "or":
                flags.insert(.or)
            case "and":
                flags.insert(.and)
            case "privateKeyUsage":
                flags.insert(.privateKeyUsage)
            case "applicationPassword":
                flags.insert(.applicationPassword)
            default:
                continue
            }
        }
        return flags
    }
    
    /// Creates an access control object based on the provided parameters.
    private func createAccessControl(params: KeychainQueryParameters) -> SecAccessControl? {
        guard let accessibilityLevel = params.accessibilityLevel else { return nil }
        let protection = parseAccessibleAttr(accessibilityLevel)
        let flags = parseAccessControlFlags(params.accessControlFlags)
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(nil, protection, flags, &error)
        if let error = error?.takeRetainedValue() {
            print("Error creating access control: \(error.localizedDescription)")
            return nil
        }
        return accessControl
    }

    /// Constructs a keychain query dictionary from the given parameters.
    private func baseQuery(from params: KeychainQueryParameters) -> [CFString: Any] {
        // Validate parameters
        do {
            try validateQueryParameters(params: params)
        } catch {
            fatalError("Validation failed: \(error)")
        }
        
        var query: [CFString: Any] = [kSecClass: kSecClassGenericPassword]
        
        if let account = params.key {
            query[kSecAttrAccount] = account
        }
        
        if let service = params.service {
            query[kSecAttrService] = service
        }

        if let shouldReturnData = params.shouldReturnData {
            query[kSecReturnData] = shouldReturnData
        }

        if let itemLabel = params.itemLabel {
            query[kSecAttrLabel] = itemLabel
        }

        if let itemDescription = params.itemDescription {
            query[kSecAttrDescription] = itemDescription
        }

        if let itemComment = params.itemComment {
            query[kSecAttrComment] = itemComment
        }

        if let isHidden = params.isHidden {
            query[kSecAttrIsInvisible] = isHidden
        }

        if let isPlaceholder = params.isPlaceholder {
            query[kSecAttrIsNegative] = isPlaceholder
        }

        if let resultLimit = params.resultLimit {
            query[kSecMatchLimit] = resultLimit == 1 ? kSecMatchLimitOne : kSecMatchLimitAll
        }

        if let shouldReturnPersistentReference = params.shouldReturnPersistentReference {
            query[kSecReturnPersistentRef] = shouldReturnPersistentReference
        }

        if let authenticationUIBehavior = params.authenticationUIBehavior {
            query[kSecUseAuthenticationUI] = authenticationUIBehavior
        }

        if let accessControl = createAccessControl(params: params) {
            query[kSecAttrAccessControl] = accessControl
        } else {
            if let accessibilityLevel = params.accessibilityLevel {
                query[kSecAttrAccessible] = parseAccessibleAttr(accessibilityLevel)
            }
            if let isSynchronizable = params.isSynchronizable {
                query[kSecAttrSynchronizable] = isSynchronizable
            }
        }
        
        #if os(macOS)
        if #available(macOS 10.15, *) {
            query[kSecUseDataProtectionKeychain] = params.usesDataProtectionKeychain
        }
        #endif
        
        #if os(iOS)
        if let accessGroup = params.accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        #endif

        return query
    }
    
    private func validateQueryParameters(params: KeychainQueryParameters) throws {
        // Match limit
        if params.resultLimit == 1, params.shouldReturnData == true {
            throw OSSecError(status: errSecParam, message: "Cannot use kSecMatchLimitAll when expecting a single result with kSecReturnData.")
        }

        // Invisible and negative
        if params.isHidden == true, params.isPlaceholder == true {
            throw OSSecError(status: errSecParam, message: "Cannot use both kSecAttrIsInvisible and kSecAttrIsNegative together.")
        }

        // Persistent reference
        if params.shouldReturnPersistentReference == true, params.shouldReturnData == true {
            throw OSSecError(status: errSecParam, message: "Cannot use kSecReturnPersistentRef and kSecReturnData together.")
        }
    }

    /// Checks if a key exists in the keychain.
    /// This function checks both synchronizable and non-synchronizable states.
    internal func containsKey(params: KeychainQueryParameters) -> Result<Bool, OSSecError> {
        /// Helper function to query the keychain.
        func queryKeychain(withSynchronizable synchronizable: Bool?) -> OSStatus {
            var modifiedParams = params
            modifiedParams.isSynchronizable = synchronizable // Modify the synchronizable parameter for the query.
            modifiedParams.shouldReturnData = false              // Ensuring no data is returned.
            let query = baseQuery(from: modifiedParams)
            return SecItemCopyMatching(query as CFDictionary, nil)
        }

        // Check synchronizable items first.
        let statusSync = queryKeychain(withSynchronizable: true)
        if statusSync == errSecSuccess {
            return .success(true)
        } else if statusSync != errSecItemNotFound {
            return .failure(OSSecError(status: statusSync))
        }

        // Check non-synchronizable items.
        let statusNonSync = queryKeychain(withSynchronizable: false)
        if statusNonSync == errSecSuccess {
            return .success(true)
        } else if statusNonSync == errSecItemNotFound {
            return .success(false)
        } else {
            return .failure(OSSecError(status: statusNonSync))
        }
    }

    /// Reads all items from the keychain matching the query parameters.
    internal func readAll(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        var query = baseQuery(from: params)
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnAttributes] = true

        var ref: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &ref)

        // Return nil if nothing is found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        guard status == errSecSuccess else {
            return FlutterSecureStorageResponse(status: status, value: nil)
        }

        var results: [String: String] = [:]
        if let items = ref as? [[CFString: Any]] {
            for item in items {
                if let key = item[kSecAttrAccount] as? String,
                   let data = item[kSecValueData] as? Data,
                   let value = String(data: data, encoding: .utf8) {
                    results[key] = value
                }
            }
        }

        return FlutterSecureStorageResponse(status: status, value: results)
    }

    /// Reads a single item from the keychain.
    internal func read(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        let query = baseQuery(from: params)
        var ref: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &ref)
        
        // Return nil if nothing is found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        guard status == errSecSuccess, let data = ref as? Data else {
            return FlutterSecureStorageResponse(status: status, value: nil)
        }

        let value = String(data: data, encoding: .utf8)
        return FlutterSecureStorageResponse(status: status, value: value)
    }

    /// Writes an item to the keychain. Updates if the key already exists.
    internal func write(params: KeychainQueryParameters, value: String) -> FlutterSecureStorageResponse {
        let keyExists = (containsKey(params: params).getOrElse(false))
        var query = baseQuery(from: params)

        if keyExists {
            let update: [CFString: Any] = [kSecValueData: value.data(using: .utf8) as Any]
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)

            if status == errSecSuccess {
                return FlutterSecureStorageResponse(status: status, value: nil)
            } else {
                _ = delete(params: params)
            }
        }

        query[kSecValueData] = value.data(using: .utf8)
        let status = SecItemAdd(query as CFDictionary, nil)
        return FlutterSecureStorageResponse(status: status, value: nil)
    }

    /// Deletes an item from the keychain.
    internal func delete(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        let query = baseQuery(from: params)
        let status = SecItemDelete(query as CFDictionary)
        // Return nil if nothing is found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        return FlutterSecureStorageResponse(status: status, value: nil)
    }

    /// Deletes all items matching the query parameters.
    internal func deleteAll(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        let query = baseQuery(from: params)
        let status = SecItemDelete(query as CFDictionary)
        // Return nil if nothing is found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
    
    internal func getPersistentReference(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        var query = baseQuery(from: params)
        query[kSecReturnPersistentRef] = true

        var ref: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &ref)
        return FlutterSecureStorageResponse(status: status, value: ref)
    }

    internal func getItemFromPersistentReference(_ persistentRef: Data) -> FlutterSecureStorageResponse {
        let query: [CFString: Any] = [
            kSecValuePersistentRef: persistentRef,
            kSecReturnAttributes: true,
            kSecReturnData: true
        ]

        var ref: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &ref)
        return FlutterSecureStorageResponse(status: status, value: ref)
    }
}

extension Result where Success == Bool, Failure == OSSecError {
    /// Extracts the value from the result or returns a default value in case of an error.
    func getOrElse(_ defaultValue: Bool) -> Bool {
        switch self {
        case .success(let value): return value
        case .failure: return defaultValue
        }
    }
}
