//
//  FlutterSecureStorage.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Foundation
import Security
import CryptoKit
import LocalAuthentication

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

    /// Reusable authentication context to allow biometric reuse within one operation.
    var authenticationContext: LAContext?

    /// `accessControlFlags` (iOS/macOS): Specifies access control settings (e.g., biometrics, passcode).
    var accessControlFlags: String?

    /// `useSecureEnclave` (iOS/macOS): Indicates whether the Secure Enclave for cryptographic key operations when available is used.
    var useSecureEnclave: Bool?
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
        // Without flags, skip SecAccessControl so kSecAttrSynchronizable is not silently dropped by the Security framework.
        guard let flagString = params.accessControlFlags, !flagString.isEmpty else { return nil }
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

        if let authenticationContext = params.authenticationContext {
            query[kSecUseAuthenticationContext] = authenticationContext
        }

        // If Secure Enclave style gating requested but no flags provided,
        // default to requiring user presence (biometry or passcode).
        var effectiveParams = params
        if (params.useSecureEnclave ?? false) && (params.accessControlFlags == nil || params.accessControlFlags?.isEmpty == true) {
            effectiveParams.accessControlFlags = "userPresence"
        }

        if let accessControl = createAccessControl(params: effectiveParams) {
            query[kSecAttrAccessControl] = accessControl
        } else {
            if let accessibilityLevel = effectiveParams.accessibilityLevel {
                query[kSecAttrAccessible] = parseAccessibleAttr(accessibilityLevel)
            }
            // Avoid synchronizable when device-bound enforcement is desired.
            if let isSynchronizable = effectiveParams.isSynchronizable, !(effectiveParams.useSecureEnclave ?? false) {
                query[kSecAttrSynchronizable] = isSynchronizable
            }
        }
        
        #if os(macOS)
        if #available(macOS 10.15, *), params.usesDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain] = true
        }
        #endif
        
        #if os(iOS)
        if let accessGroup = params.accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        #endif

        return query
    }

    // MARK: - Secure Enclave Helpers

    /// Constructs a stable tag for the Secure Enclave private key for a given service.
    private func enclaveKeyTag(for service: String?) -> Data {
        let serviceLabel = service ?? "flutter_secure_storage_service"
        return ("fss.enclave." + serviceLabel).data(using: .utf8)!
    }

    /// Ensures a Secure Enclave EC private key exists for the provided service, creating it if needed.
    /// The private key uses hardcoded access control with .privateKeyUsage to allow crypto operations
    /// without requiring user authentication (authentication is handled at the data item level).
    @available(iOS 13.0, macOS 10.15, *)
    private func ensureEnclavePrivateKey(service: String?) throws -> SecKey {
        let tag = enclaveKeyTag(for: service) as CFData

        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: tag,
            kSecReturnRef: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let item = item {
            return (item as! SecKey)
        }

        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag
            ]
        ]
        // Use hardcoded access control with .privateKeyUsage for the SE private key.
        // This allows crypto operations without user authentication prompts.
        // User authentication is handled at the data item level via accessControlFlags.
        let keyAccessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )
        if let ac = keyAccessControl {
            var privateAttrs = attributes[kSecPrivateKeyAttrs] as! [CFString: Any]
            privateAttrs[kSecAttrAccessControl] = ac
            attributes[kSecPrivateKeyAttrs] = privateAttrs
        }

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw OSSecError(status: errSecParam, message: error?.takeRetainedValue().localizedDescription)
        }
        return privateKey
    }

    /// Wraps a symmetric key using ECIES with the provided public key.
    @available(iOS 13.0, macOS 10.15, *)
    private func wrapSymmetricKey(_ keyData: Data, using publicKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw OSSecError(status: errSecUnimplemented, message: "ECIES not supported for encryption")
        }
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(publicKey, algorithm, keyData as CFData, &error) as Data? else {
            throw OSSecError(status: errSecParam, message: error?.takeRetainedValue().localizedDescription)
        }
        return encrypted
    }

    /// Unwraps a symmetric key using ECIES with the provided private key.
    @available(iOS 13.0, macOS 10.15, *)
    private func unwrapSymmetricKey(_ wrappedData: Data, using privateKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw OSSecError(status: errSecUnimplemented, message: "ECIES not supported for decryption")
        }
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(privateKey, algorithm, wrappedData as CFData, &error) as Data? else {
            throw OSSecError(status: errSecAuthFailed, message: error?.takeRetainedValue().localizedDescription)
        }
        return decrypted
    }

    /// Deletes the Secure Enclave private key for the provided service.
    @available(iOS 13.0, macOS 10.15, *)
    private func deleteEnclavePrivateKey(service: String?) {
        let tag = enclaveKeyTag(for: service) as CFData
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: tag
        ]
        _ = SecItemDelete(query as CFDictionary)
    }

    /// Composes the companion key name used to store the wrapped AES key for a data item key.
    private func wrappedKeyName(for account: String) -> String { "fss.wrapped." + account }

    /// Builds a keychain query for the wrapped AES key item.
    private func wrappedKeyQuery(from params: KeychainQueryParameters, account: String, returnData: Bool) -> [CFString: Any] {
        var baseParams = params
        baseParams.shouldReturnData = returnData
        baseParams.isSynchronizable = false
        baseParams.accessControlFlags = params.accessControlFlags // prompts apply on unwrap
        var query = baseQuery(from: baseParams)
        query[kSecAttrAccount] = wrappedKeyName(for: account)
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
        query[kSecReturnData] = true

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
                guard let key = item[kSecAttrAccount] as? String else { continue }

                // Skip wrapped key items (they're companion items for Secure Enclave)
                if key.hasPrefix("fss.wrapped.") {
                    continue
                }

                // If Secure Enclave is enabled, try to decrypt the item
                if params.useSecureEnclave == true {
                    var itemParams = params
                    itemParams.key = key
                    let readResult = read(params: itemParams)
                    if readResult.status == errSecSuccess, let value = readResult.value as? String {
                        results[key] = value
                    } else {
                        // Fallback: if Secure Enclave read failed (no wrapped key), try plain text
                        if let data = item[kSecValueData] as? Data,
                           let value = String(data: data, encoding: .utf8) {
                            results[key] = value
                        }
                    }
                } else {
                    // Standard read: decode as UTF-8
                    if let data = item[kSecValueData] as? Data,
                       let value = String(data: data, encoding: .utf8) {
                        results[key] = value
                    }
                }
            }
        }

        return FlutterSecureStorageResponse(status: status, value: results)
    }

    /// Reads a single item from the keychain.
    internal func read(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        // If Secure Enclave flow is not requested, do the standard lookup
        if !(params.useSecureEnclave ?? false) {
            let query = baseQuery(from: params)
            var ref: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &ref)

            if (status == errSecItemNotFound) {
                return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
            }
            guard status == errSecSuccess, let data = ref as? Data else {
                return FlutterSecureStorageResponse(status: status, value: nil)
            }
            let value = String(data: data, encoding: .utf8)
            return FlutterSecureStorageResponse(status: status, value: value)
        }

        // Secure Enclave path: fetch wrapped AES key, unwrap, then decrypt payload
        guard let account = params.key else {
            return FlutterSecureStorageResponse(status: errSecParam, value: nil)
        }
        let keyQuery = wrappedKeyQuery(from: params, account: account, returnData: true)
        var keyRef: AnyObject?
        let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyRef)
        if keyStatus == errSecItemNotFound {
            // No wrapped key or value
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        guard keyStatus == errSecSuccess, let wrappedKeyData = keyRef as? Data else {
            return FlutterSecureStorageResponse(status: keyStatus, value: nil)
        }

        // Read encrypted data payload
        var dataParams = params
        dataParams.shouldReturnData = true
        let dataQuery = baseQuery(from: dataParams)
        var dataRef: AnyObject?
        let dataStatus = SecItemCopyMatching(dataQuery as CFDictionary, &dataRef)
        if dataStatus == errSecItemNotFound {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        guard dataStatus == errSecSuccess, let encryptedData = dataRef as? Data else {
            return FlutterSecureStorageResponse(status: dataStatus, value: nil)
        }

        // Unwrap AES key via Secure Enclave
        if #available(iOS 13.0, macOS 10.15, *) {
            do {
                let privateKey = try ensureEnclavePrivateKey(service: params.service)
                let aesKeyData = try unwrapSymmetricKey(wrappedKeyData, using: privateKey)
                let key = SymmetricKey(data: aesKeyData)
                // Encrypted blob format: nonce(12) + ciphertext+tag
                guard encryptedData.count > 12 else {
                    return FlutterSecureStorageResponse(status: errSecDecode, value: nil)
                }
                let nonceData = encryptedData.prefix(12)
                let ctData = encryptedData.suffix(encryptedData.count - 12)
                let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData), ciphertext: ctData.dropLast(16), tag: ctData.suffix(16))
                let plaintext = try AES.GCM.open(sealedBox, using: key)
                let value = String(data: plaintext, encoding: .utf8)
                return FlutterSecureStorageResponse(status: errSecSuccess, value: value)
            } catch {
                // If unwrapping fails (e.g., no enclave), gracefully fall back to standard read
                var fallbackParams = params
                fallbackParams.useSecureEnclave = false
                let query = baseQuery(from: fallbackParams)
                var ref: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &ref)
                if (status == errSecItemNotFound) {
                    return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
                }
                guard status == errSecSuccess, let data = ref as? Data else {
                    return FlutterSecureStorageResponse(status: status, value: nil)
                }
                let value = String(data: data, encoding: .utf8)
                return FlutterSecureStorageResponse(status: status, value: value)
            }
        } else {
            // Fallback for OS versions without required APIs: standard read with access control
            var fallbackParams = params
            fallbackParams.useSecureEnclave = false
            let query = baseQuery(from: fallbackParams)
            var ref: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &ref)
            if (status == errSecItemNotFound) {
                return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
            }
            guard status == errSecSuccess, let data = ref as? Data else {
                return FlutterSecureStorageResponse(status: status, value: nil)
            }
            let value = String(data: data, encoding: .utf8)
            return FlutterSecureStorageResponse(status: status, value: value)
        }
    }

    /// Writes an item to the keychain. Updates if the key already exists.
    internal func write(params: KeychainQueryParameters, value: String) -> FlutterSecureStorageResponse {
        if !(params.useSecureEnclave ?? false) {
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

        // Secure Enclave-backed: encrypt with per-item AES key wrapped by enclave key
        guard let account = params.key else {
            return FlutterSecureStorageResponse(status: errSecParam, value: nil)
        }

        // Ensure enclave private key exists
        if #available(iOS 13.0, macOS 10.15, *) {
            do {
                let privateKey = try ensureEnclavePrivateKey(service: params.service)
                guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                    return FlutterSecureStorageResponse(status: errSecParam, value: nil)
                }

                // Generate random AES key and encrypt value
                let aesKey = SymmetricKey(size: .bits256)
                let nonce = AES.GCM.Nonce()
                let sealed = try AES.GCM.seal(Data(value.utf8), using: aesKey, nonce: nonce)
                let nonceBytes = Data(nonce)
                let blob = nonceBytes + sealed.ciphertext + sealed.tag

                // Wrap AES key with Enclave public key
                let wrappedKey = try wrapSymmetricKey(Data(aesKey.withUnsafeBytes { Data($0) }), using: publicKey)

                // Store wrapped key under companion account
                var keyParams = params
                keyParams.key = wrappedKeyName(for: account)
                keyParams.shouldReturnData = false
                keyParams.isSynchronizable = false
                var keyQuery = baseQuery(from: keyParams)
                keyQuery[kSecValueData] = wrappedKey
                // Upsert wrapped key item
                let keyExists = (containsKey(params: keyParams).getOrElse(false))
                var keyStatus: OSStatus
                if keyExists {
                    keyStatus = SecItemUpdate(keyQuery as CFDictionary, [kSecValueData: wrappedKey] as CFDictionary)
                } else {
                    keyStatus = SecItemAdd(keyQuery as CFDictionary, nil)
                }
                guard keyStatus == errSecSuccess else {
                    return FlutterSecureStorageResponse(status: keyStatus, value: nil)
                }

                // Store encrypted payload under original account
                var dataParams = params
                dataParams.shouldReturnData = false
                var dataQuery = baseQuery(from: dataParams)
                dataQuery[kSecValueData] = blob
                let dataExists = (containsKey(params: params).getOrElse(false))
                var dataStatus: OSStatus
                if dataExists {
                    dataStatus = SecItemUpdate(dataQuery as CFDictionary, [kSecValueData: blob] as CFDictionary)
                } else {
                    dataStatus = SecItemAdd(dataQuery as CFDictionary, nil)
                }
                return FlutterSecureStorageResponse(status: dataStatus, value: nil)
            } catch {
                return FlutterSecureStorageResponse(status: errSecParam, value: nil)
            }
        } else {
            // Fallback for OS versions without required APIs: store using standard Keychain with access control
            var fallbackParams = params
            fallbackParams.useSecureEnclave = false
            let keyExists = (containsKey(params: fallbackParams).getOrElse(false))
            var query = baseQuery(from: fallbackParams)
            if keyExists {
                let update: [CFString: Any] = [kSecValueData: value.data(using: .utf8) as Any]
                let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
                return FlutterSecureStorageResponse(status: status, value: nil)
            } else {
                query[kSecValueData] = value.data(using: .utf8)
                let status = SecItemAdd(query as CFDictionary, nil)
                return FlutterSecureStorageResponse(status: status, value: nil)
            }
        }
    }

    /// Deletes an item from the keychain.
    internal func delete(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        // Delete primary item across sync variants/accessibility permutations.
        let primaryResult = performDelete(params: params, clearKey: false)
        if primaryResult.status != errSecSuccess {
            return primaryResult
        }

        // If Secure Enclave flow is used, also remove the wrapped AES key companion item.
        if params.useSecureEnclave == true, let account = params.key {
            var keyParams = params
            keyParams.key = wrappedKeyName(for: account)
            let wrappedResult = performDelete(params: keyParams, clearKey: false)
            if wrappedResult.status != errSecSuccess {
                return wrappedResult
            }
        }

        return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
    }

    /// Deletes all items matching the query parameters.
    /// If Secure Enclave is enabled, also deletes the Secure Enclave private key.
    internal func deleteAll(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        let result = performDelete(params: params, clearKey: true)

        // If Secure Enclave is enabled, also delete the SE private key
        if params.useSecureEnclave == true {
            if #available(iOS 13.0, macOS 10.15, *) {
                deleteEnclavePrivateKey(service: params.service)
            }
        }

        return result
    }

    /// Private helper method to perform keychain deletion.
    /// Attempts to delete items with both synchronizable states and without accessibility constraints
    /// to ensure complete removal regardless of how items were originally stored.
    ///
    /// - Parameters:
    ///   - params: The keychain query parameters
    ///   - clearKey: If true, removes the key constraint to delete all items; if false, deletes specific key
    /// - Returns: Response indicating success or failure of the deletion operation
    private func performDelete(params: KeychainQueryParameters, clearKey: Bool) -> FlutterSecureStorageResponse {
        func deleteFromKeychain(withSynchronizable synchronizable: Bool?) -> OSStatus {
            var modifiedParams = params

            if clearKey {
                modifiedParams.key = nil
            }

            modifiedParams.isSynchronizable = synchronizable
            modifiedParams.accessibilityLevel = nil
            modifiedParams.accessControlFlags = nil

            let query = baseQuery(from: modifiedParams)
            return SecItemDelete(query as CFDictionary)
        }

        let statusSync = deleteFromKeychain(withSynchronizable: true)
        let statusNonSync = deleteFromKeychain(withSynchronizable: false)

        // Return success if both operations report item not found
        if statusSync == errSecItemNotFound && statusNonSync == errSecItemNotFound {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        // Return success if either operation succeeded
        if statusSync == errSecSuccess || statusNonSync == errSecSuccess {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }

        // Return the first error encountered
        let status = statusSync != errSecItemNotFound ? statusSync : statusNonSync

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
