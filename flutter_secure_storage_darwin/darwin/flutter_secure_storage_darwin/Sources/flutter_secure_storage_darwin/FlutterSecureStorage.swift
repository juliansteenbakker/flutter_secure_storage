//
//  FlutterSecureStorage.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Foundation
import Security
import CryptoKit

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

    /// `useSecureEnclave` (iOS/macOS): Indicates whether the Secure Enclave for cryptographic key operations when available is used.
    var useSecureEnclave: Bool?

    /// `migrateToSecureEnclave` (iOS/macOS): Indicates whether existing data should be migrated to Secure Enclave.
    var migrateToSecureEnclave: Bool?

    /// `resetOnError` (iOS/macOS): Indicates whether to delete all data when migration or encryption fails.
    var resetOnError: Bool?
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

    // MARK: - Secure Enclave Helpers

    /// Constructs a stable tag for the Secure Enclave private key for a given service.
    private func enclaveKeyTag(for service: String?) -> Data {
        let serviceLabel = service ?? "flutter_secure_storage_service"
        return ("fss.enclave." + serviceLabel).data(using: .utf8)!
    }

    /// Ensures a Secure Enclave EC private key exists for the provided service, creating it if needed.
    @available(iOS 11.3, macOS 10.15, *)
    private func ensureEnclavePrivateKey(service: String?, accessControl: SecAccessControl?) throws -> SecKey {
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
        if let ac = accessControl {
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
    @available(iOS 11.3, macOS 10.15, *)
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
    @available(iOS 11.3, macOS 10.15, *)
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

    // MARK: - Migration Helpers

    /// Encryption modes for tracking migration state
    enum EncryptionMode: String {
        case standard = "standard"
        case secureEnclave = "secure_enclave"
        case notSet = "not_set"
    }

    /// Generates a unique UserDefaults key for the encryption mode based on service name.
    private func encryptionModeKey(for service: String?) -> String {
        let serviceLabel = service ?? "flutter_secure_storage_service"
        return "fss.encryption_mode.\(serviceLabel)"
    }

    /// Gets the current stored encryption mode.
    private func getStoredEncryptionMode(service: String?) -> EncryptionMode {
        let key = encryptionModeKey(for: service)
        if let modeString = UserDefaults.standard.string(forKey: key),
           let mode = EncryptionMode(rawValue: modeString) {
            return mode
        }
        return .notSet
    }

    /// Sets the current encryption mode.
    private func setStoredEncryptionMode(service: String?, mode: EncryptionMode) {
        let key = encryptionModeKey(for: service)
        UserDefaults.standard.set(mode.rawValue, forKey: key)
    }

    /// Gets the requested encryption mode from parameters.
    private func getRequestedEncryptionMode(params: KeychainQueryParameters) -> EncryptionMode {
        return (params.useSecureEnclave ?? false) ? .secureEnclave : .standard
    }

    /// Checks if migration is needed by comparing stored vs requested modes.
    private func requiresMigration(params: KeychainQueryParameters) -> (needed: Bool, from: EncryptionMode, to: EncryptionMode) {
        let storedMode = getStoredEncryptionMode(service: params.service)
        let requestedMode = getRequestedEncryptionMode(params: params)

        // Migration needed if modes differ and migration is enabled
        if storedMode != requestedMode && (params.migrateToSecureEnclave ?? false) {
            // Special case: if mode is not set and we have no data, consider it already migrated
            if storedMode == .notSet {
                // Check if there's any existing data (without triggering migration)
                var checkParams = params
                checkParams.useSecureEnclave = false
                checkParams.migrateToSecureEnclave = false // Prevent recursion
                let response = readAllInternal(params: checkParams)
                if let items = response.value as? [String: String], items.isEmpty {
                    // No data exists, just set mode and skip migration
                    return (needed: false, from: storedMode, to: requestedMode)
                }
            }
            return (needed: true, from: storedMode, to: requestedMode)
        }

        return (needed: false, from: storedMode, to: requestedMode)
    }

    /// Handles storage operation errors by optionally deleting corrupted data and retrying.
    /// Returns true if data was deleted and operation should be retried.
    private func handleStorageError(operation: String, key: String?, params: KeychainQueryParameters, error: Error) -> Bool {
        let deleteOnFailure = params.resetOnError ?? false
        let target = key != nil ? "key '\(key!)'" : "all data"

        print("[FlutterSecureStorage] Storage operation '\(operation)' failed for \(target): \(error.localizedDescription)")

        if !deleteOnFailure {
            print("[FlutterSecureStorage] Set resetOnError=true to automatically delete corrupted data")
            return false
        }

        print("[FlutterSecureStorage] resetOnError enabled. Attempting to delete corrupted data and retry...")

        // Delete the corrupted data
        if let key = key {
            var deleteParams = params
            deleteParams.key = key
            let response = delete(params: deleteParams)
            if response.status == errSecSuccess {
                print("[FlutterSecureStorage] Data for key has been deleted. Retrying operation...")
                return true
            } else {
                print("[FlutterSecureStorage] Failed to delete data for key during error handling")
                return false
            }
        } else {
            let response = deleteAll(params: params)
            if response.status == errSecSuccess {
                print("[FlutterSecureStorage] All data has been deleted. Retrying operation...")
                return true
            } else {
                print("[FlutterSecureStorage] Failed to delete all data during error handling")
                return false
            }
        }
    }

    /// Checks if Secure Enclave is available on this device.
    @available(iOS 11.3, macOS 10.15, *)
    private func isSecureEnclaveAvailable() -> Bool {
        let tag = "fss.enclave.availability.test".data(using: .utf8)!
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: false,
                kSecAttrApplicationTag: tag
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let _ = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return false
        }
        return true
    }

    /// Migrates all existing keychain data to Secure Enclave-backed encryption.
    /// Returns true on success, false on failure.
    @available(iOS 11.3, macOS 10.15, *)
    private func migrateToSecureEnclave(params: KeychainQueryParameters) -> Bool {
        print("[FlutterSecureStorage] Starting migration to Secure Enclave...")

        // Check if Secure Enclave is available
        guard isSecureEnclaveAvailable() else {
            print("[FlutterSecureStorage] Secure Enclave not available on this device")
            return false
        }

        // Step 1: Read all existing data (non-SE path)
        var readParams = params
        readParams.useSecureEnclave = false
        readParams.shouldReturnData = true

        let readResponse = readAllInternal(params: readParams)
        guard readResponse.status == errSecSuccess else {
            print("[FlutterSecureStorage] Failed to read existing data for migration: \(readResponse.status)")
            return false
        }

        guard let allItems = readResponse.value as? [String: String] else {
            print("[FlutterSecureStorage] No data to migrate or invalid format")
            return true // Nothing to migrate is success
        }

        if allItems.isEmpty {
            print("[FlutterSecureStorage] No data to migrate")
            return true
        }

        print("[FlutterSecureStorage] Found \(allItems.count) items to migrate")

        // Step 2: Prepare Secure Enclave encryption
        let ac = createAccessControl(params: params)
        guard let privateKey = try? ensureEnclavePrivateKey(service: params.service, accessControl: ac),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            print("[FlutterSecureStorage] Failed to create or access Secure Enclave key")
            return false
        }

        var successCount = 0
        var failureCount = 0

        // Step 3: Re-encrypt each item with Secure Enclave
        for (key, value) in allItems {
            // Skip wrapped key entries (they're companions, not data)
            if key.hasPrefix("fss.wrapped.") {
                continue
            }

            do {
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
                keyParams.key = wrappedKeyName(for: key)
                keyParams.shouldReturnData = false
                keyParams.isSynchronizable = false
                keyParams.useSecureEnclave = true
                var keyQuery = baseQuery(from: keyParams)
                keyQuery[kSecValueData] = wrappedKey

                // Delete old wrapped key if it exists
                _ = SecItemDelete(keyQuery as CFDictionary)

                // Add new wrapped key
                var keyStatus = SecItemAdd(keyQuery as CFDictionary, nil)
                guard keyStatus == errSecSuccess else {
                    print("[FlutterSecureStorage] Failed to store wrapped key for '\(key)': \(keyStatus)")
                    failureCount += 1
                    continue
                }

                // Store encrypted payload under original account (preserving all attributes)
                var dataParams = params
                dataParams.key = key
                dataParams.shouldReturnData = false
                dataParams.useSecureEnclave = true
                var dataQuery = baseQuery(from: dataParams)

                // Delete old entry
                _ = SecItemDelete(dataQuery as CFDictionary)

                // Add new encrypted entry
                dataQuery[kSecValueData] = blob
                let dataStatus = SecItemAdd(dataQuery as CFDictionary, nil)

                if dataStatus == errSecSuccess {
                    successCount += 1
                    print("[FlutterSecureStorage] Migrated key: '\(key)'")
                } else {
                    print("[FlutterSecureStorage] Failed to store encrypted data for '\(key)': \(dataStatus)")
                    failureCount += 1
                }
            } catch {
                print("[FlutterSecureStorage] Error migrating key '\(key)': \(error.localizedDescription)")
                failureCount += 1
            }
        }

        print("[FlutterSecureStorage] Migration completed: \(successCount) succeeded, \(failureCount) failed")

        // Consider migration successful if no failures occurred
        // (empty data is also considered a successful migration)
        return failureCount == 0
    }

    /// Migrates all existing Secure Enclave-encrypted data back to standard keychain storage.
    /// Returns true on success, false on failure.
    @available(iOS 11.3, macOS 10.15, *)
    private func migrateFromSecureEnclave(params: KeychainQueryParameters) -> Bool {
        print("[FlutterSecureStorage] Starting migration from Secure Enclave to standard keychain...")

        // Step 1: Read all existing SE-encrypted data
        var readParams = params
        readParams.useSecureEnclave = true
        readParams.shouldReturnData = true

        // Get all items (this will decrypt them via SE)
        let readResponse = readAllInternal(params: readParams)
        guard readResponse.status == errSecSuccess else {
            print("[FlutterSecureStorage] Failed to read existing SE data for migration: \(readResponse.status)")
            return false
        }

        guard let allItems = readResponse.value as? [String: String] else {
            print("[FlutterSecureStorage] No data to migrate or invalid format")
            return true // Nothing to migrate is success
        }

        if allItems.isEmpty {
            print("[FlutterSecureStorage] No data to migrate")
            return true
        }

        print("[FlutterSecureStorage] Found \(allItems.count) items to migrate from SE")

        var successCount = 0
        var failureCount = 0

        // Step 2: Re-write each item using standard keychain (no SE)
        for (key, value) in allItems {
            // Skip wrapped key entries (they're companions, not data)
            if key.hasPrefix("fss.wrapped.") {
                continue
            }

            // Write with standard keychain
            var writeParams = params
            writeParams.key = key
            writeParams.useSecureEnclave = false

            // Delete old SE-encrypted entry and its wrapped key
            var deleteParams = params
            deleteParams.key = key
            deleteParams.useSecureEnclave = true
            _ = delete(params: deleteParams)

            // Write as standard keychain item
            let keyExists = (containsKey(params: writeParams).getOrElse(false))
            var query = baseQuery(from: writeParams)
            var status: OSStatus

            if keyExists {
                let update: [CFString: Any] = [kSecValueData: value.data(using: .utf8) as Any]
                status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            } else {
                query[kSecValueData] = value.data(using: .utf8)
                status = SecItemAdd(query as CFDictionary, nil)
            }

            if status == errSecSuccess {
                successCount += 1
                print("[FlutterSecureStorage] Migrated key from SE: '\(key)'")
            } else {
                print("[FlutterSecureStorage] Failed to store standard keychain data for '\(key)': \(status)")
                failureCount += 1
            }
        }

        // Step 3: Clean up any remaining wrapped keys
        var wrappedKeyParams = params
        wrappedKeyParams.useSecureEnclave = false
        let allKeysResponse = readAllInternal(params: wrappedKeyParams)
        if let allKeys = allKeysResponse.value as? [String: String] {
            for key in allKeys.keys where key.hasPrefix("fss.wrapped.") {
                var deleteParams = params
                deleteParams.key = key
                deleteParams.useSecureEnclave = false
                _ = delete(params: deleteParams)
            }
        }

        print("[FlutterSecureStorage] Migration from SE completed: \(successCount) succeeded, \(failureCount) failed")

        // Consider migration successful if no failures occurred
        return failureCount == 0
    }

    /// Checks if migration is needed and performs it if necessary.
    /// Returns true if storage is ready to use (either migration succeeded or not needed).
    internal func ensureMigrationIfNeeded(params: KeychainQueryParameters) -> Bool {
        // Check if migration is enabled
        guard (params.migrateToSecureEnclave ?? false) else {
            return true // Migration disabled
        }

        // Check if migration is needed
        let migrationCheck = requiresMigration(params: params)
        guard migrationCheck.needed else {
            return true // No migration needed
        }

        let fromMode = migrationCheck.from
        let toMode = migrationCheck.to

        print("[FlutterSecureStorage] Migration required: \(fromMode.rawValue) → \(toMode.rawValue)")

        // Check OS version support for SE migrations
        if toMode == .secureEnclave || fromMode == .secureEnclave {
            guard #available(iOS 11.3, macOS 10.15, *) else {
                print("[FlutterSecureStorage] Secure Enclave requires iOS 11.3+ or macOS 10.15+")
                print("[FlutterSecureStorage] Falling back to standard keychain")
                setStoredEncryptionMode(service: params.service, mode: .standard)
                return false // Indicate fallback needed
            }
        }

        // Perform migration based on direction
        var migrationSuccess = false

        if #available(iOS 11.3, macOS 10.15, *) {
            switch (fromMode, toMode) {
            case (.notSet, .secureEnclave), (.standard, .secureEnclave):
                // Forward migration: standard → SE
                print("[FlutterSecureStorage] Migrating to Secure Enclave...")
                migrationSuccess = migrateToSecureEnclave(params: params)

            case (.secureEnclave, .standard):
                // Reverse migration: SE → standard
                print("[FlutterSecureStorage] Migrating from Secure Enclave to standard keychain...")
                migrationSuccess = migrateFromSecureEnclave(params: params)

            case (.notSet, .standard):
                // Just starting with standard, no migration needed
                print("[FlutterSecureStorage] Initializing with standard keychain (no migration needed)")
                setStoredEncryptionMode(service: params.service, mode: .standard)
                return true

            default:
                print("[FlutterSecureStorage] Unexpected migration path: \(fromMode.rawValue) → \(toMode.rawValue)")
                return true
            }
        }

        if migrationSuccess {
            print("[FlutterSecureStorage] Migration succeeded")
            setStoredEncryptionMode(service: params.service, mode: toMode)
            return true
        } else {
            print("[FlutterSecureStorage] Migration failed")

            // Handle migration failure based on resetOnError flag
            if params.resetOnError ?? false {
                print("[FlutterSecureStorage] resetOnError enabled. Deleting all data and starting fresh...")
                _ = deleteAll(params: params)
                setStoredEncryptionMode(service: params.service, mode: toMode)
                return true
            } else {
                print("[FlutterSecureStorage] Migration failed and resetOnError is disabled")
                print("[FlutterSecureStorage] Keeping current encryption mode: \(fromMode.rawValue)")
                // Don't change the stored mode, keep using the old one
                return false // Indicate fallback needed
            }
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

    /// Internal method to read all items without migration checks (to prevent recursion).
    private func readAllInternal(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
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
                   let data = item[kSecValueData] as? Data {

                    // Skip wrapped key entries (they're companions, not data)
                    if key.hasPrefix("fss.wrapped.") {
                        continue
                    }

                    // If Secure Enclave is enabled, try to decrypt the data
                    if (params.useSecureEnclave ?? false) {
                        // Attempt SE decryption by reading individual item
                        var itemParams = params
                        itemParams.key = key
                        itemParams.migrateToSecureEnclave = false // Don't trigger migration for each item
                        let itemResponse = readInternal(params: itemParams)
                        if itemResponse.status == errSecSuccess, let decryptedValue = itemResponse.value as? String {
                            results[key] = decryptedValue
                        }
                        // If decryption fails, skip this item
                    } else {
                        // Standard path: data is plaintext
                        if let value = String(data: data, encoding: .utf8) {
                            results[key] = value
                        }
                    }
                }
            }
        }

        return FlutterSecureStorageResponse(status: status, value: results)
    }

    /// Reads all items from the keychain matching the query parameters with error handling and retry.
    internal func readAll(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        // Check if migration is needed before reading all
        var effectiveParams = params
        if !ensureMigrationIfNeeded(params: params) {
            // Migration failed or SE unavailable, fall back to non-SE
            effectiveParams.useSecureEnclave = false
        }

        // Attempt readAll with error handling
        let response = readAllInternal(params: effectiveParams)

        // If readAll failed and resetOnError is enabled, try to recover
        if response.status != errSecSuccess && response.status != errSecItemNotFound {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(response.status))
            if handleStorageError(operation: "readAll", key: nil, params: effectiveParams, error: error) {
                // Retry after deleting all corrupted data
                return readAllInternal(params: effectiveParams)
            }
        }

        return response
    }

    /// Internal method to read a single item without migration checks (to prevent recursion).
    private func readInternal(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
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
        var keyQuery = wrappedKeyQuery(from: params, account: account, returnData: true)
        var keyRef: AnyObject?
        var keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyRef)
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
        var dataQuery = baseQuery(from: dataParams)
        var dataRef: AnyObject?
        let dataStatus = SecItemCopyMatching(dataQuery as CFDictionary, &dataRef)
        if dataStatus == errSecItemNotFound {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        guard dataStatus == errSecSuccess, let encryptedData = dataRef as? Data else {
            return FlutterSecureStorageResponse(status: dataStatus, value: nil)
        }

        // Unwrap AES key via Secure Enclave
        if #available(iOS 11.3, macOS 10.15, *) {
            let ac = createAccessControl(params: params)
            do {
                let privateKey = try ensureEnclavePrivateKey(service: params.service, accessControl: ac)
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

    /// Reads a single item from the keychain with error handling and retry.
    internal func read(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        // Check if migration is needed before reading
        var effectiveParams = params
        if !ensureMigrationIfNeeded(params: params) {
            // Migration failed or SE unavailable, fall back to non-SE
            effectiveParams.useSecureEnclave = false
        }

        // Attempt read with error handling
        let response = readInternal(params: effectiveParams)

        // If read failed and resetOnError is enabled, try to recover
        if response.status != errSecSuccess && response.status != errSecItemNotFound {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(response.status))
            if handleStorageError(operation: "read", key: effectiveParams.key, params: effectiveParams, error: error) {
                // Retry after deleting corrupted data
                return readInternal(params: effectiveParams)
            }
        }

        return response
    }

    /// Internal method to write an item without error handling (to prevent recursion).
    private func writeInternal(params: KeychainQueryParameters, value: String) -> FlutterSecureStorageResponse {
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

        // Ensure enclave private key exists (with provided access control)
        if #available(iOS 11.3, macOS 10.15, *) {
            let ac = createAccessControl(params: params)
            do {
                let privateKey = try ensureEnclavePrivateKey(service: params.service, accessControl: ac)
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

    /// Writes an item to the keychain with error handling and retry.
    internal func write(params: KeychainQueryParameters, value: String) -> FlutterSecureStorageResponse {
        // Check if migration is needed before writing
        var effectiveParams = params
        if !ensureMigrationIfNeeded(params: params) {
            // Migration failed or SE unavailable, fall back to non-SE
            effectiveParams.useSecureEnclave = false
        }

        // Attempt write with error handling
        let response = writeInternal(params: effectiveParams, value: value)

        // If write failed and resetOnError is enabled, try to recover
        if response.status != errSecSuccess {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(response.status))
            if handleStorageError(operation: "write", key: effectiveParams.key, params: effectiveParams, error: error) {
                // Retry after deleting corrupted data
                return writeInternal(params: effectiveParams, value: value)
            }
        }

        return response
    }

    /// Deletes an item from the keychain.
    internal func delete(params: KeychainQueryParameters) -> FlutterSecureStorageResponse {
        // Delete the primary value
        let query = baseQuery(from: params)
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            return FlutterSecureStorageResponse(status: status, value: nil)
        }

        // If Secure Enclave flow is used, also remove the wrapped AES key companion item
        if params.useSecureEnclave == true, let account = params.key {
            var keyParams = params
            keyParams.key = wrappedKeyName(for: account)
            let wrappedQuery = baseQuery(from: keyParams)
            _ = SecItemDelete(wrappedQuery as CFDictionary)
        }

        return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
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
