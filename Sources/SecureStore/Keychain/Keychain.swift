//
//  Keychain.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

public final class Keychain {
    /// Generates an array of cryptographically secure random bytes.
    ///
    /// - Parameter size: the size of the key to generate, in bytes
    /// - Throws: On error throw a error of type SecError
    /// - Returns: On success return an array of cryptographically secure random bytes
    public static func generateSecureRandomKeyWithSize(_ size: Int) -> Result<Data, SecureStoreError> {
        var key = Data(count: size)
        let result = key.withUnsafeMutableBytes { keyBytes -> Result<Void, SecureStoreError> in
            guard let baseAddress = keyBytes.baseAddress else { return .failure(.unknown) }
            guard SecRandomCopyBytes(kSecRandomDefault, size, baseAddress) == errSecSuccess else {
                return .failure(.unknown)
            }
            return .success(())
        }
        return result.map { key }
    }
}

// MARK: - Helpers
extension Keychain {
    static func wipeAll() {
        let kSecClasses = [kSecClassGenericPassword,
                           kSecClassInternetPassword,
                           kSecClassCertificate,
                           kSecClassKey,
                           kSecClassIdentity]
        for secClass in kSecClasses {
            SecItemDelete([kSecClass: secClass] as CFDictionary)
        }
    }
    
    static func get<T>(query: CFDictionary) -> Result<T, SecureStoreError> {
        var result: AnyObject?
        let status = SecItemCopyMatching(query, &result)

        if status != errSecSuccess {
            return .failure(SecureStoreError(rawValue: status) ?? .unknown)
        }
        return .success(result as! T)
    }

    static func save(query: CFDictionary) -> Result<Void, SecureStoreError> {
        let status = SecItemAdd(query, nil)
        if status != errSecSuccess {
            return .failure(SecureStoreError(rawValue: status) ?? .unknown)
        }
        return .success(())
    }

    static func delete(query: CFDictionary) -> Result<Void, SecureStoreError> {
        let status = SecItemDelete(query)
        if status != errSecSuccess {
            return .failure(SecureStoreError(rawValue: status) ?? .unknown)
        }
        return .success(())
    }

    static func update(query: CFDictionary, with update: CFDictionary) -> Result<Void, SecureStoreError> {
        let status = SecItemUpdate(query, update)
        if status != errSecSuccess {
            return .failure(SecureStoreError(rawValue: status) ?? .unknown)
        }
        return .success(())
    }
}
