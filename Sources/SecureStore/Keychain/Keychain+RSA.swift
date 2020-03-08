//
//  Keychain+RSA.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

// MARK: - RSA Key
extension Keychain {
    static func wipeRSAKeys() -> Result<Void, SecureStoreError> {
        delete(query: [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                       kSecClass: kSecClassKey] as CFDictionary)
    }
    
    /// Save a value as a new RSA keychain entry
    ///
    /// - Parameters:
    ///   - value: A key whose value is the item's data.
    ///   - tag: A key whose value indicates the item's private tag
    ///   - accessGroup: A key whose value is a string indicating the access group an item is in.
    static func saveRSAKey(_ rsaKey: Data,
                           withTag tag: String,
                           type: KeyType,
                           accessGroup: String? = nil,
                           overwrite: Bool = false)
        -> Result<Void, SecureStoreError> {
            
            var queryFilter: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrApplicationTag: tag,
                kSecValueData: rsaKey,
                kSecAttrKeyClass: type.kSecAttrKeyClass,
                kSecReturnPersistentRef: true
            ]
            
            if let attrAccessGroup = accessGroup {
                queryFilter[kSecAttrAccessGroup] = attrAccessGroup as AnyObject
            }
            
            // Add the new keychain item
            let result = save(query: queryFilter as CFDictionary)
            switch result {
            case .failure(let error) where error == .duplicatedItem:
                return updateRSAKey(rsaKey, withTag: tag, type: type, accessGroup: accessGroup)
            default:
                return result
            }
    }
    
    /// Update the value for the password item that match the tag.
    ///
    /// - Parameters:
    ///   - value: A key whose value is a string indicating the access group an item is in.
    ///   - accessGroup: A key whose value is a string indicating the access group an item is in.
    ///   - forService: A key whose value is a string indicating the item's service.
    ///   - account: A key whose value is a string indicating the item's account name.
    ///   - attrKeySize: A key whose value indicates the number of bits in a cryptographic key.
    /// - Throws: On error throw a error of type SecError
    internal static func updateRSAKey(_ rsaKey: Data?, withTag tag: String, type: KeyType, accessGroup: String? = nil) -> Result<Void, SecureStoreError> {
        let searchQuery = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyClass: type.kSecAttrKeyClass
            ] as CFDictionary
        
        var updateQuery = [CFString: Any]()
        if let rsaKey = rsaKey {
            updateQuery[kSecValueData] = rsaKey
        }
        if let accessGroup = accessGroup {
            updateQuery[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        
        return update(query: searchQuery, with: updateQuery as CFDictionary)
    }
    
    static func deleteRSAKeyWithTag(_ tag: AnyObject, accessGroup: String? = nil) -> Result<Void, SecureStoreError> {
        var queryFilter = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: tag
        ]
        if let accessGroup = accessGroup {
            queryFilter[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return delete(query: queryFilter as CFDictionary)
    }
    
    static func retrieveRSASecKeyWithTag(_ tag: String, accessGroup: String? = nil) -> Result<SecKey, SecureStoreError> {
        var query: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecReturnRef: kCFBooleanTrue as Any,
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return get(query: query as CFDictionary)
    }
    
    static func retrieveRSAKeyDataWithTag(_ tag: String, accessGroup: String? = nil) -> Result<Data, SecureStoreError> {
        var query: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecReturnData: kCFBooleanTrue as CFBoolean,
            kSecClass: kSecClassKey as CFString,
            kSecAttrApplicationTag: tag as CFString
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return get(query: query as CFDictionary)
    }
    
    static func retrieveAllRSAKeys<T>() -> Result<[T], SecureStoreError> {
        let query = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecClass: kSecClassKey as CFString,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnData: kCFBooleanTrue as CFBoolean
            ]  as CFDictionary
        let result: Result<CFArray, SecureStoreError> = get(query: query)
        return result.map { $0 as! [T] }
    }
}
