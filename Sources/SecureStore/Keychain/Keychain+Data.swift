//
//  Keychain+Data.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

// MARK: - Private data
extension Keychain {    
    /// Save a private value as a new default keychain entry
    ///
    /// - Parameters:
    ///   - value: A key whose value is the item's data.
    ///   - tag: A key whose value indicates the item's private tag
    ///   - accessGroup: A key whose value is a string indicating the access group an item is in.
    ///   - accessibility: Indicates when a keychain item is accessible, default is afterFirstUnlockThisDeviceOnly
    /// - Throws: On error throw a error of type SecError
    static func storeData(_ data: Data,
                          withTag tag: AnyObject,
                          accessGroup: String? = nil,
                          accessibility: Accessibility,
                          overwrite: Bool = false)
        -> Result<Void, SecureStoreError> {

        // Get the Keychain query to save our key
        var query = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeySizeInBits: data.bits as AnyObject,
            kSecValueData: data as AnyObject,
            kSecAttrAccessible: accessibility.kSecAttrAccessible
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        let result = save(query: query as CFDictionary)
        guard overwrite == true else { return result }
        switch result {
        case .failure(let error) where error == .duplicatedItem:
            return updateDataWithTag(tag, with: data, accessGroup: accessGroup, accessibility: accessibility)
        default:
            return result
        }
    }

    static func deleteDataWithTag(_ tag: AnyObject, accessGroup: String? = nil) -> Result<Void, SecureStoreError> {
        // First check in the keychain for an existing key
        var query = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
            ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return delete(query: query as CFDictionary)
    }

    /// Get the keychain entry as a Ref object
    ///
    /// - Parameters:
    ///   - tag: A key whose value indicates the item's private tag
    ///   - value: An instance to temporarily use via pointer. Note that the inout exclusivity rules mean that, like any other inout argument, value cannot be directly accessed by other code for the duration of body. Access must only occur through the pointer argument to body until body returns.
    /// - Throws: On error throw a error of type SecError
    /// - Returns: On success return a dynamic type
    static func retrieveDataWithTag<T>(_ tag: AnyObject, accessGroup: String? = nil) -> Result<T, SecureStoreError> {
        var query = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecReturnData: true as AnyObject
            ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return get(query: query as CFDictionary)
    }

    static func getAllDataWithTag<T>(_ tag: AnyObject) -> Result<[T], SecureStoreError> {
        let query = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnData: true as AnyObject
            ] as CFDictionary
        let result: Result<CFArray, SecureStoreError> = get(query: query as CFDictionary)
        return result.map { $0 as! [T] }
    }

    /// Update the access group for the item that match the tag.
    ///
    /// - Parameters:
    ///   - value: A key whose value is the item's data.
    ///   - accessGroup: A key whose value is a string indicating the access group an item is in.
    ///   - tag: A key whose value indicates the item's private tag
    /// - Throws: On error throw a error of type SecError
    static func updateDataWithTag(_ tag: AnyObject,
                                         with value: Data? = nil,
                                         accessGroup: String? = nil,
                                         accessibility: Accessibility? = nil) -> Result<Void, SecureStoreError> {

        let query = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
            ] as CFDictionary

        var updateQuery = [CFString: AnyObject]()
        if let value = value {
            updateQuery[kSecValueData] = value as AnyObject
            updateQuery[kSecAttrKeySizeInBits] = value.bits as AnyObject
        }
        if let accessGroup = accessGroup {
            updateQuery[kSecAttrAccessGroup] = accessGroup as AnyObject
        }

        if let accessibility = accessibility {
            updateQuery[kSecAttrAccessible] = accessibility.kSecAttrAccessible
        }
        return update(query: query, with: updateQuery as CFDictionary)
    }
}
