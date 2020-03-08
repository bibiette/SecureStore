//
//  Keychain+Password.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

// MARK: - Password
extension Keychain {
    /// Save a value as a new default keychain entry
    ///
    /// - Parameters:
    ///   - value: A key whose value is the item's data.
    ///   - forService: A key whose value is a string indicating the item's service.
    ///   - account: A key whose value is a string indicating the item's account name.
    ///   - accessGroup: optionally specify which group has access to this, if left nil keychain entry will only be available to the process that saved it
    ///   - accessibility: Indicates when a keychain item is accessible, default is afterFirstUnlockThisDeviceOnly
    /// - Throws: On error throw a error of type SecError
    static func storePassword(_ password: AnyObject,
                              forService service: AnyObject,
                              account: AnyObject? = nil,
                              accessGroup: String? = nil,
                              accessibility: Accessibility = .always,
                              overwrite: Bool = false) -> Result<Void, SecureStoreError> {
        
        // Get the Keychain query to save our key
        var query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecValueData: password,
            kSecAttrAccessible: accessibility.kSecAttrAccessible
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        if let account = account {
            query[kSecAttrAccount] = account
        }
        let result = save(query: query as CFDictionary)
        guard overwrite == true else { return result }
        switch result {
        case .failure(let error) where error == .duplicatedItem:
            return updateStoredPassword(password,
                                        accessGroup: accessGroup,
                                        forService: service,
                                        account: account,
                                        accessibility: accessibility)
        default:
            return result
        }
    }
    
    /// Get the keychain entry as a Ref object
    ///
    /// - Parameters:
    ///   - forService: A key whose value is a string indicating the item's service.
    ///   - account: A key whose value is a string indicating the item's account name.
    ///   - value: An instance to temporarily use via pointer. Note that the inout exclusivity rules mean that, like any other inout argument, value cannot be directly accessed by other code for the duration of body. Access must only occur through the pointer argument to body until body returns.
    /// - Throws: On error throw a error of type SecError
    /// - Returns: On success return a dynamic type
    static func retrievePasswordForService<T>(_ service: AnyObject,
                                              account: AnyObject? = nil,
                                              accessGroup: String? = nil) -> Result<T, SecureStoreError> {
        var query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecReturnData: true as AnyObject
        ]
        if let account = account {
            query[kSecAttrAccount] = account
        }
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return get(query: query as CFDictionary)
    }
    
    static func retrieveAllPasswordForService<T>(_ service: AnyObject? = nil) -> Result<[T], SecureStoreError> {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnData: kCFBooleanTrue as CFBoolean
        ]
        if let service = service {
            query[kSecAttrService] = service
        }
        let result: Result<CFArray, SecureStoreError> = get(query: query as CFDictionary)
        return result.map { $0 as! [T] }
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
    static func updateStoredPassword(_ password: AnyObject? = nil,
                                     accessGroup: String? = nil,
                                     forService service: AnyObject,
                                     account: AnyObject? = nil,
                                     accessibility: Accessibility? = nil) -> Result<Void, SecureStoreError> {
        // Search Query
        var searchQuery = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service
        ]
        if let account = account {
            searchQuery[kSecAttrAccount] = account
        }
        
        // Update Query
        var updateQuery = [
            kSecAttrService: service
        ]
        if let password = password {
            updateQuery[kSecValueData] = password
        }
        
        if let accessGroup = accessGroup {
            updateQuery[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        if let account = account {
            updateQuery[kSecAttrAccount] = account
        }
        
        if let accessibility = accessibility {
            updateQuery[kSecAttrAccessible] = accessibility.kSecAttrAccessible
        }
        
        return update(query: searchQuery as CFDictionary, with: updateQuery as CFDictionary)
    }
    
    static func deletePassword(forService service: AnyObject,
                               account: AnyObject? = nil,
                               accessGroup: String? = nil) -> Result<Void, SecureStoreError> {
        var query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service
        ]
        if let account = account {
            query[kSecAttrAccount] = account
        }
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup] = accessGroup as AnyObject
        }
        return delete(query: query as CFDictionary)
    }
}
