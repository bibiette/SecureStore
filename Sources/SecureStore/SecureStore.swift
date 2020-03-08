//
//  SecureStore.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

public protocol SecureDataStoring {
    func wipeAll()
    
    func storeData(_ data: Data, withKey key: String) -> Result<Void, SecureStoreError>
    func retrieveDataWithKey(_ key: String) -> Result<Data, SecureStoreError>
}

public protocol SecureRandomKeyStoring {
    /// Will retrieve the stored Secure Random Key, if non exist it will create and store one before returning it
    /// - Parameters:
    ///   - size: The size the secure random key should be
    func retrieveSecureRandomKeyOfSize(_ size: Int, withKey key: String) -> Result<Data, SecureStoreError>
}

public struct SecureStore {
    /// An access group as definied in keychain access group
    /// Used to share data between app and app extension
    public let accessGroup: String?
    public let accessibility: Accessibility
    
    init(accessGroup: String? = nil, accessibility: Accessibility = .always) {
        self.accessGroup = accessGroup
        self.accessibility = accessibility
    }
}

// MARK: - SecureDataStoring
extension SecureStore: SecureDataStoring {
    public func wipeAll() {
        Keychain.wipeAll()
    }
    
    public func storeData(_ data: Data, withKey key: String) -> Result<Void, SecureStoreError> {
        guard let tag = key.data(using: .utf8, allowLossyConversion: false) else {
            return .failure(.couldNotGenerateTag)
        }
        return Keychain.storeData(data ,
                                  withTag: tag as AnyObject,
                                  accessGroup: accessGroup,
                                  accessibility: accessibility,
                                  overwrite: true)
    }
    
    public func retrieveDataWithKey(_ key: String) -> Result<Data, SecureStoreError> {
        guard let tag = key.data(using: .utf8, allowLossyConversion: false) else {
            return .failure(.couldNotGenerateTag)
        }
        return Keychain.retrieveDataWithTag(tag as AnyObject,
                                            accessGroup: accessGroup)
    }
}

extension SecureStore: SecureRandomKeyStoring {
    public func retrieveSecureRandomKeyOfSize(_ size: Int, withKey key: String) -> Result<Data, SecureStoreError> {
        let retrieveResult = retrieveDataWithKey(key)
        switch retrieveResult {
        case .failure(let error) where error == .notFound:
            switch Keychain.generateSecureRandomKeyWithSize(size) {
            case .success(let secureKey):
                return storeData(secureKey, withKey: key).map { secureKey }
            default:
                return .failure(.unknown)
            }
        default: return retrieveResult
        }
    }
}
