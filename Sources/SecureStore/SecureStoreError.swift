//
//  SecureStoreError.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

public enum SecureStoreError: Int32, Error {
     case duplicatedItem = -25299 // errSecDuplicateItem
     case notFound = -25300 // errSecItemNotFound
     case missingEntitlement = -34018 // errSecMissingEntitlement
     case noAccess = -25243 // errSecNoAccessForItem, The specified item has no access control.
     case noSuchAttribute = -25303

     case unknown = 999
     case couldNotGenerateTag = 1

     public var description: String {
         if self == .unknown {
             return "Unknown SecError"
         }
         if #available(iOS 11.3, *) {
             return SecCopyErrorMessageString(self.rawValue, nil).debugDescription
         }
         switch self {
         case .duplicatedItem:
             return "Duplicated Item found in keychain"
         case .notFound:
             return "Could not found Item in keychain"
         case .missingEntitlement:
            return "Missing entitlement"
         case .noAccess:
            return "no access control"
         case .noSuchAttribute:
            return "No such attributes"
         case .unknown:
             return "Unknown Secure Store error"
         case .couldNotGenerateTag:
            return "Could not generate Tag"
         }
     }
 }
