//
//  Accessibility.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

public enum Accessibility {
      /// The data in the keychain item can be accessed only while the device is unlocked by the user.
      case whenUnlocked
      /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
      case afterFirstUnlock
      /// The data in the keychain item can always be accessed regardless of whether the device is locked.
      case always
      /// The data in the keychain can only be accessed when the device is unlocked. Only available if a passcode is set on the device
      ///  Items with this attribute do not migrate to a new device
      case whenPasscodeSetThisDeviceOnly
      /// The data in the keychain item can be accessed only while the device is unlocked by the user.
      ///  Items with this attribute do not migrate to a new device
      case whenUnlockedThisDeviceOnly
      /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
      ///  Items with this attribute do not migrate to a new device
      case afterFirstUnlockThisDeviceOnly
      ///  The data in the keychain item can always be accessed regardless of whether the device is locked.
      ///  Items with this attribute do not migrate to a new device
      case alwaysThisDeviceOnly

      internal var kSecAttrAccessible: CFString {
          switch self {
          case .whenUnlocked:
              return kSecAttrAccessibleWhenUnlocked
          case .afterFirstUnlock:
              return kSecAttrAccessibleAfterFirstUnlock
          case .always:
              return kSecAttrAccessibleAlways
          case .whenPasscodeSetThisDeviceOnly:
              return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
          case .whenUnlockedThisDeviceOnly:
              return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
          case .afterFirstUnlockThisDeviceOnly:
              return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
          case .alwaysThisDeviceOnly:
              return kSecAttrAccessibleAlwaysThisDeviceOnly
          }
      }
  }
