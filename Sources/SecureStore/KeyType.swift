//
//  KeyType.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

enum KeyType {
    case `private`
    case `public`

    internal var kSecAttrKeyClass: CFString {
        switch self {
        case .private:
            return kSecAttrKeyClassPrivate
        case .public:
            return kSecAttrKeyClassPublic
        }
    }
}
