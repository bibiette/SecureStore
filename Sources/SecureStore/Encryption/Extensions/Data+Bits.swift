//
//  DataExtension.swift
//  SecureStore
//
//  Created by Barbara Rollet on 14/09/2018.
//  Copyright © 2020 Barbara Rollet. All rights reserved.
//

import Foundation

extension Data {
    public var bytes: Int {
        return count
    }

    public var bits: Int {
        return bytes * 8
    }
}
