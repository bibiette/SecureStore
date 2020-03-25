//
//  RandomKeyGenerationTests.swift
//  SecureStoreTests
//
//  Created by Bibiette on 25/03/2020.
//

import XCTest
@testable import SecureStore

class RandomKeyGenerationTests: XCTestCase {
    func testWhenGeneratingRandomKeyOfSize10_ThenNewKeySizeIs10() {
        let size = 10
        let result = Keychain.generateSecureRandomKeyWithSize(size)
        switch result {
        case let .success(key):
            XCTAssertEqual(key.count, size)
        case let .failure(error):
            XCTFail("failure with error \(error)")
        }
    }
    
    func testWhenGeneratingTwoRandomKeyOfSize10_ThenKeysShouldNotBeEqual() throws {
        let size = 10
        let key1 = try XCTUnwrap(try? Keychain.generateSecureRandomKeyWithSize(size).get())
        let key2 = try XCTUnwrap(try? Keychain.generateSecureRandomKeyWithSize(size).get())
        XCTAssertEqual(key1.count, key2.count)
        XCTAssertNotEqual(key1, key2)
    }

    static var allTests = [
    ("testWhenGeneratingRandomKeyOfSize10_ThenNewKeySizeIs10", testWhenGeneratingRandomKeyOfSize10_ThenNewKeySizeIs10),
    ("testWhenGeneratingTwoRandomKeyOfSize10_ThenKeysShouldNotBeEqual", testWhenGeneratingTwoRandomKeyOfSize10_ThenKeysShouldNotBeEqual)
    ]
}
