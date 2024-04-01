//
//  Data+Extensions.swift
//  OTPKit
//
//  Created by David Walter on 01.04.24.
//

import Foundation
import CryptoKit

extension Data {
    init(_ key: SymmetricKey) {
        self = key.withUnsafeBytes { body in
            Data(body)
        }
    }
}
