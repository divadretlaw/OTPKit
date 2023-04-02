//
//  TOTP.swift
//  OTPKit
//
//  Created by David Walter on 02.04.23.
//

import Foundation
import CryptoKit

/// TOTP: A Time-Based One-Time Password Algorithm
///
/// See https://www.rfc-editor.org/rfc/rfc6238 for details
public struct TOTP {
    var hotp: HOTP
    var period: TimeInterval
    
    /// Creates a Time-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - period: The window that produce the same code. Defaults to 30 seconds.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init(key: SymmetricKey, period: TimeInterval = 30, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        self.hotp = HOTP(key: key, digits: digits, algorithm: algorithm)
        self.period = period
    }
    
    /// Creates a Time-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - period: The window that produce the same code. Defaults to 30 seconds.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init(key data: Data, period: TimeInterval = 30, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        self.init(key: SymmetricKey(data: data), period: period, digits: digits, algorithm: algorithm)
    }
    
    
    /// Creates a Time-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - period: The window that produce the same code. Defaults to 30 seconds.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``HashFunction/sha1``.
    public init?(base32: String, period: TimeInterval = 30, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        guard let data = Data(base32Encoded: base32) else { return nil }
        self.init(key: SymmetricKey(data: data), period: period, digits: digits, algorithm: algorithm)
    }
    
    /// Generate the authentication code for the given timestamp.
    ///
    /// - Parameter date: The timestamp to generate the authentication code for. Defaults to now.
    /// - Returns: The authentication code.
    public func authenticationCode(for date: Date = Date()) -> String {
        let counter = uint_fast64_t(date.timeIntervalSince1970 / period)
        return hotp.authenticationCode(for: counter)
    }
}
