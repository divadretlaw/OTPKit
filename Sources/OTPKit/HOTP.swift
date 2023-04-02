//
//  HOTP.swift
//  OTPKit
//
//  Created by David Walter on 02.04.23.
//

import Foundation
import CryptoKit

/// HOTP: An HMAC-Based One-Time Password Algorithm
///
/// See https://www.rfc-editor.org/rfc/rfc4226 for details
public struct HOTP {
    var key: SymmetricKey
    var digits: Int
    var algorithm: OTPAlgorithm
    
    /// Creates a HMAC-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init(key: SymmetricKey, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        self.key = key
        self.digits = max(1, min(digits, 10))
        self.algorithm = algorithm
    }
    
    /// Creates a HMAC-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init(key data: Data, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        self.init(key: SymmetricKey(data: data), digits: digits, algorithm: algorithm)
    }
    
    /// Creates a HMAC-based one-time password generator.
    ///
    /// - Parameters:
    ///   - base32: The Base32 encoded symmetric key used to secure the computation.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init?(base32: String, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        guard let data = Data(base32Encoded: base32) else { return nil }
        self.init(key: SymmetricKey(data: data), digits: digits, algorithm: algorithm)
    }
    
    /// Generate the authentication code for the given counter.
    ///
    /// - Parameter counter: The counter to generate the authentication code for.
    /// - Returns: The authentication code.
    public func authenticationCode<I>(for counter: I) -> String where I: BinaryInteger {
        authenticationCode(for: UInt64(counter))
    }
    
    /// Generate the authentication code for the given counter.
    ///
    /// - Parameter counter: The counter to generate the authentication code for.
    /// - Returns: The authentication code.
    public func authenticationCode(for counter: UInt64) -> String {
        authenticationCode(for: counter.bigEndian.data)
    }
    
    /// Generate the authentication code for the given counter.
    ///
    /// - Parameter counter: The counter to generate the authentication code for.
    /// - Returns: The authentication code.
    func authenticationCode(for data: Data) -> String {
        // Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
        let authenticationCode = algorithm.authenticationCode(for: data, using: key)
        let hs = Data(authenticationCode) // HS s a 20-byte string
        
        // Step 2: Generate a 4-byte string (Dynamic Truncation)
        let offset = Int(hs.last) & 0xF
        let Sbits = hs[offset...offset + 3]
        
        // Step 3: Compute an HOTP value
        let Snum = UInt32(data: Sbits).bigEndian & 0x7FFFFFFF // Convert S to a number in ...2^{31}-1
        let D = UInt64(Snum) % UInt64(pow(10, Double(digits))) // D is a number in the range 0...10^{Digit}-1
        return String(format: "%0*d", digits, D)
    }
}
