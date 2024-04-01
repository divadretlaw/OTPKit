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
public struct HOTP: Equatable, Hashable, Codable, Sendable {
    /// Data representation of the key used to secure the computation
    private let data: Data
    
    /// Number of digits of the one-time password
    public let digits: Int
    /// HMAC alogrithm used to compute the one-time password
    public let algorithm: OTPAlgorithm
    
    /// Base32 encoded key
    public var base32EncodedKey: String {
        data.base32EncodedString()
    }
    
    /// SymmetricKey created from the key data
    internal var key: SymmetricKey {
        SymmetricKey(data: data)
    }
    
    /// Creates a HMAC-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init(key: SymmetricKey, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        self.data = Data(key)
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
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        key.withUnsafeBytes { body in
            hasher.combine(bytes: body)
        }
        hasher.combine(digits)
        hasher.combine(algorithm)
    }
    
    // MARK: - Codable
    
    enum CodingKeys: CodingKey {
        case key
        case digits
        case algorithm
    }
    
    // MARK: - Encodable
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(base32EncodedKey, forKey: .key)
        try container.encode(digits, forKey: .digits)
        try container.encode(algorithm, forKey: .algorithm)
    }
    
    // MARK: - Decodable
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let base32 = try container.decode(String.self, forKey: .key)
        guard let data = Data(base32Encoded: base32) else {
            let context = DecodingError.Context(codingPath: [CodingKeys.key], debugDescription: "Key is not Base32 encoded.")
            throw DecodingError.dataCorrupted(context)
        }
        self.data = data
        self.digits = try container.decode(Int.self, forKey: .digits)
        self.algorithm = try container.decode(OTPAlgorithm.self, forKey: .algorithm)
    }
}
