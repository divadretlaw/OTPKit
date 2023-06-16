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
public struct TOTP: Equatable, Hashable, Codable {
    internal let hotp: HOTP
    
    /// `TimeInterval` the one-time password is valid
    public let period: TimeInterval
    
    /// Base32 encoded key
    public var base32EncodedKey: String {
        hotp.base32EncodedKey
    }
    
    /// Number of digits of the one-time password
    public var digits: Int { hotp.digits }
    /// HMAC alogrithm used to compute the one-time password
    public var algorithm: OTPAlgorithm { hotp.algorithm }
    
    /// Creates a Time-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - period: The window that produces the same code. Defaults to 30 seconds.
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
    ///   - period: The window that produces the same code. Defaults to 30 seconds.
    ///   - digits: The number of digits (1 - 10) in the computed authentication code. Defaults to 6.
    ///   - algorithm: The function to compute the hash with. Defaults to ``OTPAlgorithm/sha1``.
    public init(key data: Data, period: TimeInterval = 30, digits: Int = 6, algorithm: OTPAlgorithm = .sha1) {
        self.init(key: SymmetricKey(data: data), period: period, digits: digits, algorithm: algorithm)
    }
    
    
    /// Creates a Time-based one-time password generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    ///   - period: The window that produces the same code. Defaults to 30 seconds.
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
    
    // MARK: - HOTP Helper
    
    internal func authenticationCode(for counter: UInt64) -> String {
        hotp.authenticationCode(for: counter.bigEndian.data)
    }
    
    // MARK: - Codable
    
    enum CodingKeys: CodingKey {
        case key
        case digits
        case algorithm
        case period
    }
    
    // MARK: - Encodable
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(base32EncodedKey, forKey: .key)
        try container.encode(digits, forKey: .digits)
        try container.encode(algorithm, forKey: .algorithm)
        try container.encode(period, forKey: .period)
    }
    
    // MARK: - Decodable
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let base32 = try container.decode(String.self, forKey: .key)
        guard let data = Data(base32Encoded: base32) else {
            let context = DecodingError.Context(codingPath: [CodingKeys.key], debugDescription: "Key is not Base32 encoded.")
            throw DecodingError.dataCorrupted(context)
        }
        let key = SymmetricKey(data: data)
        let digits = try container.decode(Int.self, forKey: .digits)
        let algorithm = try container.decode(OTPAlgorithm.self, forKey: .algorithm)
        self.hotp = HOTP(key: key, digits: digits, algorithm: algorithm)
        self.period = try container.decode(TimeInterval.self, forKey: .period)
    }
}
