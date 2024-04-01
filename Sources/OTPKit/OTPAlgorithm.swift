//
//  OTPAlgorithm.swift
//  OTPKit
//
//  Created by David Walter on 02.04.23.
//

import Foundation
import CryptoKit

/// Hash function to compute the one-time password with.
public enum OTPAlgorithm: String, Equatable, Hashable, Codable, Sendable, CustomStringConvertible {
    /// Compute HMAC with SHA-1
    case sha1 = "SHA1"
    /// Compute HMAC with SHA-256
    case sha256 = "SHA256"
    /// Compute HMAC with SHA-384
    case sha384 = "SHA384"
    /// Compute HMAC with SHA-512
    case sha512 = "SHA512"
    /// Compute HMAC with MD5
    case md5 = "MD5"
    
    func authenticationCode<D>(for data: D, using key: SymmetricKey) -> Data where D: DataProtocol {
        switch self {
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
        case .sha384:
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: key))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
        case .md5:
            return Data(HMAC<Insecure.MD5>.authenticationCode(for: data, using: key))
        }
    }
    
    public var description: String {
        switch self {
        case .sha1:
            return "SHA-1"
        case .sha256:
            return "SHA-256"
        case .sha384:
            return "SHA-384"
        case .sha512:
            return "SHA-512"
        case .md5:
            return "MD5"
        }
    }
}
