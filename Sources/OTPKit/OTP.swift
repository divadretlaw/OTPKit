import Foundation
import CryptoKit
import Base32

/// One-time password
open class OTP {
    // DIGITS_POWER                              0   1    2     3      4       5        6         7          8
    private static let DIGITS_POWER: [UInt32] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]
    
    public enum Mode {
        case sha1
        case sha256
        case sha512
        
        func authenticationCode(for data: Data, with key: Data) -> Data {
            let key = SymmetricKey(data: key)
            
            switch self {
            case .sha1:
                return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
            case .sha256:
                return Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
            case .sha512:
                return Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
            }
        }
    }
    
    private var key: Data
    private var digits: Int
    private var mode: Mode
    
    init?(key: Data, digits: Int = 6, mode: Mode = .sha1) {
        guard digits > 0, digits <= 8 else { return nil }
        
        self.key = key
        self.digits = digits
        self.mode = mode
    }

    init?(secret: String, digits: Int = 6, mode: Mode = .sha1) {
        guard let key = secret.base32DecodedData, digits > 0, digits <= 8 else { return nil }
        
        self.key = key
        self.digits = digits
        self.mode = mode
    }
    
    /// Generate the password for the given counter
    ///
    /// - Parameter counter: Value for which the token is generated
    /// - Returns: Generated token or nil on error
    public func generate(counter: UInt64) -> String? {
        var bigEndianCounter = counter.bigEndian
        let counterData = Data(bytes: &bigEndianCounter, count: MemoryLayout.size(ofValue: bigEndianCounter))
        
        let hmac = self.mode.authenticationCode(for: counterData, with: key)
        
        // put selected bytes into result int
        let truncated = hmac.withUnsafeBytes { rawPtr -> UInt32? in
            let buffer = rawPtr.bindMemory(to: UInt8.self)
            guard var ptr = buffer.baseAddress else { return nil }

            // offset with the last digit
            ptr = ptr + Int(ptr[hmac.count - 1] & 0xF)

            return ptr.withMemoryRebound(to: UInt32.self, capacity: 1) {
                $0.pointee
            }
        }

        guard var hash = truncated else { return nil }
        
        // ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        hash = UInt32(bigEndian: hash)
        hash = hash & 0x7FFFFFFF
        
        let password = hash % Self.DIGITS_POWER[self.digits]
        return String(format: "%0*u", self.digits, password)
    }
}
