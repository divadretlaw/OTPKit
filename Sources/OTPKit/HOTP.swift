import Foundation

/// HMAC-based one-time password version of the `OTP`
public final class HOTP: OTP {
    private var counter: UInt64
    
    /// HMAC-based one-time password
    /// 
    /// - Parameters:
    ///     - key: Shared Secret
    ///     - counter: Value of the counter
    ///     - digits: Number of digits. Must be between 1 and 8. Default 6
    ///     - mode: Mode used for token generation. Default: SHA1
    public init?(key: Data, counter: UInt64, digits: Int, mode: Mode) {
        self.counter = uint_fast64_t(counter)
        super.init(key: key, digits: digits, mode: mode)
    }
    
    /// HMAC-based one-time password
    ///
    /// - Parameters:
    ///     - secret: Shared Secret in Base32
    ///     - counter: Value of the counter
    ///     - digits: Number of digits. Must be between 1 and 8. Default 6
    ///     - mode: Mode used for token generation. Default: SHA1
    public init?(secret: String, counter: UInt64, digits: Int, mode: Mode) {
        self.counter = counter
        super.init(secret: secret, digits: digits, mode: mode)
    }
    
    /// Generate the next token
    ///
    /// - Returns: Generated Token or nil on error
    public func generate() -> String? {
        return generate(counter: counter)
    }
}
