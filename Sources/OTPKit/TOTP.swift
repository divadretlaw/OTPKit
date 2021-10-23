import Foundation

/// Time-based One-Time Password version of the `OTP`
public final class TOTP: OTP {
    public private(set) var duration: TimeInterval
    
    /// Time-based One-Time Password
    ///
    /// - Parameters:
    ///     - key: Shared Secret
    ///     - duration: Time-step duration, must be greater than 0. Default 30s
    ///     - digits: Number of digits. Must be between 1 and 8. Default 6
    ///     - mode: Mode used for token generation. Default: SHA1
    public init?(key: Data, duration: TimeInterval = 30, digits: Int = 6, mode: Mode = .sha1) {
        guard duration > 0 else { return nil }
        
        self.duration = duration
        
        super.init(key: key, digits: digits, mode: mode)
    }
    
    /// Time-based One-Time Password
    /// 
    /// - Parameters:
    ///     - secret: Shared Secret in Base32
    ///     - duration: Time-step duration. Default 30s
    ///     - digits: Number of digits. Must be between 1 and 8. Default 6
    ///     - mode: Mode used for token generation. Default: SHA1
    public init?(secret: String, duration: TimeInterval = 30, digits: Int = 6, mode: Mode = .sha1) {
        guard duration > 0 else { return nil }
        
        self.duration = duration
        
        super.init(secret: secret, digits: digits, mode: mode)
    }
    
    /// Generate current token
    ///
    /// - Returns: Generated Token or nil on error
    public func generate() -> String? {
        return generate(date: Date())
    }
    
    /// Generate token based on time
    ///
    /// - Parameter date: Date for when to generate the code
    /// - Returns: Generated Token or nil on error
    public func generate(date: Date) -> String? {
        let seconds = date.timeIntervalSince1970
        let counter = UInt64(seconds / self.duration)
        return self.generate(counter: counter)
    }
}
