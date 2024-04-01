//
//  TOTP+Async.swift
//  OTPKit
//
//  Created by David Walter on 15.06.23.
//

import Foundation

#if canImport(_Concurrency)
extension TOTP {
    /// `AsyncStream` of authentication codes. Will yield one code per start of the next period.
    ///
    /// ```swift
    /// let totp = TOTP(...)
    /// for await code in totp.authenticationCodes() {
    ///    // code
    /// }
    /// ```
    public func authenticationCodes() -> AsyncStream<String> {
        AsyncStream { continuation in
            guard !Task.isCancelled else {
                continuation.finish()
                return
            }
            
            // Yield the current authentication code immediately
            continuation.yield(authenticationCode())
            
            Task<Void, Never> {
                repeat {
                    do {
                        let timestamp = Date().timeIntervalSince1970 / period
                        let counter = uint_fast64_t(timestamp)
                        let decimals = timestamp - Double(counter)
                        let date = Date(timeIntervalSince1970: Double(counter + 1) * period + decimals)
                        try await Task.sleep(until: date)
                        let code = hotp.authenticationCode(for: counter + 1)
                        continuation.yield(code)
                    } catch {
                        continuation.finish()
                    }
                } while !Task.isCancelled
            }
        }
    }
}

extension Array where Element == TOTP {
    /// `AsyncStream` of authentication codes. Will yield one code per start of the next period.
    ///
    /// - Parameter period: Optional period on when to yield the next code.
    /// Defaults to minimum period of the given ``TOTP``s.
    ///
    /// ```swift
    /// let totp1 = TOTP(...)
    /// let totp2 = TOTP(...)
    /// for await codes in [totp1, totp2].authenticationCodes() {
    ///    // codes
    /// }
    /// ```
    public func authenticationCodes(period: TimeInterval? = nil) -> AsyncStream<[String]> {
        AsyncStream { continuation in
            guard !Task.isCancelled, !isEmpty, let period = period ?? map(\.period).min() else {
                continuation.finish()
                return
            }
            
            // Yield the current authentication codes immediately
            continuation.yield(map { $0.authenticationCode() })
            
            Task<Void, Never> {
                repeat {
                    do {
                        let timestamp = Date().timeIntervalSince1970 / period
                        let counter = uint_fast64_t(timestamp)
                        let decimals = timestamp - Double(counter)
                        let date = Date(timeIntervalSince1970: Double(counter + 1) * period + decimals)
                        try await Task.sleep(until: date)
                        let codes = map { totp in
                            let counter = uint_fast64_t(date.timeIntervalSince1970 / totp.period)
                            return totp.authenticationCode(for: counter)
                        }
                        continuation.yield(codes)
                    } catch {
                        continuation.finish()
                    }
                } while !Task.isCancelled
            }
        }
    }
}
#endif
