//
//  Task+Extensions.swift
//  OTPKit
//
//  Created by David Walter on 15.06.23.
//

import Foundation

extension Task where Success == Never, Failure == Never {
    static func sleep(seconds: TimeInterval) async throws {
        guard seconds >= 0 else { return }
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }
    
    static func sleep(until: Date) async throws {
        try await Task.sleep(seconds: until.timeIntervalSinceNow)
    }
}
