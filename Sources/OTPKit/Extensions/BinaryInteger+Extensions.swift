//
//  BinaryInteger+Extensions.swift
//  OTPKit
//
//  Created by David Walter on 02.04.23.
//

import Foundation

extension BinaryInteger {
    init(data: Data) {
        self = data
            .prefix(MemoryLayout.size(ofValue: Self.self))
            .enumerated()
            .reduce(into: 0) { result, element in
                result |= Self(element.element) << (element.offset * 8)
            }
    }
    
    init<T>(_ source: T?) where T: BinaryInteger {
        if let source = source {
            self = Self(source)
        } else {
            self = 0
        }
    }
    
    var data: Data {
        withUnsafeBytes(of: self) { Data($0) }
    }
}
