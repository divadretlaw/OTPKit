//
//  Base32.swift
//  OTPKit
//
//  Created by 野村 憲男 on 1/24/15.
//
//  Copyright (c) 2015 Norio Nomura
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

import Foundation

// https://tools.ietf.org/html/rfc4648

// MARK: - Extensions

public extension Data {
    // base32
    func base32EncodedString() -> String {
        withUnsafeBytes { ptr -> String in
            base32encode(ptr.baseAddress, count, alphabetEncodeTable)
        }
    }
    
    func base32EncodedData() -> Data {
        Data(base32EncodedString().utf8)
    }
    
    init?(base32Encoded: Data) {
        guard let data = String(data: base32Encoded, encoding: .utf8).flatMap(base32Decode) else { return nil }
        self = data
    }
    
    init?(base32Encoded: String) {
        guard let data = base32Decode(base32Encoded) else { return nil }
        self = data
    }
}

// MARK: - Private

private func base32Encode(_ data: Data) -> String {
    return data.withUnsafeBytes { ptr -> String in
        base32encode(ptr.baseAddress, data.count, alphabetEncodeTable)
    }
}

private func base32Decode(_ string: String) -> Data? {
    return base32decode(string, alphabetDecodeTable).flatMap {
        Data(bytes: $0, count: $0.count)
    }
}

// MARK: encode

private let alphabetEncodeTable: [Int8] = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","2","3","4","5","6","7"].map { (c: UnicodeScalar) -> Int8 in Int8(c.value) }

private func base32encode(_ data: UnsafeRawPointer?, _ length: Int, _ table: [Int8]) -> String {
    guard length > 0, let data = data else { return "" }
    
    var length = length
    
    var bytes = data.assumingMemoryBound(to: UInt8.self)
    
    let resultBufferSize = Int(ceil(Double(length) / 5)) * 8 + 1    // need null termination
    let resultBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: resultBufferSize)
    var encoded = resultBuffer
    
    // encode regular blocks
    while length >= 5 {
        encoded[0] = table[Int(bytes[0] >> 3)]
        encoded[1] = table[Int((bytes[0] & 0b00000111) << 2 | bytes[1] >> 6)]
        encoded[2] = table[Int((bytes[1] & 0b00111110) >> 1)]
        encoded[3] = table[Int((bytes[1] & 0b00000001) << 4 | bytes[2] >> 4)]
        encoded[4] = table[Int((bytes[2] & 0b00001111) << 1 | bytes[3] >> 7)]
        encoded[5] = table[Int((bytes[3] & 0b01111100) >> 2)]
        encoded[6] = table[Int((bytes[3] & 0b00000011) << 3 | bytes[4] >> 5)]
        encoded[7] = table[Int((bytes[4] & 0b00011111))]
        length -= 5
        encoded = encoded.advanced(by: 8)
        bytes = bytes.advanced(by: 5)
    }
    
    // encode last block
    var byte0, byte1, byte2, byte3, byte4: UInt8
    (byte0, byte1, byte2, byte3, byte4) = (0,0,0,0,0)
    switch length {
    case 4:
        byte3 = bytes[3]
        encoded[6] = table[Int((byte3 & 0b00000011) << 3 | byte4 >> 5)]
        encoded[5] = table[Int((byte3 & 0b01111100) >> 2)]
        fallthrough
    case 3:
        byte2 = bytes[2]
        encoded[4] = table[Int((byte2 & 0b00001111) << 1 | byte3 >> 7)]
        fallthrough
    case 2:
        byte1 = bytes[1]
        encoded[3] = table[Int((byte1 & 0b00000001) << 4 | byte2 >> 4)]
        encoded[2] = table[Int((byte1 & 0b00111110) >> 1)]
        fallthrough
    case 1:
        byte0 = bytes[0]
        encoded[1] = table[Int((byte0 & 0b00000111) << 2 | byte1 >> 6)]
        encoded[0] = table[Int(byte0 >> 3)]
    default: break
    }
    
    // padding
    let pad = Int8(UnicodeScalar("=").value)
    switch length {
    case 0:
        encoded[0] = 0
    case 1:
        encoded[2] = pad
        encoded[3] = pad
        fallthrough
    case 2:
        encoded[4] = pad
        fallthrough
    case 3:
        encoded[5] = pad
        encoded[6] = pad
        fallthrough
    case 4:
        encoded[7] = pad
        fallthrough
    default:
        encoded[8] = 0
        break
    }
    
    // return
    if let base32Encoded = String(validatingUTF8: resultBuffer) {
        resultBuffer.deallocate()
        return base32Encoded
    } else {
        resultBuffer.deallocate()
        fatalError("internal error")
    }
}

// MARK: decode

let __: UInt8 = 255
let alphabetDecodeTable: [UInt8] = [
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x00 - 0x0F
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x10 - 0x1F
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x20 - 0x2F
    __,__,26,27, 28,29,30,31, __,__,__,__, __,__,__,__,  // 0x30 - 0x3F
    __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x40 - 0x4F
    15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x50 - 0x5F
    __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x60 - 0x6F
    15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x70 - 0x7F
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x80 - 0x8F
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x90 - 0x9F
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xA0 - 0xAF
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xB0 - 0xBF
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xC0 - 0xCF
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xD0 - 0xDF
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xE0 - 0xEF
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xF0 - 0xFF
]

private func base32decode(_ string: String, _ table: [UInt8]) -> [UInt8]? {
    let length = string.unicodeScalars.count
    if length == 0 {
        return []
    }
    
    // calc padding length
    func getLeastPaddingLength(_ string: String) -> Int {
        if string.hasSuffix("======") {
            return 6
        } else if string.hasSuffix("====") {
            return 4
        } else if string.hasSuffix("===") {
            return 3
        } else if string.hasSuffix("=") {
            return 1
        } else {
            return 0
        }
    }
    
    // validate string
    let leastPaddingLength = getLeastPaddingLength(string)
    if let index = string.unicodeScalars.firstIndex(where: {$0.value > 0xff || table[Int($0.value)] > 31}) {
        // index points padding "=" or invalid character that table does not contain.
        let pos = string.unicodeScalars.distance(from: string.unicodeScalars.startIndex, to: index)
        // if pos points padding "=", it's valid.
        if pos != length - leastPaddingLength {
            print("string contains some invalid characters.")
            return nil
        }
    }
    
    var remainEncodedLength = length - leastPaddingLength
    var additionalBytes = 0
    switch remainEncodedLength % 8 {
        // valid
    case 0: break
    case 2: additionalBytes = 1
    case 4: additionalBytes = 2
    case 5: additionalBytes = 3
    case 7: additionalBytes = 4
    default:
        print("string length is invalid.")
        return nil
    }
    
    // validated
    let dataSize = remainEncodedLength / 8 * 5 + additionalBytes
    
    // Use UnsafePointer<UInt8>
    return string.utf8CString.withUnsafeBufferPointer {
        (data: UnsafeBufferPointer<CChar>) -> [UInt8] in
        var encoded = data.baseAddress!
        
        var result = Array<UInt8>(repeating: 0, count: dataSize)
        var decodedOffset = 0
        
        // decode regular blocks
        var value0, value1, value2, value3, value4, value5, value6, value7: UInt8
        (value0, value1, value2, value3, value4, value5, value6, value7) = (0,0,0,0,0,0,0,0)
        while remainEncodedLength >= 8 {
            value0 = table[Int(encoded[0])]
            value1 = table[Int(encoded[1])]
            value2 = table[Int(encoded[2])]
            value3 = table[Int(encoded[3])]
            value4 = table[Int(encoded[4])]
            value5 = table[Int(encoded[5])]
            value6 = table[Int(encoded[6])]
            value7 = table[Int(encoded[7])]
            
            result[decodedOffset]     = value0 << 3 | value1 >> 2
            result[decodedOffset + 1] = value1 << 6 | value2 << 1 | value3 >> 4
            result[decodedOffset + 2] = value3 << 4 | value4 >> 1
            result[decodedOffset + 3] = value4 << 7 | value5 << 2 | value6 >> 3
            result[decodedOffset + 4] = value6 << 5 | value7
            
            remainEncodedLength -= 8
            decodedOffset += 5
            encoded = encoded.advanced(by: 8)
        }
        
        // decode last block
        (value0, value1, value2, value3, value4, value5, value6, value7) = (0,0,0,0,0,0,0,0)
        
        switch remainEncodedLength {
        case 7:
            value6 = table[Int(encoded[6])]
            value5 = table[Int(encoded[5])]
            fallthrough
        case 5:
            value4 = table[Int(encoded[4])]
            fallthrough
        case 4:
            value3 = table[Int(encoded[3])]
            value2 = table[Int(encoded[2])]
            fallthrough
        case 2:
            value1 = table[Int(encoded[1])]
            value0 = table[Int(encoded[0])]
        default:
            break
        }
        
        switch remainEncodedLength {
        case 7:
            result[decodedOffset + 3] = value4 << 7 | value5 << 2 | value6 >> 3
            fallthrough
        case 5:
            result[decodedOffset + 2] = value3 << 4 | value4 >> 1
            fallthrough
        case 4:
            result[decodedOffset + 1] = value1 << 6 | value2 << 1 | value3 >> 4
            fallthrough
        case 2:
            result[decodedOffset]     = value0 << 3 | value1 >> 2
        default:
            break
        }
        
        return result
    }
}
