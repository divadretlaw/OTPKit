import XCTest
@testable import OTPKit

final class TOTPTests: XCTestCase {
    private func test(interval: TimeInterval, mode: OTP.Mode) -> String? {
        // Secret: 12345678901234567890 in Base32
        guard let tool = TOTP(secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", duration: 30, digits: 8, mode: mode) else {
            XCTFail("Unable to create TOTP OATHTool")
            return nil
        }
        
        let date = Date(timeIntervalSince1970: interval)
        return tool.generate(date: date)
    }
    
    func testSHA1() {
        XCTAssertEqual(test(interval: 59, mode: .sha1), "94287082")
        XCTAssertEqual(test(interval: 1111111109, mode: .sha1), "07081804")
        XCTAssertEqual(test(interval: 1111111111, mode: .sha1), "14050471")
        XCTAssertEqual(test(interval: 1234567890, mode: .sha1), "89005924")
        XCTAssertEqual(test(interval: 2000000000, mode: .sha1), "69279037")
        XCTAssertEqual(test(interval: 20000000000, mode: .sha1), "65353130")
    }
    
    func testSHA256() {
        XCTAssertEqual(test(interval: 59, mode: .sha256), "32247374")
        XCTAssertEqual(test(interval: 1111111109, mode: .sha256), "34756375")
        XCTAssertEqual(test(interval: 1111111111, mode: .sha256), "74584430")
        XCTAssertEqual(test(interval: 1234567890, mode: .sha256), "42829826")
        XCTAssertEqual(test(interval: 2000000000, mode: .sha256), "78428693")
        XCTAssertEqual(test(interval: 20000000000, mode: .sha256), "24142410")
    }
    
    func testSHA512() {
        XCTAssertEqual(test(interval: 59, mode: .sha512), "69342147")
        XCTAssertEqual(test(interval: 1111111109, mode: .sha512), "63049338")
        XCTAssertEqual(test(interval: 1111111111, mode: .sha512), "54380122")
        XCTAssertEqual(test(interval: 1234567890, mode: .sha512), "76671578")
        XCTAssertEqual(test(interval: 2000000000, mode: .sha512), "56464532")
        XCTAssertEqual(test(interval: 20000000000, mode: .sha512), "69481994")
    }
}
