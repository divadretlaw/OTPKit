import XCTest
@testable import OTPKit

final class HOTPTests: XCTestCase {
    /// HOTP Tests
    ///
    /// See: https://www.rfc-editor.org/rfc/rfc4226#page-32
    func test() throws {
        let secret = "12345678901234567890"
        let hotp = HOTP(key: Data(secret.utf8))
        
        XCTAssertEqual(hotp.authenticationCode(for: 0), "755224")
        XCTAssertEqual(hotp.authenticationCode(for: 1), "287082")
        XCTAssertEqual(hotp.authenticationCode(for: 2), "359152")
        XCTAssertEqual(hotp.authenticationCode(for: 3), "969429")
        XCTAssertEqual(hotp.authenticationCode(for: 4), "338314")
        XCTAssertEqual(hotp.authenticationCode(for: 5), "254676")
        XCTAssertEqual(hotp.authenticationCode(for: 6), "287922")
        XCTAssertEqual(hotp.authenticationCode(for: 7), "162583")
        XCTAssertEqual(hotp.authenticationCode(for: 8), "399871")
        XCTAssertEqual(hotp.authenticationCode(for: 9), "520489")
    }
    
    func test_digits() throws {
        let secret = "12345678901234567890"
        
        for digits in 1...10 {
            let hotp = HOTP(key: Data(secret.utf8), digits: digits)
            XCTAssertEqual(hotp.authenticationCode(for: 0), String("1284755224".suffix(digits)))
        }
    }
    
    func test_Encodable() async throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let secret = "12345678901234567890"
        let hotp = HOTP(key: Data(secret.utf8), digits: 6)
        let data = try encoder.encode(hotp)
        guard let json = String(data: data, encoding: .utf8) else { return }
        print(json)
    }
    
    func test_Decodable() async throws {
        let decoder = JSONDecoder()
        
        let json = """
        {
            "key": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "digits": 6,
            "algorithm": "SHA1"
        }
        """
        
        _ = try decoder.decode(HOTP.self, from: Data(json.utf8))
    }
}
