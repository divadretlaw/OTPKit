import XCTest
@testable import OTPKit

final class TOTPTests: XCTestCase {
    /// TOTP Tests
    ///
    /// See: https://www.rfc-editor.org/rfc/rfc6238#page-15
    func test() throws {
        let secret = "12345678901234567890"
        let secret32 = "12345678901234567890123456789012"
        let secret64 = "1234567890123456789012345678901234567890123456789012345678901234"
        
        let totpSHA1 = TOTP(key: Data(secret.utf8), period: 30, digits: 8, algorithm: .sha1)
        let totpSHA256 = TOTP(key: Data(secret32.utf8), period: 30, digits: 8, algorithm: .sha256)
        let totpSHA512 = TOTP(key: Data(secret64.utf8), period: 30, digits: 8, algorithm: .sha512)
        
        // Time(sec): 59
        let time59 = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(totpSHA1.authenticationCode(for: time59), "94287082")
        XCTAssertEqual(totpSHA256.authenticationCode(for: time59), "46119246")
        XCTAssertEqual(totpSHA512.authenticationCode(for: time59), "90693936")
        // Time(sec): 1111111109
        let time1111111109 = Date(timeIntervalSince1970: 1111111109)
        XCTAssertEqual(totpSHA1.authenticationCode(for: time1111111109), "07081804")
        XCTAssertEqual(totpSHA256.authenticationCode(for: time1111111109), "68084774")
        XCTAssertEqual(totpSHA512.authenticationCode(for: time1111111109), "25091201")
        // Time(sec): 1111111111
        let time1111111111 = Date(timeIntervalSince1970: 1111111111)
        XCTAssertEqual(totpSHA1.authenticationCode(for: time1111111111), "14050471")
        XCTAssertEqual(totpSHA256.authenticationCode(for: time1111111111), "67062674")
        XCTAssertEqual(totpSHA512.authenticationCode(for: time1111111111), "99943326")
        // Time(sec): 1234567890
        let time1234567890 = Date(timeIntervalSince1970: 1234567890)
        XCTAssertEqual(totpSHA1.authenticationCode(for: time1234567890), "89005924")
        XCTAssertEqual(totpSHA256.authenticationCode(for: time1234567890), "91819424")
        XCTAssertEqual(totpSHA512.authenticationCode(for: time1234567890), "93441116")
        // Time(sec): 2000000000
        let time2000000000 = Date(timeIntervalSince1970: 2000000000)
        XCTAssertEqual(totpSHA1.authenticationCode(for: time2000000000), "69279037")
        XCTAssertEqual(totpSHA256.authenticationCode(for: time2000000000), "90698825")
        XCTAssertEqual(totpSHA512.authenticationCode(for: time2000000000), "38618901")
        // Time(sec): 20000000000
        let time20000000000 = Date(timeIntervalSince1970: 20000000000)
        XCTAssertEqual(totpSHA1.authenticationCode(for: time20000000000), "65353130")
        XCTAssertEqual(totpSHA256.authenticationCode(for: time20000000000), "77737706")
        XCTAssertEqual(totpSHA512.authenticationCode(for: time20000000000), "47863826")
    }
    
    /// TOTP async stream tests
    func test_async() async throws {
        let secret = "12345678901234567890"
        let totp = TOTP(key: Data(secret.utf8), period: 30, digits: 6, algorithm: .sha1)
        
        let codeExpecation = XCTestExpectation()
        codeExpecation.expectedFulfillmentCount = 10
        let outOfLoopExpecation = XCTestExpectation()
        
        let task = Task {
            for await code in totp.authenticationCodes() {
                print(code)
                // Check if the returned code coresponds with a generated code now
                XCTAssertEqual(code, totp.authenticationCode())
                codeExpecation.fulfill()
            }
            // We should reach this after cancelling the task
            outOfLoopExpecation.fulfill()
        }
        
        await fulfillment(of: [codeExpecation], timeout: 500)
        task.cancel()
        await fulfillment(of: [outOfLoopExpecation])
    }
    
    /// TOTP cancel async stream tests
    func test_async_cancel() async throws {
        let secret = "12345678901234567890"
        let totp = TOTP(key: Data(secret.utf8), period: 30, digits: 6, algorithm: .sha1)
        
        let outOfLoopExpecation = XCTestExpectation()
        
        let task = Task {
            try? await Task.sleep(seconds: 5)
            for await code in totp.authenticationCodes() {
                print(code)
                print("Test")
            }
            // We should reach this after cancelling the task
            outOfLoopExpecation.fulfill()
            print("END")
        }
        
        task.cancel()
        await fulfillment(of: [outOfLoopExpecation])
    }
    
    /// TOTP collection async stream tests
    func test_async_collection() async throws {
        let secret1 = "12345678901234567890"
        let totp1 = TOTP(key: Data(secret1.utf8), period: 20, digits: 8, algorithm: .sha1)
        let secret2 = "12345678901234567890123456789012"
        let totp2 = TOTP(key: Data(secret2.utf8), period: 30, digits: 6, algorithm: .sha1)
        
        let codeExpecation = XCTestExpectation()
        codeExpecation.expectedFulfillmentCount = 5
        let outOfLoopExpecation = XCTestExpectation()
        
        let task = Task {
            for await codes in [totp1, totp2].authenticationCodes() {
                print(codes)
                // Check if the returned code coresponds with a generated code now
                XCTAssertEqual(codes, [totp1.authenticationCode(), totp2.authenticationCode()])
                codeExpecation.fulfill()
            }
            // We should reach this after cancelling the task
            outOfLoopExpecation.fulfill()
        }
        
        await fulfillment(of: [codeExpecation], timeout: 200)
        task.cancel()
        await fulfillment(of: [outOfLoopExpecation])
    }
    
    func test_Encodable() async throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let secret = "12345678901234567890"
        let totp = TOTP(key: Data(secret.utf8))
        let data = try encoder.encode(totp)
        guard let json = String(data: data, encoding: .utf8) else { return }
        print(json)
    }
    
    func test_Decodable() async throws {
        let decoder = JSONDecoder()
        
        let json = """
        {
            "key": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "digits": 6,
            "algorithm": "SHA1",
            "period" : 30
        }
        """
        
        _ = try decoder.decode(TOTP.self, from: Data(json.utf8))
    }
}
