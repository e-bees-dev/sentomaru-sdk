import Foundation
@testable import SentomaruCapacitorBridge
import XCTest

final class ReplyShapingTests: XCTestCase {
    func testADictionaryPassesThroughUnchanged() {
        let data = SentomaruCapacitorReply.data(["sessionId": "s1", "keyId": "k1"])
        XCTAssertEqual(data as? [String: String], ["sessionId": "s1", "keyId": "k1"])
    }

    func testAScalarIsWrappedUnderValue() {
        XCTAssertEqual(SentomaruCapacitorReply.data("Enrolled") as? [String: String], ["value": "Enrolled"])
        XCTAssertEqual(SentomaruCapacitorReply.data(true) as? [String: Bool], ["value": true])
    }

    func testAnArrayIsWrappedUnderValue() {
        let data = SentomaruCapacitorReply.data([1, 2, 3])
        XCTAssertEqual(data["value"] as? [Int], [1, 2, 3])
    }

    func testNilIsWrappedAsNSNull() {
        let data = SentomaruCapacitorReply.data(nil)
        XCTAssertTrue(data["value"] is NSNull)
    }
}
