import Foundation
@testable import SentomaruCordovaBridge
import SentomaruHybridCore
import XCTest

final class ReplyShapingTests: XCTestCase {
    func testStatusMapsSuccessToOkAndEverythingElseToError() {
        XCTAssertEqual(SentomaruCordovaReply.status(for: .success), .ok)
        XCTAssertEqual(SentomaruCordovaReply.status(for: .failure), .error)
        XCTAssertEqual(SentomaruCordovaReply.status(for: .notImplemented), .error)
    }

    func testOptionsReadsTheFirstArgumentAsADictionary() {
        XCTAssertEqual(SentomaruCordovaReply.options(from: [["organization": "acme"]]) as? [String: String], ["organization": "acme"])
    }

    func testOptionsIsNilWithoutAnObjectFirstArgument() {
        XCTAssertNil(SentomaruCordovaReply.options(from: []))
        XCTAssertNil(SentomaruCordovaReply.options(from: ["not a dict"]))
    }
}
