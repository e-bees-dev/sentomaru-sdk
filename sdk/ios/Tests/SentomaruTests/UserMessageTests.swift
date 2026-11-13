import Foundation
@testable import Sentomaru
import SentomaruCore
import XCTest

/// `sdk-user-message-v1`: the default text, the locale resolution, the host override and the code mapping, against the shared vector
/// `contracts/sdk/user-message-vectors-v1.json` (read from the repository, never copied).
final class UserMessageTests: XCTestCase {
    private func vector() throws -> [String: Any] {
        let url = AppAttestVectorTests.repositoryRoot.appendingPathComponent("contracts/sdk/user-message-vectors-v1.json")
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    func testDefaultTextsAreTheSharedOnesAndHaveTheStableKey() throws {
        let v = try vector()
        XCTAssertEqual(v["key"] as? String, SentomaruUserMessage.key)
        XCTAssertEqual(v["texts"] as? [String: String], SentomaruUserMessage.defaultTexts)
        XCTAssertEqual(v["fallbackLocale"] as? String, SentomaruUserMessage.fallbackLocale)
    }

    func testEverySituationShowsTheTextOfItsLocale() throws {
        let v = try vector()
        XCTAssertEqual((v["situations"] as? [String])?.sorted(), SentomaruUserMessage.Situation.allCases.map(\.rawValue).sorted())
        let texts = try XCTUnwrap(v["texts"] as? [String: String])
        for s in SentomaruUserMessage.Situation.allCases {
            for (locale, text) in texts { XCTAssertEqual(SentomaruUserMessage.resolve(s, locale: locale), text) }
        }
    }

    func testLocaleResolution() throws {
        for c in try XCTUnwrap(try vector()["localeResolution"] as? [[String: Any]]) {
            let tag = c["tag"] as? String
            XCTAssertEqual(SentomaruUserMessage.resolveLocale(tag), c["locale"] as? String, "tag \(tag ?? "nil")")
        }
    }

    func testHostOverride() throws {
        for c in try XCTUnwrap(try vector()["overrides"] as? [[String: Any]]) {
            let got = SentomaruUserMessage.resolve(.challenge, locale: c["locale"] as? String, overrides: c["overrides"] as? [String: String])
            XCTAssertEqual(got, c["expected"] as? String, c["name"] as? String ?? "")
        }
    }

    func testCodeMapping() throws {
        let map = try XCTUnwrap((try vector()["mobileCodes"] as? [String: Any])?["map"] as? [String: Any])
        for (code, expected) in map {
            XCTAssertEqual(SentomaruUserMessage.situation(forCode: code)?.rawValue, expected as? String, code)
        }
        XCTAssertNil(SentomaruUserMessage.situation(forCode: "NeverSeenBefore"))
    }

    func testSentomaruErrorAccessorKeepsTheCodeAndOnlyAddsTheMessage() throws {
        let en = try XCTUnwrap(SentomaruUserMessage.defaultTexts["en"])
        XCTAssertEqual(SentomaruError.networkUnavailable.userMessage(locale: "en"), en)
        XCTAssertEqual(SentomaruError.serverRejected(.SUSPENDED).userMessage(locale: "en-US"), en)
        XCTAssertEqual(SentomaruError.notEnrolled.userMessage(locale: "es", overrides: ["es": "Texto del anfitrión."]), "Texto del anfitrión.")
        XCTAssertNil(SentomaruError.cancelled.userMessage(locale: "en"))
        XCTAssertNil(SentomaruError.invalidRequest(.PARAMS).userMessage(locale: "en"))
        XCTAssertEqual(SentomaruError.serverRejected(.SUSPENDED).code, "ServerRejected:SUSPENDED")
    }

    func testTheTextNeverNamesAReasonOrADetection() throws {
        let forbidden = try XCTUnwrap(try vector()["forbiddenInText"] as? [String])
        for text in SentomaruUserMessage.defaultTexts.values {
            for word in forbidden { XCTAssertFalse(text.lowercased().contains(word.lowercased()), "'\(word)' in: \(text)") }
        }
    }
}
