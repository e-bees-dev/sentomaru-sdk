import Foundation
import XCTest

/// `../Shim/SentomaruCordovaPlugin.swift` needs the Cordova pod to compile and is in no target in `../Package.swift`
/// (see its own comment), so this reads it as TEXT instead: every `contracts/sdk/hybrid-bridge-v1.json` method
/// (minus `flutterOnly`) is a `@objc(name:) func name(_ command: CDVInvokedUrlCommand)` here, and no other is.
final class SelectorCoverageTests: XCTestCase {
    private static var packageRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private static var repoRoot: URL {
        packageRoot.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    func testShimImplementsExactlyTheContract() throws {
        let contractUrl = Self.repoRoot.appendingPathComponent("contracts/sdk/hybrid-bridge-v1.json")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: contractUrl)) as! [String: Any]
        let flutterOnly = Set(json["flutterOnly"] as! [String])
        let methods = json["methods"] as! [[String: Any]]
        let contract = Set(methods.map { $0["name"] as! String }.filter { !flutterOnly.contains($0) })

        let text = try String(contentsOf: Self.packageRoot.appendingPathComponent("Shim/SentomaruCordovaPlugin.swift"), encoding: .utf8)
        let pattern = try NSRegularExpression(pattern: #"@objc\((\w+):\) func \1\(_ command: CDVInvokedUrlCommand\)"#)
        let found = pattern.matches(in: text, range: NSRange(text.startIndex..., in: text))
        let selectors = Set(found.compactMap { match -> String? in
            guard let range = Range(match.range(at: 1), in: text) else { return nil }
            return String(text[range])
        })
        XCTAssertEqual(selectors, contract)
    }
}
