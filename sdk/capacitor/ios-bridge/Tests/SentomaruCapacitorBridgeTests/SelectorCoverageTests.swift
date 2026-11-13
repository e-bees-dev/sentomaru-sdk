import Foundation
import XCTest

/// Neither `../Shim/SentomaruCapacitorPlugin.swift` nor `../CocoaPodsBridge/SentomaruCapacitorPluginBridge.m` is
/// compiled by anything in `../Package.swift` (both need the Capacitor pod). This reads both as TEXT instead,
/// the one check available without it: every `contracts/sdk/hybrid-bridge-v1.json` method (minus `flutterOnly`)
/// is a `@objc func <name>(_ call: CAPPluginCall)` in the shim AND a `CAP_PLUGIN_METHOD(<name>, ...)` in the
/// manifest, and neither has an extra one.
final class SelectorCoverageTests: XCTestCase {
    private static var packageRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private static var repoRoot: URL {
        packageRoot.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private func contractMethods() throws -> Set<String> {
        let url = Self.repoRoot.appendingPathComponent("contracts/sdk/hybrid-bridge-v1.json")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let flutterOnly = Set(json["flutterOnly"] as! [String])
        let methods = json["methods"] as! [[String: Any]]
        return Set(methods.map { $0["name"] as! String }.filter { !flutterOnly.contains($0) })
    }

    private func matches(_ pattern: String, in text: String) throws -> Set<String> {
        let regex = try NSRegularExpression(pattern: pattern)
        let found = regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
        return Set(found.compactMap { match -> String? in
            guard let range = Range(match.range(at: 1), in: text) else { return nil }
            return String(text[range])
        })
    }

    func testShimImplementsExactlyTheContract() throws {
        let text = try String(contentsOf: Self.packageRoot.appendingPathComponent("Shim/SentomaruCapacitorPlugin.swift"), encoding: .utf8)
        let found = try matches(#"@objc func (\w+)\(_ call: CAPPluginCall\)"#, in: text)
        XCTAssertEqual(found, try contractMethods())
    }

    func testManifestRegistersExactlyTheContract() throws {
        let text = try String(contentsOf: Self.packageRoot.appendingPathComponent("CocoaPodsBridge/SentomaruCapacitorPluginBridge.m"), encoding: .utf8)
        let found = try matches(#"CAP_PLUGIN_METHOD\((\w+),"#, in: text)
        XCTAssertEqual(found, try contractMethods())
    }
}
