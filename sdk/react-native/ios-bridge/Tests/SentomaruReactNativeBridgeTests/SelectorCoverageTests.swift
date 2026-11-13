import Foundation
import XCTest

/// `CocoaPodsBridge/SentomaruReactNativeModuleBridge.m` needs React-Core to compile (see its own comment) and is in
/// no target `../Package.swift` declares, so nothing here builds or runs it. This test reads it as TEXT instead: the
/// one check available without that pod, that every `contracts/sdk/hybrid-bridge-v1.json` method (minus
/// `flutterOnly`) has an `RCT_EXTERN_METHOD` of the same name here, and no other method is exported.
final class SelectorCoverageTests: XCTestCase {
    private static var packageRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // this file
            .deletingLastPathComponent() // SentomaruReactNativeBridgeTests
            .deletingLastPathComponent() // Tests
    }

    private static var repoRoot: URL {
        packageRoot
            .deletingLastPathComponent() // ios
            .deletingLastPathComponent() // react-native
            .deletingLastPathComponent() // sdk
    }

    private func contractMethods() throws -> [String] {
        let url = Self.repoRoot.appendingPathComponent("contracts/sdk/hybrid-bridge-v1.json")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let flutterOnly = Set(json["flutterOnly"] as! [String])
        let methods = json["methods"] as! [[String: Any]]
        return methods.map { $0["name"] as! String }.filter { !flutterOnly.contains($0) }
    }

    private func externedSelectors() throws -> Set<String> {
        let url = Self.packageRoot.appendingPathComponent("CocoaPodsBridge/SentomaruReactNativeModuleBridge.m")
        let text = try String(contentsOf: url, encoding: .utf8)
        let pattern = try NSRegularExpression(pattern: #"RCT_EXTERN_METHOD\((\w+):"#)
        let matches = pattern.matches(in: text, range: NSRange(text.startIndex..., in: text))
        return Set(matches.compactMap { match -> String? in
            guard let range = Range(match.range(at: 1), in: text) else { return nil }
            return String(text[range])
        })
    }

    func testEveryContractMethodIsExtern() throws {
        let contract = try contractMethods()
        let externed = try externedSelectors()
        XCTAssertEqual(externed, Set(contract), "CocoaPodsBridge/SentomaruReactNativeModuleBridge.m vs hybrid-bridge-v1.json")
    }

    func testTheModuleItselfImplementsEveryExternedSelector() throws {
        let externed = try externedSelectors()
        let swiftSource = try String(
            contentsOf: Self.packageRoot.appendingPathComponent("Sources/SentomaruReactNativeBridge/SentomaruReactNativeModule.swift"),
            encoding: .utf8)
        for selector in externed {
            XCTAssertTrue(swiftSource.contains("\"\(selector)\""), "no bridge.handle(\"\(selector)\", ...) in SentomaruReactNativeModule.swift")
        }
    }
}
