import Foundation
@testable import SentomaruHybridCore
import XCTest

private enum Settled: Equatable {
    case resolved(String) // described, since `Any?` is not Equatable
    case rejected(code: String, message: String?)
}

/// The resolve/reject mapping every lote-5 native module (RN, Capacitor, Cordova) reuses instead of its own.
final class ResolveRejectTests: XCTestCase {
    private func call(_ method: String, _ options: [String: Any]? = nil) async -> Settled {
        let bridge = SentomaruHybridBridge()
        return await withCheckedContinuation { continuation in
            bridge.handle(method, options, resolve: { value in
                continuation.resume(returning: .resolved(String(describing: value)))
            }, reject: { code, message in
                continuation.resume(returning: .rejected(code: code, message: message))
            })
        }
    }

    func testSuccessResolvesWithTheReplyValue() async {
        let result = await call("sessionId") // before initialize: success(nil)
        XCTAssertEqual(result, .resolved(String(describing: Optional<Any>.none)))
    }

    func testFailureRejectsWithTheStableCodeAndMessage() async {
        let result = await call("state") // before initialize: NotInitialized
        XCTAssertEqual(result, .rejected(code: "NotInitialized", message: "Sentomaru native client not initialized"))
    }

    func testNotImplementedRejectsAsUnimplementedWithNoMessage() async {
        let result = await call("sealedLoad")
        XCTAssertEqual(result, .rejected(code: SentomaruHybridBridge.unimplemented, message: nil))
    }
}
