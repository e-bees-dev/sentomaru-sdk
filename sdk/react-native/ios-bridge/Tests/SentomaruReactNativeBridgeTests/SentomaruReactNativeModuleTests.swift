import Foundation
@testable import SentomaruReactNativeBridge
import SentomaruHybridCore
import XCTest

/// `SentomaruReactNativeModule` is real, compiled Swift (no React import, see its own doc comment): these tests
/// exercise it exactly as the `.m` extern declarations would call it, with resolver/rejecter blocks matching
/// `RCTPromiseResolveBlock`/`RCTPromiseRejectBlock`'s own shape.
final class SentomaruReactNativeModuleTests: XCTestCase {
    private enum Settled: Equatable {
        case resolved(String)
        case rejected(String, String?)
    }

    private func call(_ body: (SentomaruReactNativeModule, @escaping SentomaruReactNativeModule.Resolve,
                                @escaping SentomaruReactNativeModule.Reject) -> Void) async -> Settled {
        let module = SentomaruReactNativeModule()
        return await withCheckedContinuation { continuation in
            body(module,
                 { value in continuation.resume(returning: .resolved(String(describing: value))) },
                 { code, message, _ in continuation.resume(returning: .rejected(code ?? "", message)) })
        }
    }

    func testRequiresMainQueueSetupIsFalse() {
        XCTAssertFalse(SentomaruReactNativeModule.requiresMainQueueSetup())
    }

    func testStateBeforeInitializeRejectsNotInitialized() async {
        let result = await call { module, resolve, reject in module.state(resolver: resolve, rejecter: reject) }
        XCTAssertEqual(result, .rejected("NotInitialized", "Sentomaru native client not initialized"))
    }

    func testSessionIdBeforeInitializeResolvesNil() async {
        let result = await call { module, resolve, reject in module.sessionId(resolver: resolve, rejecter: reject) }
        XCTAssertEqual(result, .resolved(String(describing: Optional<Any>.none)))
    }

    func testSealedLoadIsUnimplemented() async {
        let result = await call { module, resolve, reject in module.sealedLoad(["key": "x"], resolver: resolve, rejecter: reject) }
        XCTAssertEqual(result, .rejected(SentomaruHybridBridge.unimplemented, nil))
    }

    func testInitializeRefusesAMissingOrganization() async {
        let result = await call { module, resolve, reject in module.initialize([:], resolver: resolve, rejecter: reject) }
        XCTAssertEqual(result, .rejected("ConfigurationError", "Invalid or missing Sentomaru configuration"))
    }
}
