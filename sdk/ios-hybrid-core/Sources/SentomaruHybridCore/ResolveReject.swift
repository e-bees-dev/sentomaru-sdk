import Foundation

/// The lote-5 native modules (RN, Capacitor, Cordova) all settle a call with a resolve/reject pair instead of a
/// typed `BridgeReply`: RN's `RCTPromiseResolveBlock`/`RCTPromiseRejectBlock`, Capacitor's `CAPPluginCall.resolve`/
/// `.reject`, Cordova's `CDVPluginResult` success/error sent through its `CDVCommandDelegate`. This is the one place
/// that turns a `BridgeReply` into that shape, so the three native modules do not each invent their own mapping.
/// `notImplemented` (`scaffoldInfo`, `reattestationDue`/`reattestIfDue`/`reattest`, `sealedConfigure`/`sealedLoad`/
/// `sealedString`) becomes `Unimplemented`: the contract has no shared code for it, each framework needs its own.
public extension SentomaruHybridBridge {
    static let unimplemented = "Unimplemented"

    /// [resolve] gets `reply.value` (nil for a `void` reply); [reject] gets the stable code (`reply.code`, or
    /// `Unimplemented`) and the message (nil for `notImplemented`, as no SDK/bridge message exists for it).
    func handle(_ method: String, _ options: [String: Any]?, resolve: @escaping @Sendable (Any?) -> Void,
                reject: @escaping @Sendable (_ code: String, _ message: String?) -> Void) {
        handle(method, options) { reply in
            switch reply.kind {
            case .success: resolve(reply.value)
            case .failure: reject(reply.code ?? SentomaruHybridBridge.channelError, reply.message)
            case .notImplemented: reject(Self.unimplemented, nil)
            }
        }
    }
}
