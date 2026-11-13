import Foundation

/// D-22 (Capacitor iOS): `CAPPluginCall.resolve(_:)` only takes a dictionary (`PluginCallResultData`), unlike RN's
/// `RCTPromiseResolveBlock` or Cordova's `CDVPluginResult`, both of which take any JSON-codec value directly. A
/// `BridgeReply.success` whose value is already a dictionary (`enroll`, `rotate`, `sign`, `collectSignalsSnapshot`)
/// passes straight through; everything else (`state`'s string, `collectSignals`'s list, `renewSession`'s string,
/// `reattestationDue`'s bool, the `void` replies' nil) is wrapped under `"value"` — the shim (`Shim/`, not compiled
/// here) calls `call.resolve(SentomaruCapacitorReply.data(reply.value))` and nothing else.
public enum SentomaruCapacitorReply {
    public static func data(_ value: Any?) -> [String: Any] {
        guard let value else { return ["value": NSNull()] }
        if let dict = value as? [String: Any] { return dict }
        return ["value": value]
    }
}
