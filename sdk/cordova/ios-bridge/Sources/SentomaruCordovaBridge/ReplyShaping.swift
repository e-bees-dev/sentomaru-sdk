import Foundation
import SentomaruHybridCore

/// D-22 (Cordova iOS): the two Cordova-specific decisions the shim (`Shim/`, not compiled here) needs, kept testable
/// here instead of inline in a file that needs the Cordova pod to even parse.
public enum SentomaruCordovaReply {
    /// `CDVCommandStatus` only has OK and ERROR for this bridge (no `CDVCommandStatus_NO_RESULT`: every call answers
    /// exactly once, success or failure, same as every other hybrid layer).
    public enum Status: Equatable { case ok, error }

    public static func status(for kind: BridgeReply.Kind) -> Status {
        kind == .success ? .ok : .error
    }

    /// `command.arguments[0]` by convention (the one options object every JS call sends, same as RN's single
    /// `NSDictionary` parameter and Capacitor's `call.options`); anything else (no arguments, or a non-object first
    /// argument) is `nil`, which `SentomaruHybridBridge.handle` already treats as "no options".
    public static func options(from arguments: [Any]) -> [String: Any]? {
        arguments.first as? [String: Any]
    }
}
