@preconcurrency import Flutter
import Foundation

/// D-10b: Flutter glue of the iOS side. The channel `sentomaru_flutter` (same name as Android) goes to
/// [SentomaruFlutterBridge]; this class only converts Flutter types and answers on the main thread. No EventChannel:
/// Dart never listens to signal events on iOS (`signalEventsSupported` is false there).
///
/// Non-interactive: no biometric prompt, no UI, no view controller (the Secure Enclave key is created without
/// user-presence flags, as the Android key has no user authentication).
public final class SentomaruFlutterPlugin: NSObject, FlutterPlugin {
    static let channelName = "sentomaru_flutter"

    let bridge: SentomaruFlutterBridge

    init(bridge: SentomaruFlutterBridge = SentomaruFlutterBridge()) {
        self.bridge = bridge
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: channelName, binaryMessenger: registrar.messenger())
        registrar.addMethodCallDelegate(SentomaruFlutterPlugin(), channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let answer = ResultBox(result)
        bridge.handle(call.method, Self.arguments(call.arguments)) { reply in
            DispatchQueue.main.async { answer.send(reply) }
        }
    }

    public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
        bridge.detach()
    }

    /// The call's map with `FlutterStandardTypedData` (the `sign` body) as `Data`, so the bridge needs no Flutter type.
    static func arguments(_ raw: Any?) -> [String: Any]? {
        guard let map = raw as? [String: Any] else { return nil }
        return map.mapValues { value in (value as? FlutterStandardTypedData)?.data ?? value }
    }

    /// `BridgeReply` as the `FlutterResult` value (`FlutterError` with the Android code and message).
    static func resultValue(_ reply: BridgeReply) -> Any? {
        switch reply.kind {
        case .success: return reply.value
        case .failure: return FlutterError(code: reply.code ?? SentomaruFlutterBridge.channelError,
                                           message: reply.message ?? reply.code, details: reply.details)
        case .notImplemented: return FlutterMethodNotImplemented
        }
    }
}

/// The `FlutterResult` block carried to the main queue (it is called there, once).
private final class ResultBox: @unchecked Sendable {
    private let result: FlutterResult

    init(_ result: @escaping FlutterResult) { self.result = result }

    func send(_ reply: BridgeReply) { result(SentomaruFlutterPlugin.resultValue(reply)) }
}
