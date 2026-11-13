// D-22 (Cordova iOS): the real CDVPlugin subclass. Needs the Cordova pod (`import Cordova`, `CDVPlugin`,
// `CDVInvokedUrlCommand`, `CDVPluginResult`): this file is in no target `../Package.swift` declares, so a
// `swift build`/`swift test` there never compiles it; ../Tests/SentomaruCordovaBridgeTests/SelectorCoverageTests
// instead reads it as TEXT against contracts/sdk/hybrid-bridge-v1.json. No per-method registration file: Cordova's
// `plugin.xml` registers this class once, and the JS action name is the native selector directly.
import Cordova
import SentomaruHybridCore
import SentomaruCordovaBridge

@objc(SentomaruCordovaPlugin)
public class SentomaruCordovaPlugin: CDVPlugin {
    private let bridge = SentomaruHybridBridge()

    private func dispatch(_ method: String, _ command: CDVInvokedUrlCommand) {
        let options = SentomaruCordovaReply.options(from: command.arguments)
        bridge.handle(method, options) { reply in
            let result: CDVPluginResult
            switch SentomaruCordovaReply.status(for: reply.kind) {
            case .ok: result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: reply.value)
            case .error: result = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: reply.code ?? "ChannelError")
            }
            self.commandDelegate.send(result, callbackId: command.callbackId)
        }
    }

    @objc(initialize:) func initialize(_ command: CDVInvokedUrlCommand) { dispatch("initialize", command) }
    @objc(state:) func state(_ command: CDVInvokedUrlCommand) { dispatch("state", command) }
    @objc(reenrollmentReason:) func reenrollmentReason(_ command: CDVInvokedUrlCommand) { dispatch("reenrollmentReason", command) }
    @objc(enroll:) func enroll(_ command: CDVInvokedUrlCommand) { dispatch("enroll", command) }
    @objc(rotate:) func rotate(_ command: CDVInvokedUrlCommand) { dispatch("rotate", command) }
    @objc(sign:) func sign(_ command: CDVInvokedUrlCommand) { dispatch("sign", command) }
    @objc(reset:) func reset(_ command: CDVInvokedUrlCommand) { dispatch("reset", command) }
    @objc(collectSignals:) func collectSignals(_ command: CDVInvokedUrlCommand) { dispatch("collectSignals", command) }
    @objc(collectSignalsSnapshot:) func collectSignalsSnapshot(_ command: CDVInvokedUrlCommand) { dispatch("collectSignalsSnapshot", command) }
    @objc(sessionId:) func sessionId(_ command: CDVInvokedUrlCommand) { dispatch("sessionId", command) }
    @objc(renewSession:) func renewSession(_ command: CDVInvokedUrlCommand) { dispatch("renewSession", command) }
    @objc(reattestationDue:) func reattestationDue(_ command: CDVInvokedUrlCommand) { dispatch("reattestationDue", command) }
    @objc(reattestIfDue:) func reattestIfDue(_ command: CDVInvokedUrlCommand) { dispatch("reattestIfDue", command) }
    @objc(reattest:) func reattest(_ command: CDVInvokedUrlCommand) { dispatch("reattest", command) }
    @objc(sealedConfigure:) func sealedConfigure(_ command: CDVInvokedUrlCommand) { dispatch("sealedConfigure", command) }
    @objc(sealedLoad:) func sealedLoad(_ command: CDVInvokedUrlCommand) { dispatch("sealedLoad", command) }
    @objc(sealedString:) func sealedString(_ command: CDVInvokedUrlCommand) { dispatch("sealedString", command) }
}
