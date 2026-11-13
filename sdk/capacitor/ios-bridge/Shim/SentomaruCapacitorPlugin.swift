// D-22 (Capacitor iOS): the real CAPPlugin subclass. Needs the Capacitor pod (`import Capacitor`, `CAPPlugin`,
// `CAPPluginCall`): this file is in no target `../Package.swift` declares, so a `swift build`/`swift test` there
// never compiles it; ../Tests/SentomaruCapacitorBridgeTests/SelectorCoverageTests instead reads it as TEXT against
// contracts/sdk/hybrid-bridge-v1.json. Every method here is this one line: read `call.options`, call the bridge,
// shape the reply with SentomaruCapacitorReply (`../Sources/SentomaruCapacitorBridge`), done.
import Capacitor
import SentomaruHybridCore
import SentomaruCapacitorBridge

@objc(SentomaruCapacitorPlugin)
public class SentomaruCapacitorPlugin: CAPPlugin {
    private let bridge = SentomaruHybridBridge()

    private func dispatch(_ method: String, _ call: CAPPluginCall) {
        bridge.handle(method, call.options, resolve: { call.resolve(SentomaruCapacitorReply.data($0)) },
                       reject: { code, message in call.reject(message ?? code, code) })
    }

    @objc func initialize(_ call: CAPPluginCall) { dispatch("initialize", call) }
    @objc func state(_ call: CAPPluginCall) { dispatch("state", call) }
    @objc func reenrollmentReason(_ call: CAPPluginCall) { dispatch("reenrollmentReason", call) }
    @objc func enroll(_ call: CAPPluginCall) { dispatch("enroll", call) }
    @objc func rotate(_ call: CAPPluginCall) { dispatch("rotate", call) }
    @objc func sign(_ call: CAPPluginCall) { dispatch("sign", call) }
    @objc func reset(_ call: CAPPluginCall) { dispatch("reset", call) }
    @objc func collectSignals(_ call: CAPPluginCall) { dispatch("collectSignals", call) }
    @objc func collectSignalsSnapshot(_ call: CAPPluginCall) { dispatch("collectSignalsSnapshot", call) }
    @objc func sessionId(_ call: CAPPluginCall) { dispatch("sessionId", call) }
    @objc func renewSession(_ call: CAPPluginCall) { dispatch("renewSession", call) }
    @objc func reattestationDue(_ call: CAPPluginCall) { dispatch("reattestationDue", call) }
    @objc func reattestIfDue(_ call: CAPPluginCall) { dispatch("reattestIfDue", call) }
    @objc func reattest(_ call: CAPPluginCall) { dispatch("reattest", call) }
    @objc func sealedConfigure(_ call: CAPPluginCall) { dispatch("sealedConfigure", call) }
    @objc func sealedLoad(_ call: CAPPluginCall) { dispatch("sealedLoad", call) }
    @objc func sealedString(_ call: CAPPluginCall) { dispatch("sealedString", call) }
}
