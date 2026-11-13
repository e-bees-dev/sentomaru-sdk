// D-22 (Capacitor iOS): registers ../Shim/SentomaruCapacitorPlugin.swift's methods for Capacitor's JS bridge.
// CAP_PLUGIN/CAP_PLUGIN_METHOD are Capacitor-Core macros (<Capacitor/Capacitor.h>): this file needs that pod and an
// Xcode or CocoaPods project to compile, which this repository's `swift build`/`swift test` does not have, so it
// is NOT written against or verified by either here. It is not a member of any target in ../Package.swift.
// ../Tests/SentomaruCapacitorBridgeTests/SelectorCoverageTests reads this file as TEXT and checks every
// CAP_PLUGIN_METHOD here against contracts/sdk/hybrid-bridge-v1.json.
#import <Capacitor/Capacitor.h>

CAP_PLUGIN(SentomaruCapacitorPlugin, "Sentomaru",
    CAP_PLUGIN_METHOD(initialize, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(state, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(reenrollmentReason, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(enroll, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(rotate, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(sign, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(reset, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(collectSignals, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(collectSignalsSnapshot, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(sessionId, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(renewSession, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(reattestationDue, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(reattestIfDue, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(reattest, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(sealedConfigure, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(sealedLoad, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(sealedString, CAPPluginReturnPromise);
)
