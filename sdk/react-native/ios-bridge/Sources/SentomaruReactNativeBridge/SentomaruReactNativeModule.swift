import Foundation
import SentomaruHybridCore

/// D-22 (RN iOS): the method-channel-bridge-v1 dispatch as React Native's own native-module shape, one `@objc`
/// method per contract entry, every one taking a single options dictionary (as Capacitor's `CAPPluginCall.options`
/// already does, and Cordova's own `command.arguments[0]`): the three native modules stay structurally identical,
/// all three forwarding straight into `SentomaruHybridBridge`.
///
/// This file never imports React: a Swift `@objc` method's block parameters bridge to Objective-C blocks by shape,
/// not by the Swift-side type name, so `Resolve`/`Reject` below are ABI-compatible with `RCTPromiseResolveBlock`/
/// `RCTPromiseRejectBlock` without the import. `@objc(name:resolver:rejecter:)`, `NSObject` and `NSDictionary` are
/// all Foundation/the Objective-C runtime, present without React too. What this class cannot do alone is register
/// itself as a React Native module (`RCT_EXPORT_MODULE`) or export these selectors to JS (`RCT_EXTERN_METHOD`):
/// both are Objective-C macros that need React-Core's headers. `CocoaPodsBridge/SentomaruReactNativeModuleBridge.m`
/// (outside every target in `Package.swift`, so a `swift build`/`swift test` here never touches it) is that
/// declaration, written but NOT compiled by this package — only a real Xcode/CocoaPods project with the `React-Core`
/// pod can. `SelectorCoverageTests` instead reads that file as text and checks, selector by selector, that it
/// exports every method this class implements and no other.
@objc(SentomaruReactNativeModule)
public final class SentomaruReactNativeModule: NSObject {
    /// `RCTPromiseResolveBlock`'s shape (`typedef void (^RCTPromiseResolveBlock)(id result)`). `@Sendable`: React
    /// already calls these blocks across threads (the bridge's own JS/native queues), same as `BridgeReply` here.
    public typealias Resolve = @Sendable @convention(block) (Any?) -> Void
    /// `RCTPromiseRejectBlock`'s shape (`typedef void (^RCTPromiseRejectBlock)(NSString *code, NSString *message, NSError *error)`).
    public typealias Reject = @Sendable @convention(block) (String?, String?, Error?) -> Void

    private let bridge: SentomaruHybridBridge

    public init(bridge: SentomaruHybridBridge = SentomaruHybridBridge()) {
        self.bridge = bridge
        super.init()
    }

    @objc public static func requiresMainQueueSetup() -> Bool { false }

    private func dispatch(_ method: String, _ options: NSDictionary?, _ resolve: @escaping Resolve, _ reject: @escaping Reject) {
        bridge.handle(method, options as? [String: Any], resolve: { resolve($0) }, reject: { code, message in reject(code, message, nil) })
    }

    @objc(initialize:resolver:rejecter:)
    public func initialize(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) {
        dispatch("initialize", options, resolver, rejecter)
    }
    @objc(state:rejecter:)
    public func state(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("state", nil, resolver, rejecter) }
    @objc(reenrollmentReason:rejecter:)
    public func reenrollmentReason(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("reenrollmentReason", nil, resolver, rejecter) }
    @objc(enroll:resolver:rejecter:)
    public func enroll(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("enroll", options, resolver, rejecter) }
    @objc(rotate:resolver:rejecter:)
    public func rotate(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("rotate", options, resolver, rejecter) }
    @objc(sign:resolver:rejecter:)
    public func sign(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("sign", options, resolver, rejecter) }
    @objc(reset:rejecter:)
    public func reset(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("reset", nil, resolver, rejecter) }
    @objc(collectSignals:rejecter:)
    public func collectSignals(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("collectSignals", nil, resolver, rejecter) }
    @objc(collectSignalsSnapshot:resolver:rejecter:)
    public func collectSignalsSnapshot(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) {
        dispatch("collectSignalsSnapshot", options, resolver, rejecter)
    }
    @objc(sessionId:rejecter:)
    public func sessionId(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("sessionId", nil, resolver, rejecter) }
    @objc(renewSession:rejecter:)
    public func renewSession(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("renewSession", nil, resolver, rejecter) }
    @objc(reattestationDue:rejecter:)
    public func reattestationDue(resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("reattestationDue", nil, resolver, rejecter) }
    @objc(reattestIfDue:resolver:rejecter:)
    public func reattestIfDue(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("reattestIfDue", options, resolver, rejecter) }
    @objc(reattest:resolver:rejecter:)
    public func reattest(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("reattest", options, resolver, rejecter) }
    @objc(sealedConfigure:resolver:rejecter:)
    public func sealedConfigure(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("sealedConfigure", options, resolver, rejecter) }
    @objc(sealedLoad:resolver:rejecter:)
    public func sealedLoad(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("sealedLoad", options, resolver, rejecter) }
    @objc(sealedString:resolver:rejecter:)
    public func sealedString(_ options: NSDictionary?, resolver: @escaping Resolve, rejecter: @escaping Reject) { dispatch("sealedString", options, resolver, rejecter) }
}
