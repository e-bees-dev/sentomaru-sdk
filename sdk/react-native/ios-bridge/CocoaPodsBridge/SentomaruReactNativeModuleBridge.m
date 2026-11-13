// D-22 (RN iOS): exports SentomaruReactNativeModule (Sources/SentomaruReactNativeBridge) to JS. RCT_EXPORT_MODULE and
// RCT_EXTERN_METHOD are React-Core macros (<React/RCTBridgeModule.h>): this file needs that pod and an Xcode or
// CocoaPods project to compile, which this repository's `swift build`/`swift test` does not have, so it is NOT
// written against or verified by either here. It is not a member of any target in ../Package.swift: nothing here
// builds that file. SelectorCoverageTests reads this file as TEXT and checks every RCT_EXTERN_METHOD selector here
// against contracts/sdk/hybrid-bridge-v1.json, so a method added to one and not the other fails that test.
//
// To use: add this file (and the matching real React-Core import) to the RN app's Podfile/Xcode project alongside
// SentomaruReactNativeBridge's compiled Swift sources.
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(SentomaruReactNativeModule, NSObject)

RCT_EXTERN_METHOD(initialize:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(state:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(reenrollmentReason:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(enroll:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(rotate:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sign:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(reset:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(collectSignals:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(collectSignalsSnapshot:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sessionId:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(renewSession:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(reattestationDue:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(reattestIfDue:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(reattest:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sealedConfigure:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sealedLoad:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sealedString:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

@end
