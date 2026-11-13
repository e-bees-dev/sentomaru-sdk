// swift-tools-version:6.0
// D-22 (RN iOS, lote 5): the pure-Swift logic of the native module, over sdk/ios-hybrid-core. This package proves
// `SentomaruReactNativeModule` on the Mac host (`swift test`): it imports only Foundation, never React. The React
// Native side (CocoaPodsBridge/, outside any target here: see its own comment) needs React-Core's headers (pod
// install, an Xcode/CocoaPods project), which this package does not have — a `swift test` here cannot prove it.
import PackageDescription

let package = Package(
    name: "SentomaruReactNativeBridge",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "SentomaruReactNativeBridge", targets: ["SentomaruReactNativeBridge"]),
    ],
    dependencies: [
        .package(path: "../../ios-hybrid-core"),
    ],
    targets: [
        .target(name: "SentomaruReactNativeBridge", dependencies: [.product(name: "SentomaruHybridCore", package: "ios-hybrid-core")],
                path: "Sources/SentomaruReactNativeBridge"),
        .testTarget(name: "SentomaruReactNativeBridgeTests", dependencies: ["SentomaruReactNativeBridge"],
                    path: "Tests/SentomaruReactNativeBridgeTests"),
    ],
    swiftLanguageModes: [.v6]
)
