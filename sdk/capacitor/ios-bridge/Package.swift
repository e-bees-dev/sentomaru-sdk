// swift-tools-version:6.0
// D-22 (Capacitor iOS, lote 5): the Capacitor-specific reply shaping, over sdk/ios-hybrid-core, provable on the Mac
// host (`swift test`): it imports only Foundation, never Capacitor. `Shim/` (the real CAPPlugin subclass) and
// `CocoaPodsBridge/` (its CAP_PLUGIN/CAP_PLUGIN_METHOD manifest) need the Capacitor pod's headers and are in no
// target below, so a `swift build`/`swift test` here never touches either — see their own comments.
import PackageDescription

let package = Package(
    name: "SentomaruCapacitorBridge",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "SentomaruCapacitorBridge", targets: ["SentomaruCapacitorBridge"]),
    ],
    dependencies: [
        .package(path: "../../ios-hybrid-core"),
    ],
    targets: [
        .target(name: "SentomaruCapacitorBridge", dependencies: [.product(name: "SentomaruHybridCore", package: "ios-hybrid-core")],
                path: "Sources/SentomaruCapacitorBridge"),
        .testTarget(name: "SentomaruCapacitorBridgeTests", dependencies: ["SentomaruCapacitorBridge"],
                    path: "Tests/SentomaruCapacitorBridgeTests"),
    ],
    swiftLanguageModes: [.v6]
)
