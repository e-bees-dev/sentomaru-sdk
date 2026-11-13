// swift-tools-version:6.0
// D-22 (iOS layers of the RN, Capacitor and Cordova hybrid bridges): the Swift twin of sdk/hybrid-core (Android),
// the method-channel dispatcher shared by the three layers over sdk/ios (D-10a). No logic of its own beyond that
// dispatch (contracts/sdk/hybrid-bridge-v1.json): a native module file per platform only forwards its framework's
// call into `SentomaruHybridBridge.handle`. macOS is a platform only so `swift test` runs on the Mac host.
import PackageDescription

let package = Package(
    name: "SentomaruHybridCore",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "SentomaruHybridCore", targets: ["SentomaruHybridCore"]),
    ],
    dependencies: [
        .package(path: "../ios"),
    ],
    targets: [
        .target(name: "SentomaruHybridCore", dependencies: [.product(name: "Sentomaru", package: "ios")],
                path: "Sources/SentomaruHybridCore"),
        .testTarget(name: "SentomaruHybridCoreTests", dependencies: ["SentomaruHybridCore"],
                    path: "Tests/SentomaruHybridCoreTests"),
    ],
    swiftLanguageModes: [.v6]
)
