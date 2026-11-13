// swift-tools-version:6.0
// D-22 (Cordova iOS, lote 5): the Cordova-specific reply shaping, over sdk/ios-hybrid-core, provable on the Mac
// host (`swift test`): it imports only Foundation, never Cordova. `Shim/` (the real CDVPlugin subclass) needs the
// Cordova pod's headers and is in no target below, so a `swift build`/`swift test` here never touches it — see its
// own comment. Unlike RN/Capacitor, Cordova has no per-method ObjC extern macro (`plugin.xml` registers the plugin
// class once; the JS action name is the native selector), so there is no second manifest file here.
import PackageDescription

let package = Package(
    name: "SentomaruCordovaBridge",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "SentomaruCordovaBridge", targets: ["SentomaruCordovaBridge"]),
    ],
    dependencies: [
        .package(path: "../../ios-hybrid-core"),
    ],
    targets: [
        .target(name: "SentomaruCordovaBridge", dependencies: [.product(name: "SentomaruHybridCore", package: "ios-hybrid-core")],
                path: "Sources/SentomaruCordovaBridge"),
        .testTarget(name: "SentomaruCordovaBridgeTests", dependencies: ["SentomaruCordovaBridge"],
                    path: "Tests/SentomaruCordovaBridgeTests"),
    ],
    swiftLanguageModes: [.v6]
)
