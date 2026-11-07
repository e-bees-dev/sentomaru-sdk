// swift-tools-version:6.0
// D-10a: Sentomaru SDK for iOS (SwiftPM). No external dependency: Foundation, CryptoKit, Security, DeviceCheck.
// macOS is a platform only so `swift test` runs on the Mac host (no simulator, no iPhone); the product targets iOS 15+.
import PackageDescription

let package = Package(
    name: "Sentomaru",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "Sentomaru", targets: ["Sentomaru"]),
    ],
    targets: [
        // RFC 9421 / RFC 9530 profile core, the Swift twin of sdk/android/core (same vectors, same error codes).
        .target(name: "SentomaruCore", path: "Sources/SentomaruCore"),
        // Installation lifecycle: Secure Enclave request key, App Attest, Keychain store, renewal, URLSession transport.
        .target(name: "Sentomaru", dependencies: ["SentomaruCore"], path: "Sources/Sentomaru"),
        .testTarget(name: "SentomaruCoreTests", dependencies: ["SentomaruCore"], path: "Tests/SentomaruCoreTests"),
        .testTarget(
            name: "SentomaruTests",
            dependencies: ["Sentomaru"],
            path: "Tests/SentomaruTests",
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
