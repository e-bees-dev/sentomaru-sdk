// D-10b: the Flutter plugin pod compiles SentomaruCore and Sentomaru into its own single module (CocoaPods has one
// module per pod), where there is no SentomaruCore module to import; under SwiftPM the two modules stay separate.
#if canImport(SentomaruCore)
@_exported import SentomaruCore
#endif
import CryptoKit
import Foundation

enum Hashing {
    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    static func base64URLNoPadding(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

enum UUIDText {
    static let zero = "00000000-0000-0000-0000-000000000000"
    static func random() -> String { UUID().uuidString.lowercased() }
}

/// Standard base64 with padding that re-encodes to itself (the server's canonical check).
enum CanonicalBase64 {
    static func decode(_ text: String) -> Data? {
        guard let data = Data(base64Encoded: text), data.base64EncodedString() == text else { return nil }
        return data
    }
}

/// Serializes the lifecycle operations of one client across `await`s (the Android client holds its monitor during
/// `send`). FIFO; never reentrant: internal steps call the `…Locked` variants.
final class AsyncSerial: @unchecked Sendable {
    private let lock = NSLock()
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func run<T>(_ body: () async throws -> T) async throws -> T {
        await acquire()
        defer { release() }
        return try await body()
    }

    private func acquire() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let resumeNow: Bool = lock.criticalSection {
                if busy {
                    waiters.append(continuation)
                    return false
                }
                busy = true
                return true
            }
            if resumeNow { continuation.resume() }
        }
    }

    private func release() {
        let next: CheckedContinuation<Void, Never>? = lock.criticalSection {
            if waiters.isEmpty {
                busy = false
                return nil
            }
            return waiters.removeFirst()
        }
        next?.resume()
    }
}

extension NSLock {
    /// `withLock` is iOS 16+; the package supports iOS 15.
    func criticalSection<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
