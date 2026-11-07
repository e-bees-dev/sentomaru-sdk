import CryptoKit
import Foundation
@testable import Sentomaru
@testable import SentomaruCore
import XCTest

/// Bloco 15 (D-25, D-26): the SDK's own code, run by the laboratory against the REAL private API. Not a unit test: it is skipped unless
/// `SENTOMARU_LAB_BRIDGE_DIR` names a directory, and then it serves JSON commands from `verification/sdk_bridge/test_ios_bridge.py`
/// (`cmd-N.json` in, `rep-N.json` out, `quit` to stop). It uses the SDK's `TransactionSigner` and `OfflineSealer` with SOFTWARE keys (the
/// Secure Enclave and the device clocks need an iPhone), so it proves the bytes and the protocol, not the hardware.
final class LabBridgeTests: XCTestCase {
    /// The request key of the lab installation (imported: the server already holds its public key from the enrollment).
    private final class ImportedKeys: InstallationKeys, @unchecked Sendable {
        let key: P256.Signing.PrivateKey
        init(_ key: P256.Signing.PrivateKey) { self.key = key }
        func exists(_ alias: String) throws -> Bool { true }
        func generate(_ alias: String) throws -> Data { key.publicKey.derRepresentation }
        func publicKey(_ alias: String) throws -> Data { key.publicKey.derRepresentation }
        func sign(_ alias: String, _ bytes: Data) throws -> Data { try key.signature(for: bytes).rawRepresentation }
        func delete(_ alias: String) throws {}
        func deleteOwned(prefix: String) throws {}
    }

    private final class MemoryOffline: OfflineStateStore, @unchecked Sendable {
        var blobs: [String: Data] = [:]
        func read(_ alias: String) throws -> Data? { blobs[alias] }
        func write(_ alias: String, _ data: Data) throws { blobs[alias] = data }
        func delete(_ alias: String) throws { blobs[alias] = nil }
    }

    private final class SoftwareTxKeys: TransactionKeys, @unchecked Sendable {
        var keys: [String: P256.Signing.PrivateKey] = [:]
        func exists(_ alias: String) throws -> Bool { keys[alias] != nil }
        func generate(_ alias: String, biometricOnly: Bool) throws -> Data {
            let key = P256.Signing.PrivateKey()
            keys[alias] = key
            return key.publicKey.derRepresentation
        }
        func promote(_ staged: String, to alias: String) throws {
            guard let key = keys[staged] else { throw TransactionError.notEnrolled }
            keys[alias] = key
            keys[staged] = nil
        }
        func sign(_ alias: String, _ bytes: Data, reason: String) throws -> Data {
            guard let key = keys[alias] else { throw TransactionError.notEnrolled }
            return try key.signature(for: bytes).rawRepresentation
        }
        func delete(_ alias: String) throws { keys[alias] = nil }
    }

    /// The device wall clock, set forward by the laboratory between two seals (what a person changing the date in Settings does); the
    /// monotonic clock and the boot session stay the real ones.
    private final class JumpingWall: @unchecked Sendable {
        private let lock = NSLock()
        private var offset: TimeInterval = 0
        func set(_ value: TimeInterval) { lock.withLock { offset = value } }
        var now: Date { lock.withLock { Date().addingTimeInterval(offset) } }
    }

    private func json(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }

    func testServeTheLaboratory() async throws {
        guard let directory = ProcessInfo.processInfo.environment["SENTOMARU_LAB_BRIDGE_DIR"] else {
            throw XCTSkip("laboratory bridge: set SENTOMARU_LAB_BRIDGE_DIR (verification/sdk_bridge/test_ios_bridge.py does)")
        }
        let root = URL(fileURLWithPath: directory)
        let txKeys = SoftwareTxKeys()
        let signer = TransactionSigner(keys: txKeys, installationAlias: "lab", version: .v2)
        var sealer: OfflineSealer?
        let wall = JumpingWall()
        try Data("ready".utf8).write(to: root.appendingPathComponent("ready"))
        var step = 0
        let deadline = Date().addingTimeInterval(600)
        while Date() < deadline {
            let command = root.appendingPathComponent("cmd-\(step).json")
            guard let data = try? Data(contentsOf: command), let request = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let name = request["command"] as? String else {
                try await Task.sleep(nanoseconds: 100_000_000)
                continue
            }
            var reply: [String: Any] = [:]
            do {
                switch name {
                case "quit":
                    try json(["ok": true]).write(to: root.appendingPathComponent("rep-\(step).json"))
                    return
                case "init":
                    let pkcs8 = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request["installationKeyPkcs8"] as? String)))
                    let key = try P256.Signing.PrivateKey(derRepresentation: pkcs8)
                    wall.set(0)
                    let live = OfflineClocks.live
                    sealer = OfflineSealer(keys: ImportedKeys(key), store: MemoryOffline(),
                                           clocks: OfflineClocks(wall: { wall.now }, elapsedNanos: live.elapsedNanos, bootSession: live.bootSession))
                    let spki = try signer.stageKey(biometricOnly: false)
                    try signer.commitKey()
                    reply = ["txPublicKeySpki": spki.base64EncodedString()]
                case "txHeader":
                    let operationId = try XCTUnwrap(request["operationId"] as? String)
                    let body = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request["body"] as? String)))
                    reply = ["header": try await signer.sign(operationId: operationId, body: body)]
                case "seal":
                    let permitJson = try XCTUnwrap((request["permit"] as? String)?.data(using: .utf8))
                    let permit = try OfflinePermit.parse(permitJson)
                    let digests = try XCTUnwrap(request["digests"] as? [String]).map { try XCTUnwrap(OfflineChain.fromBase64URL($0)) }
                    let pause = (request["pauseMillis"] as? NSNumber)?.doubleValue ?? 0
                    var seals: [OfflineSeal] = []
                    // `wallJumpSeconds` from `jumpFromIndex` on: the wall clock moves forward with no monotonic time behind it.
                    let jump = (request["wallJumpSeconds"] as? NSNumber)?.doubleValue ?? 0
                    let jumpFrom = (request["jumpFromIndex"] as? NSNumber)?.intValue ?? Int.max
                    for (index, digest) in digests.enumerated() {
                        wall.set(index >= jumpFrom ? jump : 0)
                        seals.append(try XCTUnwrap(sealer).seal(alias: "lab", permit: permit, operationDigest: digest))
                        if pause > 0 { try await Task.sleep(nanoseconds: UInt64(pause * 1_000_000)) }
                    }
                    let drop = (request["dropIndex"] as? NSNumber)?.intValue
                    if let drop { seals.remove(at: drop) }
                    let body = try OfflineRequests.reconcileBody(permit: permit, seals: seals)
                    reply = ["body": body.base64EncodedString(), "seals": seals.count]
                default:
                    reply = ["error": "unknown command"]
                }
            } catch {
                reply = ["error": "\(error)"]
            }
            try json(reply).write(to: root.appendingPathComponent("rep-\(step).json"))
            step += 1
        }
        XCTFail("the laboratory did not send `quit` within 10 minutes")
    }
}
