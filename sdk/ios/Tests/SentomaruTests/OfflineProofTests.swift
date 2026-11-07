import CryptoKit
import Foundation
@testable import Sentomaru
@testable import SentomaruCore
import XCTest

/// D-26 (iOS): the seal bytes against the golden vectors the server also checks, the seal of the client with software keys and
/// a fixed clock, and the reconciliation body. The device clocks (`kern.bootsessionuuid`, `CLOCK_MONOTONIC`) are NOT exercised
/// here: a real reboot and a real clock change need a device.
final class OfflineProofTests: XCTestCase {
    /// The vectors are read from the repository (the same file the server checks), never copied: a copy could drift.
    private func vectors() throws -> [String: Any] {
        let repository = AppAttestVectorTests.repositoryRoot.appendingPathComponent("contracts/sdk/offline-proof-chain-v1-vectors.json")
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: try Data(contentsOf: repository)) as? [String: Any])
    }

    private func b64(_ text: Any?) throws -> Data { try XCTUnwrap(OfflineChain.fromBase64URL(try XCTUnwrap(text as? String))) }

    func testTheSeedHashAndEveryRecordOfTheVectorsAreReproduced() throws {
        let v = try vectors()
        let permit = try XCTUnwrap(OfflineChain.uuidBytes(try XCTUnwrap(v["permitId"] as? String)))
        let seed = try b64(v["chainSeed"])
        XCTAssertEqual(Hashing.hex(OfflineChain.seedHash(permitId: permit, chainSeed: seed)), v["seedHashHex"] as? String)
        let key = try P256.Signing.PublicKey(derRepresentation: Data(base64Encoded: try XCTUnwrap(v["installationPublicKeySpki"] as? String))!)
        let cases = try XCTUnwrap(v["cases"] as? [[String: Any]])
        var records = 0
        for item in cases {
            for raw in try XCTUnwrap(item["items"] as? [[String: Any]]) {
                let record = OfflineChain.record(
                    permitId: permit, seq: UInt32(truncating: raw["seq"] as! NSNumber), bootCount: UInt32(truncating: raw["bootCount"] as! NSNumber),
                    elapsedNanos: UInt64(truncating: raw["elapsedRealtimeNanos"] as! NSNumber),
                    wallMillis: UInt64(truncating: raw["wallClockMillis"] as! NSNumber),
                    operationDigest: try b64(raw["operationDigest"]), prevHash: try b64(raw["prevHash"]))
                XCTAssertEqual(Hashing.hex(record), raw["recordHex"] as? String, "\(item["id"]!) seq \(raw["seq"]!)")
                XCTAssertEqual(OfflineChain.hash(of: record), try b64(raw["hash"]))
                let signature = try P256.Signing.ECDSASignature(derRepresentation: try b64(raw["signature"]))
                XCTAssertTrue(key.isValidSignature(signature, for: record), "\(item["id"]!) seq \(raw["seq"]!) signature")
                records += 1
            }
        }
        XCTAssertGreaterThan(records, 10)
    }

    // MARK: - The client's seal

    private final class Clock: @unchecked Sendable {
        let lock = NSLock()
        var wall = Date(timeIntervalSince1970: 1_793_866_200) // 2026-11-05T08:30:00Z
        var elapsed: UInt64 = 600_000_000_000
        var session: String? = "boot-A"
        func advance(_ seconds: Double) { lock.withLock { wall += seconds; elapsed += UInt64(seconds * 1e9) } }
        var clocks: OfflineClocks {
            OfflineClocks(wall: { self.lock.withLock { self.wall } }, elapsedNanos: { self.lock.withLock { self.elapsed } },
                          bootSession: { self.lock.withLock { self.session } })
        }
    }

    private final class MemoryOffline: OfflineStateStore, @unchecked Sendable {
        var blobs: [String: Data] = [:]
        var failWrite = false
        func read(_ alias: String) throws -> Data? { blobs[alias] }
        func write(_ alias: String, _ data: Data) throws {
            if failWrite { throw SentomaruError.storageUnavailable }
            blobs[alias] = data
        }
        func delete(_ alias: String) throws { blobs[alias] = nil }
    }

    private var permitJson: Data {
        let seed = OfflineChain.base64URL(Data(1...32)) // synthetic
        return Data("""
        {"permitId":"6f1c0000-0000-4000-8000-00000000d026","chainSeed":"\(seed)",
         "issuedAt":"2026-11-05T08:00:00Z","validUntil":"2026-11-06T08:00:00Z","maxItems":3,"driftToleranceSeconds":120}
        """.utf8)
    }

    private func sealer(_ clock: Clock, _ store: MemoryOffline = MemoryOffline()) throws -> (OfflineSealer, SoftwareKeys, MemoryOffline) {
        let keys = SoftwareKeys()
        _ = try keys.generate("alias")
        return (OfflineSealer(keys: keys, store: store, clocks: clock.clocks), keys, store)
    }

    private func digest(_ n: UInt8) -> Data { Data(repeating: n, count: 32) }

    func testSealsChainInOrderAndVerifyWithTheInstallationKey() throws {
        let clock = Clock()
        let (sealer, keys, _) = try sealer(clock)
        let permit = try OfflinePermit.parse(permitJson)
        var seals: [OfflineSeal] = []
        for n in 0..<3 {
            seals.append(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(UInt8(n))))
            clock.advance(60)
        }
        XCTAssertEqual(seals.map(\.seq), [0, 1, 2])
        XCTAssertEqual(seals[0].prevHash, OfflineChain.seedHash(permitId: OfflineChain.uuidBytes(permit.permitId)!, chainSeed: permit.chainSeed))
        XCTAssertEqual(seals[1].prevHash, seals[0].hash)
        XCTAssertEqual(seals[2].prevHash, seals[1].hash)
        let key = try P256.Signing.PublicKey(derRepresentation: try keys.publicKey("alias"))
        for seal in seals {
            let record = OfflineChain.record(permitId: OfflineChain.uuidBytes(permit.permitId)!, seq: seal.seq, bootCount: seal.bootCount,
                                             elapsedNanos: seal.elapsedRealtimeNanos, wallMillis: seal.wallClockMillis,
                                             operationDigest: seal.operationDigest, prevHash: seal.prevHash)
            XCTAssertEqual(OfflineChain.hash(of: record), seal.hash)
            XCTAssertTrue(key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: seal.signature), for: record))
            XCTAssertEqual(seal.bootCount, 1)
        }
        XCTAssertEqual(seals[1].wallClockMillis - seals[0].wallClockMillis, 60_000)
        XCTAssertEqual(seals[1].elapsedRealtimeNanos - seals[0].elapsedRealtimeNanos, 60_000_000_000)
    }

    func testTheChainSurvivesTheStoreAndARebootCountsUp() throws {
        let clock = Clock()
        let (first, _, store) = try sealer(clock)
        let permit = try OfflinePermit.parse(permitJson)
        let a = try first.seal(alias: "alias", permit: permit, operationDigest: digest(1))
        clock.session = "boot-B"
        clock.lock.withLock { clock.elapsed = 5_000_000_000 } // the monotonic clock restarts at boot
        clock.advance(10)
        let again = OfflineSealer(keys: first.keys, store: store, clocks: clock.clocks) // a new process, same storage
        let b = try again.seal(alias: "alias", permit: permit, operationDigest: digest(2))
        XCTAssertEqual(b.seq, 1)
        XCTAssertEqual(b.prevHash, a.hash)
        XCTAssertEqual(a.bootCount, 1)
        XCTAssertEqual(b.bootCount, 2)
    }

    func testPermitLimitsAndRefusalsNeverProduceASeal() throws {
        let clock = Clock()
        let (sealer, _, store) = try sealer(clock)
        let permit = try OfflinePermit.parse(permitJson)
        XCTAssertThrowsError(try sealer.seal(alias: "alias", permit: permit, operationDigest: Data(count: 31))) {
            XCTAssertEqual($0 as? OfflineError, .invalidDigest)
        }
        for n in 0..<3 { _ = try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(UInt8(n))) }
        XCTAssertThrowsError(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(9))) {
            XCTAssertEqual($0 as? OfflineError, .chainFull)
        }
        clock.advance(25 * 3600)
        XCTAssertThrowsError(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(9))) {
            XCTAssertEqual($0 as? OfflineError, .permitExpired)
        }
        XCTAssertNotNil(store.blobs["alias"])
    }

    func testAStorageFailureConsumesNoSequenceNumber() throws {
        let clock = Clock()
        let (sealer, _, store) = try sealer(clock)
        let permit = try OfflinePermit.parse(permitJson)
        store.failWrite = true
        XCTAssertThrowsError(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(1))) {
            XCTAssertEqual($0 as? SentomaruError, .storageUnavailable)
        }
        store.failWrite = false
        XCTAssertEqual(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(1)).seq, 0)
    }

    func testWithoutABootSessionTheCountIsUnavailableAndCannotChangeMidPermit() throws {
        let clock = Clock()
        clock.session = nil
        let (sealer, _, _) = try sealer(clock)
        let permit = try OfflinePermit.parse(permitJson)
        XCTAssertEqual(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(1)).bootCount, OfflineChain.unavailableBootCount)
        clock.session = "boot-A"
        XCTAssertThrowsError(try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(2))) {
            XCTAssertEqual($0 as? OfflineError, .clockUnavailable)
        }
    }

    func testOnlyTheNewestPermitsAreRemembered() throws {
        let clock = Clock()
        let (sealer, _, store) = try sealer(clock)
        for n in 1...6 {
            let id = "6f1c0000-0000-4000-8000-0000000000\(String(format: "%02d", n))"
            let permit = try OfflinePermit(permitId: id, chainSeed: Data(count: 32), issuedAt: clock.wall - 60, validUntil: clock.wall + 3600,
                                           maxItems: 5, driftToleranceSeconds: 120)
            _ = try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(1))
        }
        let state = try JSONDecoder().decode(OfflineSealer.State.self, from: try XCTUnwrap(store.blobs["alias"]))
        XCTAssertEqual(state.chains.count, OfflineSealer.State.keepPermits)
    }

    func testTheLiveClocksAnswerOnThisHost() throws {
        let live = OfflineClocks.live
        let a = live.elapsedNanos()
        let b = live.elapsedNanos()
        XCTAssertGreaterThan(a, 0)
        XCTAssertGreaterThanOrEqual(b, a)
        let session = try XCTUnwrap(live.bootSession(), "kern.bootsessionuuid")
        XCTAssertNotNil(UUID(uuidString: session))
        XCTAssertEqual(live.bootSession(), session)
    }

    // MARK: - Permit and body

    func testThePermitResponseIsParsedStrictly() throws {
        let permit = try OfflinePermit.parse(permitJson)
        XCTAssertEqual(permit.maxItems, 3)
        XCTAssertEqual(permit.chainSeed.count, 32)
        for bad in [#"{}"#, #"{"permitId":"x"}"#, permitJson.string.replacingOccurrences(of: "\"maxItems\":3", with: "\"maxItems\":500"),
                    permitJson.string.replacingOccurrences(of: "\"chainSeed\":\"A", with: "\"chainSeed\":\"=")] {
            XCTAssertThrowsError(try OfflinePermit.parse(Data(bad.utf8))) { XCTAssertEqual($0 as? OfflineError, .permitInvalid) }
        }
    }

    func testTheReconciliationBodyCarriesTheSealsInOrder() throws {
        let clock = Clock()
        let (sealer, _, _) = try sealer(clock)
        let permit = try OfflinePermit.parse(permitJson)
        let seals = try (0..<2).map { try sealer.seal(alias: "alias", permit: permit, operationDigest: digest(UInt8($0))) }
        let body = try OfflineRequests.reconcileBody(permit: permit, seals: seals)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(object["permitId"] as? String, permit.permitId)
        let items = try XCTUnwrap(object["items"] as? [[String: Any]])
        XCTAssertEqual(items.map { $0["seq"] as? Int }, [0, 1])
        XCTAssertEqual(Set(items[0].keys), ["seq", "bootCount", "elapsedRealtimeNanos", "wallClockMillis", "operationDigest", "prevHash", "hash", "signature"])
        XCTAssertEqual(items[1]["prevHash"] as? String, OfflineChain.base64URL(seals[0].hash))
        XCTAssertThrowsError(try OfflineRequests.reconcileBody(permit: permit, seals: []))
        XCTAssertThrowsError(try OfflineRequests.reconcileBody(permit: permit, seals: seals + seals))
    }
}

private extension Data { var string: String { String(decoding: self, as: UTF8.self) } }
