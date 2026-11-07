import Foundation
@testable import Sentomaru
@testable import SentomaruCore
import XCTest

/// D-10e: the iOS signals (catalog 1.0.0 ids) and the signed `x-sentomaru-signals` header.
final class SignalsTests: XCTestCase {
    static let instant = Date(timeIntervalSince1970: 1_793_275_200) // 2026-10-29T12:00:00Z

    /// A device (or simulator) whose checks answer what the test says; `probed` records the paths looked at.
    final class Probe: @unchecked Sendable {
        let lock = NSLock()
        var paths: [String] = []
        var writes = 0
    }

    static func environment(_ runtime: SignalsEnvironment.Runtime = .device, traced: Result<Bool, Error> = .success(false),
                            paths: Set<String> = [], write: Bool = false, images: [String] = ["/usr/lib/libSystem.B.dylib"],
                            os: String = "18.1.0", probe: Probe = Probe(),
                            screens: SignalsEnvironment.ScreenFacts? = nil) -> SignalsEnvironment {
        SignalsEnvironment(runtime: runtime, isTraced: { try traced.get() },
                           fileExists: { path in probe.lock.withLock { probe.paths.append(path) }; return paths.contains(path) },
                           canWriteOutsideSandbox: { probe.lock.withLock { probe.writes += 1 }; return write },
                           loadedImages: { images }, platform: "ios", osVersion: { os }, screens: { screens })
    }

    static func collector(_ environment: SignalsEnvironment) -> SignalsCollector {
        SignalsCollector(environment: environment, now: { instant })
    }

    func states(_ snapshot: SignalsSnapshot) -> [String: SignalState] {
        Dictionary(uniqueKeysWithValues: snapshot.observations.map { ($0.capabilityId, $0.state) })
    }

    func observation(_ snapshot: SignalsSnapshot, _ id: String) throws -> SignalObservation {
        try XCTUnwrap(snapshot.observations.first { $0.capabilityId == id })
    }

    // MARK: - Detectors

    func testCleanDeviceGivesTheSixCatalogIdsInTheAndroidOrder() throws {
        let snapshot = Self.collector(Self.environment()).snapshot()
        XCTAssertEqual(snapshot.observations.map(\.capabilityId), SignalsCollector.defaultCapabilityIds)
        XCTAssertEqual(states(snapshot), [
            "debug_attached": .notDetected, "emulator_detected": .notDetected, "root_indicated": .notDetected,
            "app_signing_digest": .unsupported, "installer_source": .unknown, "os_version": .detected,
        ])
        XCTAssertEqual(snapshot.catalogVersion, "1.15.0")
        XCTAssertTrue(snapshot.observations.allSatisfy { $0.version == "1.0.0" && $0.source == "client_observed" })
        XCTAssertEqual(try observation(snapshot, "debug_attached").detail, ["debugger_connected": "false"])
        XCTAssertEqual(try observation(snapshot, "emulator_detected").detail, ["matched_indicators": "none"])
        XCTAssertEqual(try observation(snapshot, "root_indicated").detail,
                       ["jb_path": "false", "sandbox_write": "false", "hooking_library": "false"])
        XCTAssertEqual(try observation(snapshot, "app_signing_digest").detail, [:])
        XCTAssertEqual(try observation(snapshot, "installer_source").detail, ["reason": "not_applicable"])
        XCTAssertEqual(try observation(snapshot, "os_version").detail, ["platform": "ios", "release": "18.1.0"])
    }

    // MARK: - D-27 screens (opt-in)

    func testScreenSharedReadsPublicScreenFacts() throws {
        func shared(_ facts: SignalsEnvironment.ScreenFacts?, _ runtime: SignalsEnvironment.Runtime = .device) throws -> SignalObservation {
            try observation(Self.collector(Self.environment(runtime, screens: facts)).snapshot(screen: true), "screen_shared")
        }
        let none = try shared(.init(captured: false, screenCount: 1))
        XCTAssertEqual(none.state, .notDetected); XCTAssertEqual(none.detail, ["indicators": "none"])
        let external = try shared(.init(captured: false, screenCount: 2))
        XCTAssertEqual(external.state, .detected); XCTAssertEqual(external.detail, ["indicators": "secondary_display"])
        let recording = try shared(.init(captured: true, screenCount: 1))
        XCTAssertEqual(recording.detail, ["indicators": "screen_recording"])
        let both = try shared(.init(captured: true, screenCount: 3))
        XCTAssertEqual(both.detail, ["indicators": "secondary_display,screen_recording"])
        let off = try shared(nil) // not on the main thread, or no UIKit: never "clean"
        XCTAssertEqual(off.state, .unknown); XCTAssertEqual(off.detail, ["indicators": "none", "partial": "display"])
        let mac = try shared(.init(captured: false, screenCount: 1), .other)
        XCTAssertEqual(mac.state, .unknown); XCTAssertEqual(mac.detail, ["indicators": "none", "partial": "not_ios_device"])
    }

    func testScreenCaptureIsUnsupportedAndScreenIsOptIn() throws {
        let c = Self.collector(Self.environment(screens: .init(captured: false, screenCount: 1)))
        XCTAssertEqual(c.snapshot().observations.map(\.capabilityId), SignalsCollector.defaultCapabilityIds)
        let on = c.snapshot(rasp: true, appIntegrity: true, screen: true)
        XCTAssertEqual(try observation(on, "screen_capture").state, .unsupported)
        XCTAssertEqual(on.observations.suffix(2).map(\.capabilityId), SignalsCollector.screenCapabilityIds)
        let text = on.json()
        XCTAssertFalse(text.contains("UIScreen") || text.contains("\"name\""))
    }

    func testDebuggerAttachedAndSysctlFailure() throws {
        let traced = Self.collector(Self.environment(traced: .success(true))).snapshot()
        XCTAssertEqual(try observation(traced, "debug_attached").state, .detected)
        XCTAssertEqual(try observation(traced, "debug_attached").detail, ["debugger_connected": "true"])
        struct Failed: Error {}
        let failed = Self.collector(Self.environment(traced: .failure(Failed()))).snapshot()
        XCTAssertEqual(try observation(failed, "debug_attached").state, .error, "catalog: no UNKNOWN for debug_attached")
        XCTAssertEqual(try observation(failed, "debug_attached").detail, [:])
        XCTAssertEqual(failed.observations.count, 6, "a failed check costs only its capability")
    }

    func testEachJailbreakIndicatorAloneIsDetected() throws {
        let cases: [(SignalsEnvironment, String)] = [
            (Self.environment(paths: ["/var/jb"]), "jb_path"),
            (Self.environment(paths: ["/Applications/Cydia.app"]), "jb_path"),
            (Self.environment(write: true), "sandbox_write"),
            (Self.environment(images: ["/usr/lib/libSystem.B.dylib", "/usr/lib/TweakInject/x.dylib"]), "hooking_library"),
            (Self.environment(images: ["/private/var/containers/Bundle/Application/X/App.app/Frameworks/FridaGadget.dylib"]), "hooking_library"),
        ]
        for (environment, indicator) in cases {
            let root = try observation(Self.collector(environment).snapshot(), "root_indicated")
            XCTAssertEqual(root.state, .detected, indicator)
            XCTAssertEqual(root.detail[indicator], "true", indicator)
            XCTAssertEqual(root.detail.values.filter { $0 == "true" }.count, 1, "fixed codes only, never the path")
        }
    }

    func testSimulatorIsAnEmulatorAndRootIsNotChecked() throws {
        let probe = Probe()
        let snapshot = Self.collector(Self.environment(.simulator, paths: ["/bin/bash"], write: true, probe: probe)).snapshot()
        XCTAssertEqual(try observation(snapshot, "emulator_detected").state, .detected)
        XCTAssertEqual(try observation(snapshot, "emulator_detected").detail, ["matched_indicators": "simulator"])
        let root = try observation(snapshot, "root_indicated")
        XCTAssertEqual(root.state, .unknown, "the simulator sees the Mac's /bin/bash: never DETECTED nor clean")
        XCTAssertEqual(root.detail, ["reason": "simulator"])
        XCTAssertTrue(probe.paths.isEmpty)
        XCTAssertEqual(probe.writes, 0, "no write attempt outside a device")
    }

    func testOtherRuntimeIsUnknownForEmulatorAndRoot() throws {
        let snapshot = Self.collector(Self.environment(.other)).snapshot()
        XCTAssertEqual(try observation(snapshot, "emulator_detected").state, .unknown)
        XCTAssertEqual(try observation(snapshot, "root_indicated").state, .unknown)
        XCTAssertEqual(try observation(snapshot, "root_indicated").detail, ["reason": "not_ios_device"])
        XCTAssertEqual(try observation(snapshot, "emulator_detected").detail, ["reason": "not_ios_device"])
    }

    /// Review R M1: an iPhone/iPad app on a Mac (Apple silicon) and a Mac Catalyst app are never `device`: the Mac has
    /// /bin/bash and /usr/sbin/sshd, and `root_indicated` would always be DETECTED there.
    func testIOSAppOnAMacIsNotADevice() throws {
        XCTAssertEqual(SignalsEnvironment.runtime(simulatorBuild: false, iOSBuild: true, onMac: false), .device)
        XCTAssertEqual(SignalsEnvironment.runtime(simulatorBuild: false, iOSBuild: true, onMac: true), .other)
        XCTAssertEqual(SignalsEnvironment.runtime(simulatorBuild: false, iOSBuild: false, onMac: false), .other)
        XCTAssertEqual(SignalsEnvironment.runtime(simulatorBuild: true, iOSBuild: true, onMac: true), .simulator)
        // What a Mac run reads: /bin/bash present, yet root_indicated is UNKNOWN, never DETECTED.
        let probe = Probe()
        let mac = Self.collector(Self.environment(SignalsEnvironment.runtime(simulatorBuild: false, iOSBuild: true, onMac: true),
                                                  paths: ["/bin/bash", "/usr/sbin/sshd"], probe: probe)).snapshot()
        XCTAssertEqual(try observation(mac, "root_indicated").state, .unknown)
        XCTAssertEqual(try observation(mac, "root_indicated").detail, ["reason": "not_ios_device"])
        XCTAssertTrue(probe.paths.isEmpty)
        #if os(macOS)
        XCTAssertEqual(SignalsEnvironment.liveRuntime, .other)
        #endif
    }

    /// Review R M3: on a device the root checks run once per 60 s; the cached observation keeps the instant of its real
    /// check (never re-stamped), so its age stays honest and within the server's 300 s.
    func testRootCheckIsCachedForSixtySeconds() throws {
        let clock = TestClock(Self.instant)
        let probe = Probe()
        let collector = SignalsCollector(environment: Self.environment(probe: probe), now: clock.function)
        let first = try observation(collector.snapshot(), "root_indicated")
        XCTAssertEqual(probe.writes, 1)
        clock.advance(59)
        let cached = collector.snapshot()
        XCTAssertEqual(probe.writes, 1, "no second write attempt inside 60 s")
        XCTAssertEqual(try observation(cached, "root_indicated"), first)
        XCTAssertEqual(try observation(cached, "root_indicated").observedAt, Self.instant)
        XCTAssertEqual(cached.collectedAt, Self.instant.addingTimeInterval(59), "collectedAt is this collection")
        XCTAssertEqual(try observation(cached, "debug_attached").observedAt, Self.instant.addingTimeInterval(59))
        clock.advance(1)
        XCTAssertEqual(try observation(collector.snapshot(), "root_indicated").observedAt, Self.instant.addingTimeInterval(60))
        XCTAssertEqual(probe.writes, 2, "checked again at 60 s")
        clock.advance(-10)
        _ = collector.snapshot()
        XCTAssertEqual(probe.writes, 3, "a clock that went back runs the checks again")
        // Another collector has its own cache in tests; the public init shares the process one.
        XCTAssertTrue(SignalsCollector().rootCache === SignalsCollector().rootCache)
    }

    /// Cost of the device checks with the real file system and dyld of the host (macOS; the write outside the sandbox
    /// is refused there as on a device): printed, not asserted (timing is not stable on a shared runner). A benchmark
    /// that calls the real `canWriteOutsideSandbox`: runs only with `SENTOMARU_BENCH=1`, and never as root (where the
    /// write to /private would succeed).
    func testRootCheckCostOnTheHost() throws {
        guard ProcessInfo.processInfo.environment["SENTOMARU_BENCH"] == "1" else {
            throw XCTSkip("benchmark: set SENTOMARU_BENCH=1")
        }
        guard getuid() != 0 else { throw XCTSkip("benchmark refused as root (the write outside the sandbox would succeed)") }
        let live = SignalsEnvironment.live
        let device = SignalsEnvironment(runtime: .device, isTraced: live.isTraced, fileExists: live.fileExists,
                                        canWriteOutsideSandbox: live.canWriteOutsideSandbox, loadedImages: live.loadedImages,
                                        platform: live.platform, osVersion: live.osVersion)
        var uncached: [Double] = []
        for _ in 0..<20 {
            let collector = SignalsCollector(environment: device, now: { Date() })
            let start = DispatchTime.now().uptimeNanoseconds
            _ = collector.snapshot()
            uncached.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1e6)
        }
        let collector = SignalsCollector(environment: device, now: { Date() })
        _ = collector.snapshot()
        let start = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<20 { _ = collector.snapshot() }
        let cached = Double(DispatchTime.now().uptimeNanoseconds - start) / 1e6 / 20
        uncached.sort()
        print(String(format: "D-10e cost (host): uncached median %.3f ms, max %.3f ms; cached %.3f ms",
                     uncached[10], uncached[19], cached))
    }

    func testRaspAndAppIntegrityIdsAreUnsupported() throws {
        let snapshot = Self.collector(Self.environment()).snapshot(rasp: true, appIntegrity: true)
        XCTAssertEqual(snapshot.observations.map(\.capabilityId),
                       SignalsCollector.defaultCapabilityIds + SignalsCollector.raspCapabilityIds + SignalsCollector.appIntegrityCapabilityIds)
        for id in SignalsCollector.raspCapabilityIds + SignalsCollector.appIntegrityCapabilityIds {
            XCTAssertEqual(try observation(snapshot, id).state, .unsupported, id)
            XCTAssertEqual(try observation(snapshot, id).detail, [:], id)
        }
        XCTAssertLessThan(try snapshot.headerValue().utf8.count, SignalsSnapshot.maxHeaderLength, "all 15 ids fit the header")
        XCTAssertEqual(Self.collector(Self.environment()).snapshot(rasp: true).observations.count, 12)
        XCTAssertEqual(Self.collector(Self.environment()).snapshot(appIntegrity: true).observations.count, 9)
    }

    /// The host of `swift test` is `other`: the live checks run (sysctl, dyld) and answer, but never DETECTED for root.
    func testLiveEnvironmentOnTheHost() throws {
        let snapshot = SignalsCollector().snapshot()
        XCTAssertEqual(snapshot.observations.map(\.capabilityId), SignalsCollector.defaultCapabilityIds)
        XCTAssertNotEqual(try observation(snapshot, "debug_attached").state, .error, "sysctl KERN_PROC_PID answers")
        XCTAssertFalse(SignalsEnvironment.liveImages().isEmpty)
        let os = try observation(snapshot, "os_version")
        XCTAssertEqual(os.state, .detected)
        XCTAssertNotNil(os.detail["release"]?.range(of: #"^\d+\.\d+\.\d+$"#, options: .regularExpression))
        #if os(macOS)
        XCTAssertEqual(try observation(snapshot, "root_indicated").state, .unknown)
        XCTAssertEqual(os.detail["platform"], "macos")
        #endif
        XCTAssertGreaterThanOrEqual(snapshot.durationMs, 0)
        XCTAssertTrue(snapshot.observations.allSatisfy { $0.observedAt >= snapshot.collectedAt })
    }

    // MARK: - Wire format

    /// The committed snapshot the server test (`IosSignalsSnapshotTests`) feeds to the validator and the policy engine.
    func testJsonMatchesTheSharedFixture() throws {
        let json = Self.collector(Self.environment()).snapshot().json()
        let fixture = AppAttestVectorTests.repositoryRoot.appendingPathComponent("verification/sdk/vectors/ios-signals-snapshot-v1.json")
        guard FileManager.default.fileExists(atPath: fixture.path) else { throw XCTSkip("repository file absent") }
        let committed = try String(contentsOf: fixture, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(json, committed)
    }

    func testJsonIsTheServerShape() throws {
        let json = Self.collector(Self.environment()).snapshot(rasp: true).json()
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["catalogVersion", "collectedAt", "durationMs", "observations"])
        XCTAssertEqual(object["collectedAt"] as? String, "2026-10-29T12:00:00.000Z")
        XCTAssertEqual(object["durationMs"] as? Int, 0)
        for item in try XCTUnwrap(object["observations"] as? [[String: Any]]) {
            XCTAssertEqual(Set(item.keys), ["capabilityId", "version", "state", "source", "observedAt", "detail"])
            XCTAssertNotNil((item["capabilityId"] as? String)?.range(of: "^[a-z0-9_]{3,32}$", options: .regularExpression))
            XCTAssertNotNil(item["detail"] as? [String: String])
        }
    }

    func testJsonIsPrintableAsciiAndEscaped() throws {
        let snapshot = Self.collector(Self.environment(os: "18.1 \"β\"\n\\")).snapshot()
        let json = snapshot.json()
        XCTAssertTrue(json.utf8.allSatisfy { (0x20...0x7E).contains($0) })
        XCTAssertTrue(json.contains("\"release\":\"18.1 \\\"\\u03b2\\\"\\u000a\\\\\""), json)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let os = try XCTUnwrap((object["observations"] as? [[String: Any]])?.last?["detail"] as? [String: String])
        XCTAssertEqual(os["release"], "18.1 \"β\"\n\\")
    }

    func testOverlongHeaderIsRefusedNeverCut() {
        let snapshot = Self.collector(Self.environment(os: String(repeating: "9", count: SignalsSnapshot.maxHeaderLength))).snapshot()
        XCTAssertThrowsError(try snapshot.headerValue()) { XCTAssertEqual($0 as? SentomaruError, .invalidRequest(.HEADER_VALUE)) }
    }

    /// Every id the collector sends is a client capability of the contract catalog with the same version, and every
    /// state it may give is in that capability's `supportedStates` (the server would read another one as UNKNOWN for
    /// the non-frozen ids).
    func testIdsVersionsAndStatesAreTheCatalogs() throws {
        let url = AppAttestVectorTests.repositoryRoot.appendingPathComponent("contracts/sdk/signals-catalog-v1.json")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("repository file absent") }
        let catalog = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        XCTAssertEqual(catalog["version"] as? String, SignalsSnapshot.catalogVersion)
        var entries: [String: [String: Any]] = [:]
        for entry in try XCTUnwrap(catalog["capabilities"] as? [[String: Any]]) { entries[entry["capabilityId"] as! String] = entry }
        struct Failed: Error {}
        let environments = [
            Self.environment(), Self.environment(traced: .success(true), paths: ["/var/jb"]),
            Self.environment(traced: .failure(Failed())), Self.environment(.simulator), Self.environment(.other),
        ]
        for environment in environments {
            for o in Self.collector(environment).snapshot(rasp: true, appIntegrity: true, screen: true).observations {
                let entry = try XCTUnwrap(entries[o.capabilityId], o.capabilityId)
                XCTAssertEqual(entry["source"] as? String, "client_observed", o.capabilityId)
                XCTAssertEqual(entry["version"] as? String, o.version, o.capabilityId)
                XCTAssertTrue((entry["supportedStates"] as? [String] ?? []).contains(o.state.rawValue), "\(o.capabilityId) \(o.state)")
            }
        }
    }

    /// Catalog 1.7.0: `ios` is in `supportedPlatforms` exactly for the capabilities this collector answers with a value on
    /// an iPhone or iPad (`DETECTED`/`NOT_DETECTED`, or `ERROR` when the check fails); the ids it always answers
    /// `UNSUPPORTED`, or `UNKNOWN` `reason=not_applicable`, do not declare it. `minIosVersion` is the package's iOS 15.
    func testIosPlatformIsDeclaredExactlyWhereTheCollectorHasAValue() throws {
        let url = AppAttestVectorTests.repositoryRoot.appendingPathComponent("contracts/sdk/signals-catalog-v1.json")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("repository file absent") }
        let catalog = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        var declared: Set<String> = []
        for entry in try XCTUnwrap(catalog["capabilities"] as? [[String: Any]]) {
            let id = try XCTUnwrap(entry["capabilityId"] as? String)
            guard (entry["supportedPlatforms"] as? [String] ?? []).contains("ios") else {
                XCTAssertNil(entry["minIosVersion"], id)
                continue
            }
            declared.insert(id)
            XCTAssertEqual(entry["minIosVersion"] as? String, "15.0", id)
        }
        let package = try String(contentsOf: AppAttestVectorTests.repositoryRoot.appendingPathComponent("sdk/ios/Package.swift"),
                                 encoding: .utf8)
        XCTAssertTrue(package.contains(".iOS(.v15)"))
        XCTAssertEqual(declared, ["debug_attached", "emulator_detected", "root_indicated", "os_version", "screen_shared"])
        XCTAssertTrue(declared.isSubset(of: Set(SignalsCollector.defaultCapabilityIds + ["screen_shared"]))) // D-27: opt-in screen_shared
        let screens = SignalsEnvironment.ScreenFacts(captured: false, screenCount: 1)
        let devices = [Self.environment(screens: screens), Self.environment(traced: .success(true), paths: ["/var/jb"], screens: screens)]
        for environment in devices {
            for o in Self.collector(environment).snapshot(rasp: true, appIntegrity: true, screen: true).observations {
                let noValue = o.state == .unsupported || (o.state == .unknown && o.detail["reason"] == "not_applicable")
                XCTAssertEqual(declared.contains(o.capabilityId), !noValue, "\(o.capabilityId) \(o.state)")
            }
        }
    }
}

/// D-10e: `SentomaruURLSession` signs the snapshot in `x-sentomaru-signals` (H3).
final class SignedSignalsTests: XCTestCase {
    var server: FakeServer!
    var client: SentomaruClient!

    override func setUp() async throws {
        let config = try SentomaruConfig(organization: "org-a", app: "app-a", environment: "hml", allowedHosts: ["consumer.example"],
                                         enrollmentUrl: "https://consumer.example/v1/org-a/app-a/hml/installations")
        let appAttest = FakeAppAttest()
        server = FakeServer(config: config, appAttest: appAttest)
        client = SentomaruClient(config: config, keys: SoftwareKeys(), store: MemoryStore(), appAttest: appAttest, now: { Date() })
        let challenge = try server.challenge(now: Date())
        let server = self.server!
        _ = try await client.enroll(challenge) { try await server.enroll($0) }
    }

    func helper(_ signals: SignalsCollector?) -> SentomaruURLSession {
        SentomaruURLSession(client: client, transport: SentomaruTransport(allowedHosts: ["consumer.example"]), signals: signals)
    }

    func request() -> URLRequest {
        var request = URLRequest(url: URL(string: "https://consumer.example/api/demandas")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{\"a\":1}".utf8)
        return request
    }

    /// Verifies the request's signature with the installation key; returns the covered components.
    func verify(_ signed: URLRequest) throws -> [String] {
        let headers = (signed.allHTTPHeaderFields ?? [:]).map { (name: $0.key.lowercased(), value: $0.value) }
        let message = SignedMessage(method: try XCTUnwrap(signed.httpMethod), targetURI: try XCTUnwrap(signed.url?.absoluteString),
                                    headers: headers, body: signed.httpBody ?? Data(), signatureBase: Data())
        let spki = try XCTUnwrap(server.installations.values.first?.spki)
        return try FakeServer.verifySignature(message, spki: spki).components
    }

    func testSnapshotIsCollectedAndSigned() async throws {
        let collector = SignalsCollector(environment: SignalsTests.environment(), now: { Date() })
        let signed = try await helper(collector).signed(request(), operation: "criar_demanda")
        let value = try XCTUnwrap(signed.value(forHTTPHeaderField: "x-sentomaru-signals"))
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(value.utf8)) as? [String: Any])
        let ids = (object["observations"] as? [[String: Any]])?.compactMap { $0["capabilityId"] as? String }
        XCTAssertEqual(ids, SignalsCollector.defaultCapabilityIds)
        XCTAssertEqual(try verify(signed).last, "x-sentomaru-signals", "covered after the profile components")
    }

    /// Review R M2: off by default, like the Android OkHttp interceptor; `SignalsCollector()` turns it on.
    func testDefaultHelperSendsNoSnapshotAndTheLiveCollectorSendsOne() async throws {
        let off = try await SentomaruURLSession(client: client, transport: SentomaruTransport(allowedHosts: ["consumer.example"]))
            .signed(request(), operation: "criar_demanda")
        XCTAssertNil(off.value(forHTTPHeaderField: "x-sentomaru-signals"))
        XCTAssertFalse(try verify(off).contains("x-sentomaru-signals"))
        let on = try await helper(SignalsCollector()).signed(request(), operation: "criar_demanda")
        XCTAssertNotNil(on.value(forHTTPHeaderField: "x-sentomaru-signals"))
        XCTAssertTrue(try verify(on).contains("x-sentomaru-signals"))
    }

    func testEachSignatureCollectsAnew() async throws {
        let clock = TestClock(Date())
        let collector = SignalsCollector(environment: SignalsTests.environment(), now: clock.function)
        let helper = helper(collector)
        let first = try await helper.signed(request(), operation: "criar_demanda").value(forHTTPHeaderField: "x-sentomaru-signals")
        clock.advance(2)
        let second = try await helper.signed(request(), operation: "criar_demanda").value(forHTTPHeaderField: "x-sentomaru-signals")
        XCTAssertNotEqual(first, second, "fresh observedAt per signature")
    }

    func testCallerSnapshotWinsAndNilCollectorSendsNone() async throws {
        var mine = request()
        mine.setValue("{\"catalogVersion\":\"1.6.0\",\"collectedAt\":\"2026-10-29T12:00:00Z\",\"durationMs\":0,\"observations\":[]}",
                      forHTTPHeaderField: "x-sentomaru-signals")
        let kept = try await helper(SignalsCollector()).signed(mine, operation: "o")
        XCTAssertEqual(kept.value(forHTTPHeaderField: "x-sentomaru-signals"), mine.value(forHTTPHeaderField: "x-sentomaru-signals"))
        XCTAssertTrue(try verify(kept).contains("x-sentomaru-signals"))

        let none = try await helper(nil).signed(request(), operation: "o")
        XCTAssertNil(none.value(forHTTPHeaderField: "x-sentomaru-signals"))
        XCTAssertFalse(try verify(none).contains("x-sentomaru-signals"))
    }
}
