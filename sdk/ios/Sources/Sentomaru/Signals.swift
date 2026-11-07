import Foundation
#if canImport(Darwin)
import Darwin
#endif
#if canImport(MachO)
import MachO
#endif
#if canImport(UIKit) && os(iOS)
import UIKit
#endif

/// D-10e: observation states of the signals catalog (`contracts/sdk/signals-catalog-v1.json`), with the server's wire
/// names. Local observation only; never an authorization. `STALE` is the server's and is never declared here.
public enum SignalState: String, Sendable, CaseIterable {
    case detected = "DETECTED"
    case notDetected = "NOT_DETECTED"
    case unknown = "UNKNOWN"
    case unsupported = "UNSUPPORTED"
    case error = "ERROR"
}

/// One observation of a catalog capability, `client_observed` (decision E5). Evadable: an instrumented process can
/// rewrite any value before the installation key signs it. `notDetected` means "not detected in this collection", never a
/// clean device. `detail` carries fixed codes and the OS version only: no path, identifier or personal data.
public struct SignalObservation: Sendable, Equatable {
    public let capabilityId: String
    public let version: String
    public let state: SignalState
    public let source: String
    public let observedAt: Date
    public let detail: [String: String]

    /// Capabilities whose catalog `version` is not 1.0.0 (`SignalsTests.testIdsVersionsAndStatesAreTheCatalogs` keeps this equal to the
    /// catalog): `screen_capture` 1.1.0 (catalog 1.15.0, Android scope `all`), `synthetic_input` 1.1.0 (D-27).
    static let capabilityVersions = ["screen_capture": "1.1.0", "synthetic_input": "1.1.0"]

    init(_ capabilityId: String, _ state: SignalState, at observedAt: Date, detail: [String: String] = [:]) {
        self.capabilityId = capabilityId
        version = Self.capabilityVersions[capabilityId] ?? "1.0.0"
        self.state = state
        source = "client_observed"
        self.observedAt = observedAt
        self.detail = detail
    }
}

/// D-10e: a signals snapshot in the wire format the server validates (`signals-observation-schema-v1.json`), the value of
/// the `x-sentomaru-signals` header. The SDK signs that header when present (H3, `Profile.optionalHeaders`): the signature
/// proves the snapshot left the process that holds the key unchanged, not that its values are true.
public struct SignalsSnapshot: Sendable, Equatable {
    /// Catalog version the observations follow (the catalog JSON `version`). 1.7.0 declared `ios` in
    /// `supportedPlatforms` of the four capabilities this collector answers with a value (`SignalsTests`).
    public static let catalogVersion = "1.15.0"
    /// The server refuses the whole forwarded message for a longer header value (`message-format`).
    public static let maxHeaderLength = 4096

    public let catalogVersion: String
    public let collectedAt: Date
    public let durationMs: Int
    public let observations: [SignalObservation]

    /// The JSON, members in a fixed order (as the Android SDK writes them), detail keys sorted, printable ASCII only
    /// (anything else escaped as `\uXXXX`), instants in UTC ISO-8601 with milliseconds.
    public func json() -> String {
        var out = "{\"catalogVersion\":" + Self.quote(catalogVersion)
        out += ",\"collectedAt\":" + Self.quote(Self.instant(collectedAt))
        out += ",\"durationMs\":\(max(0, durationMs)),\"observations\":["
        out += observations.map { o in
            "{\"capabilityId\":" + Self.quote(o.capabilityId) + ",\"version\":" + Self.quote(o.version) +
                ",\"state\":" + Self.quote(o.state.rawValue) + ",\"source\":" + Self.quote(o.source) +
                ",\"observedAt\":" + Self.quote(Self.instant(o.observedAt)) + ",\"detail\":{" +
                o.detail.keys.sorted().map { Self.quote($0) + ":" + Self.quote(o.detail[$0]!) }.joined(separator: ",") + "}}"
        }.joined(separator: ",")
        return out + "]}"
    }

    /// [json] as the header value; longer than `maxHeaderLength` = `InvalidRequest:HEADER_VALUE` (never cut).
    public func headerValue() throws -> String {
        let value = json()
        guard value.utf8.count <= Self.maxHeaderLength else { throw SentomaruError.invalidRequest(.HEADER_VALUE) }
        return value
    }

    static func instant(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: TimeZone(identifier: "UTC")!))
    }

    static func quote(_ text: String) -> String {
        var out = "\""
        for unit in text.utf16 {
            switch unit {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x20...0x7E: out.unicodeScalars.append(Unicode.Scalar(UInt8(unit)))
            default: out += String(format: "\\u%04x", unit)
            }
        }
        return out + "\""
    }
}

/// D-10e: what the iOS detectors read, as a port (tests replace it). `live` is the running process.
public struct SignalsEnvironment: Sendable {
    /// Where the code runs: an iPhone or iPad (`device`), the iOS simulator, or anything else, where the jailbreak checks
    /// mean nothing (`other`): the macOS host of `swift test`, a Mac Catalyst app and an iPhone/iPad app on a Mac with
    /// Apple silicon (review R M1: the Mac has /bin/bash and /usr/sbin/sshd, so `device` there would always be DETECTED).
    public enum Runtime: String, Sendable { case device, simulator, other }

    let runtime: Runtime
    /// `P_TRACED` of this process (`sysctl` `KERN_PROC_PID`); throws when the call fails.
    let isTraced: @Sendable () throws -> Bool
    let fileExists: @Sendable (String) -> Bool
    /// Whether a file could be created outside the app sandbox (it is removed right away).
    let canWriteOutsideSandbox: @Sendable () -> Bool
    /// Paths of the images loaded in this process (dyld).
    let loadedImages: @Sendable () -> [String]
    let platform: String
    let osVersion: @Sendable () -> String
    /// D-27: what the screens show right now, or nil when it cannot be read (not on the main thread, no UIKit).
    var screens: @Sendable () -> ScreenFacts? = { nil }

    /// D-27: public UIKit facts only. `captured`: any screen reports `isCaptured` (screen recording, mirroring, AirPlay);
    /// `screenCount`: `UIScreen.screens.count` (more than one = an external display). No screen name, id or app.
    struct ScreenFacts: Sendable, Equatable {
        let captured: Bool
        let screenCount: Int
    }

    public static let live = SignalsEnvironment(
        runtime: liveRuntime, isTraced: liveTraced, fileExists: { FileManager.default.fileExists(atPath: $0) },
        canWriteOutsideSandbox: liveWriteOutsideSandbox, loadedImages: liveImages, platform: livePlatform,
        osVersion: {
            let v = ProcessInfo.processInfo.operatingSystemVersion
            return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        }, screens: liveScreens)

    static var liveRuntime: Runtime {
        let info = ProcessInfo.processInfo
        return runtime(simulatorBuild: isSimulatorBuild, iOSBuild: isIOSBuild, onMac: info.isiOSAppOnMac || info.isMacCatalystApp)
    }

    /// `device` only for an iOS build (not the simulator) that is not running on a Mac.
    static func runtime(simulatorBuild: Bool, iOSBuild: Bool, onMac: Bool) -> Runtime {
        if simulatorBuild { return .simulator }
        return iOSBuild && !onMac ? .device : .other
    }

    static var isSimulatorBuild: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    /// UIKit is main-thread only: from another thread the answer is nil (the capability is UNKNOWN, `partial`), never a hop to
    /// the main queue (a caller that blocks the main thread would deadlock).
    @Sendable static func liveScreens() -> ScreenFacts? {
        #if canImport(UIKit) && os(iOS)
        guard Thread.isMainThread else { return nil }
        let screens = UIScreen.screens
        return ScreenFacts(captured: screens.contains { $0.isCaptured }, screenCount: screens.count)
        #else
        return nil
        #endif
    }

    static var isIOSBuild: Bool {
        #if os(iOS)
        return true
        #else
        return false
        #endif
    }

    static var livePlatform: String {
        #if os(iOS)
        return "ios"
        #elseif os(macOS)
        return "macos"
        #else
        return "other"
        #endif
    }

    struct SysctlFailed: Error {}

    @Sendable static func liveTraced() throws -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0, size > 0 else { throw SysctlFailed() }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    @Sendable static func liveWriteOutsideSandbox() -> Bool {
        let path = "/private/sentomaru-" + UUID().uuidString.lowercased()
        do {
            try Data("x".utf8).write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
        } catch {
            return false
        }
        try? FileManager.default.removeItem(atPath: path)
        return true
    }

    @Sendable static func liveImages() -> [String] {
        #if canImport(MachO)
        return (0..<_dyld_image_count()).compactMap { index in _dyld_get_image_name(index).map { String(cString: $0) } }
        #else
        return []
        #endif
    }
}

/// D-10e: collects the six capabilities of catalog 1.0.0 (the frozen ones the default policy reads) on iOS, and on request
/// the D-05 and D-12c ones as `UNSUPPORTED` (no iOS check exists for them). Same ids, versions and wire format as the
/// Android `SignalsCollector`; the catalog keeps no iOS-specific id. Catalog 1.7.0 listed `ios` in `supportedPlatforms`
/// of `debug_attached`, `emulator_detected`, `root_indicated` and `os_version` only (the others have no value here).
///
/// | capability | iOS |
/// |---|---|
/// | `debug_attached` | `P_TRACED` by `sysctl`: `DETECTED`/`NOT_DETECTED`, `ERROR` when the call fails |
/// | `emulator_detected` | simulator build: `DETECTED`; device: `NOT_DETECTED`; elsewhere (Mac included) `UNKNOWN` |
/// | `root_indicated` | device only: jailbreak paths, write outside the sandbox, hooking libraries loaded, the result kept 60 s; simulator and elsewhere `UNKNOWN` |
/// | `app_signing_digest` | `UNSUPPORTED` (no signing certificate readable on iOS) |
/// | `installer_source` | `UNKNOWN` `reason=not_applicable` (no installer package on iOS) |
/// | `os_version` | `DETECTED` with `platform` and `release` |
///
/// Runs on the calling thread, never blocks and never throws: a check that fails costs only its capability (`ERROR` or
/// `UNKNOWN`). The `root_indicated` checks on a device (21 paths, a write attempt outside the sandbox that the system
/// logs as a sandbox violation, the dyld image list) run at most once per `RootCheckCache.ttl` per process (review R M3). No URL scheme query (it would need UIKit, the main thread and
/// `LSApplicationQueriesSchemes`).
public struct SignalsCollector: Sendable {
    /// The catalog 1.0.0 capabilities, in the Android `defaultDetectors()` order.
    public static let defaultCapabilityIds = [
        "debug_attached", "emulator_detected", "root_indicated", "app_signing_digest", "installer_source", "os_version",
    ]
    /// D-05 capabilities (catalog 1.3.0): `UNSUPPORTED` on iOS.
    public static let raspCapabilityIds = [
        "debugger_attached", "app_debuggable", "dev_settings_enabled", "root_artifacts", "emulator_indicated",
        "hook_framework_java",
    ]
    /// D-12c capabilities (catalog 1.5.0): `UNSUPPORTED` on iOS.
    public static let appIntegrityCapabilityIds = ["app_signer_mismatch", "installer_class", "code_integrity"]
    /// D-20/D-27 consultive screen capabilities (catalog 1.12.0), opt-in: `screen_shared` is read from `UIScreen`;
    /// `screen_capture` is `UNSUPPORTED` (iOS gives no per-screen capture callback; a screenshot is reported after the fact).
    public static let screenCapabilityIds = ["screen_capture", "screen_shared"]

    /// Well-known jailbreak artifacts (rootful and rootless). Only their presence is reported, never which one.
    static let jailbreakPaths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app", "/Applications/blackra1n.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/lib/libsubstitute.dylib", "/usr/lib/libhooker.dylib", "/usr/libexec/cydia", "/usr/sbin/sshd",
        "/usr/bin/sshd", "/bin/bash", "/etc/apt", "/private/var/lib/apt", "/private/var/lib/cydia",
        "/private/var/stash", "/var/jb", "/var/binpack", "/private/preboot/jb", "/.bootstrapped", "/.installed_unc0ver",
    ]

    /// Fragments (lowercase) of hooking libraries injected by jailbreak tweaks or instrumentation.
    static let hookingImageMarkers = [
        "mobilesubstrate", "substrateloader", "substrateinserter", "libsubstitute", "libhooker", "tweakinject",
        "cynject", "frida", "libellekit", "systemhook", "sslkillswitch",
    ]

    let environment: SignalsEnvironment
    let now: @Sendable () -> Date
    let rootCache: RootCheckCache

    /// The live environment; the `root_indicated` result is shared by every collector of the process.
    public init() {
        self.init(environment: .live, now: { Date() }, rootCache: .shared)
    }

    init(environment: SignalsEnvironment, now: @escaping @Sendable () -> Date, rootCache: RootCheckCache = RootCheckCache()) {
        self.environment = environment
        self.now = now
        self.rootCache = rootCache
    }

    /// The six catalog 1.0.0 observations; with `rasp`, the D-05 ids, and with `appIntegrity`, the D-12c ids, as
    /// `UNSUPPORTED` (the Flutter plugin's `collectSignalsSnapshot(rasp:, appIntegrity:)` on iOS). Each `observedAt` is
    /// the instant its own check really ran: a `root_indicated` from the cache keeps the instant of its check, up to
    /// `RootCheckCache.ttl` (60 s) before `collectedAt`, well inside the server's 300 s freshness (`SignalsValidator`
    /// marks STALE by each `observedAt`, never by `collectedAt`). `collectedAt` is the start of this call.
    /// `durationMs` comes from the wall clock (`Date`, no boot-time API), not a monotonic clock: a clock change during
    /// the call can skew it; it is never negative.
    public func snapshot(rasp: Bool = false, appIntegrity: Bool = false, screen: Bool = false) -> SignalsSnapshot {
        let collectedAt = now()
        var observations = defaultObservations()
        let extra = (rasp ? Self.raspCapabilityIds : []) + (appIntegrity ? Self.appIntegrityCapabilityIds : [])
        let at = now()
        observations += extra.map { SignalObservation($0, .unsupported, at: at) }
        if screen {
            observations.append(SignalObservation("screen_capture", .unsupported, at: now()))
            observations.append(screenShared())
        }
        let elapsed = now().timeIntervalSince(collectedAt)
        return SignalsSnapshot(catalogVersion: SignalsSnapshot.catalogVersion, collectedAt: collectedAt,
                               durationMs: max(0, Int((elapsed * 1000).rounded(.down))), observations: observations)
    }

    func defaultObservations() -> [SignalObservation] {
        [debugAttached(), emulatorDetected(), rootIndicated(), appSigningDigest(), installerSource(), osVersion()]
    }

    func debugAttached() -> SignalObservation {
        let at = now()
        do {
            let traced = try environment.isTraced()
            return SignalObservation("debug_attached", traced ? .detected : .notDetected, at: at,
                                     detail: ["debugger_connected": String(traced)])
        } catch {
            return SignalObservation("debug_attached", .error, at: at)
        }
    }

    func emulatorDetected() -> SignalObservation {
        let at = now()
        switch environment.runtime {
        case .simulator: return SignalObservation("emulator_detected", .detected, at: at, detail: ["matched_indicators": "simulator"])
        case .device: return SignalObservation("emulator_detected", .notDetected, at: at, detail: ["matched_indicators": "none"])
        case .other: return SignalObservation("emulator_detected", .unknown, at: at, detail: ["reason": "not_ios_device"])
        }
    }

    func rootIndicated() -> SignalObservation {
        let at = now()
        switch environment.runtime {
        case .simulator:
            // The simulator sees the Mac's file system (/bin/bash, /usr/sbin/sshd): the checks would always fire.
            return SignalObservation("root_indicated", .unknown, at: at, detail: ["reason": "simulator"])
        case .other:
            return SignalObservation("root_indicated", .unknown, at: at, detail: ["reason": "not_ios_device"])
        case .device:
            return rootCache.observation(now: at) {
                let path = Self.jailbreakPaths.contains(where: environment.fileExists)
                let write = environment.canWriteOutsideSandbox()
                let images = environment.loadedImages().contains { image in
                    let lower = image.lowercased()
                    return Self.hookingImageMarkers.contains { lower.contains($0) }
                }
                return SignalObservation("root_indicated", path || write || images ? .detected : .notDetected, at: at,
                                         detail: ["jb_path": String(path), "sandbox_write": String(write),
                                                  "hooking_library": String(images)])
            }
        }
    }

    /// D-27 (consultive): the screen may be shown or recorded outside the device. Indicators `secondary_display`
    /// (`UIScreen.screens.count > 1`) and `screen_recording` (a screen with `isCaptured`: recording, mirroring or AirPlay).
    /// Read on the main thread only; elsewhere or off an iPhone/iPad it is UNKNOWN, never NOT_DETECTED. Fixed codes only.
    func screenShared() -> SignalObservation {
        let at = now()
        guard environment.runtime != .other else {
            return SignalObservation("screen_shared", .unknown, at: at, detail: ["indicators": "none", "partial": "not_ios_device"])
        }
        guard let facts = environment.screens() else {
            return SignalObservation("screen_shared", .unknown, at: at, detail: ["indicators": "none", "partial": "display"])
        }
        var found: [String] = []
        if facts.screenCount > 1 { found.append("secondary_display") }
        if facts.captured { found.append("screen_recording") }
        return SignalObservation("screen_shared", found.isEmpty ? .notDetected : .detected, at: at,
                                 detail: ["indicators": found.isEmpty ? "none" : found.joined(separator: ",")])
    }

    func appSigningDigest() -> SignalObservation {
        SignalObservation("app_signing_digest", .unsupported, at: now())
    }

    func installerSource() -> SignalObservation {
        SignalObservation("installer_source", .unknown, at: now(), detail: ["reason": "not_applicable"])
    }

    func osVersion() -> SignalObservation {
        SignalObservation("os_version", .detected, at: now(),
                          detail: ["platform": environment.platform, "release": environment.osVersion()])
    }
}

/// Review R M3: the last `root_indicated` of a device, reused for `ttl` seconds. The observation keeps the instant of its
/// real check (never re-stamped), so its age reaches the server as it is. A clock that went back (negative age) or an
/// expired entry runs the checks again; two concurrent misses may both run them (harmless).
final class RootCheckCache: @unchecked Sendable {
    static let ttl: TimeInterval = 60
    static let shared = RootCheckCache()

    private let lock = NSLock()
    private var held: SignalObservation?

    func observation(now: Date, compute: () -> SignalObservation) -> SignalObservation {
        if let held = lock.withLock({ held }) {
            let age = now.timeIntervalSince(held.observedAt)
            if age >= 0 && age < Self.ttl { return held }
        }
        let fresh = compute()
        lock.withLock { held = fresh }
        return fresh
    }
}
