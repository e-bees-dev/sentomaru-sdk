import Foundation
import Security

/// Where the SDK keeps its Keychain items. Every item is a generic password with
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and not synchronizable: it never leaves this device (no iCloud
/// Keychain, no encrypted backup restore onto another device).
public struct KeychainLocation: @unchecked Sendable {
    public let service: String
    /// Extra attributes for `SecItemAdd` (where the item goes).
    let addAttributes: [String: Any]
    /// Extra attributes for queries, updates and deletes (where items are looked up).
    let queryAttributes: [String: Any]

    /// The data protection Keychain (iOS; on macOS it needs the app's keychain entitlement).
    public static func dataProtection(service: String) -> KeychainLocation {
        KeychainLocation(service: service, addAttributes: [kSecUseDataProtectionKeychain as String: true],
                         queryAttributes: [kSecUseDataProtectionKeychain as String: true])
    }

    #if os(macOS)
    /// Test-only (macOS host): a file keychain created by the test, so `swift test` never touches the user's keychains.
    static func file(_ keychain: SecKeychain, service: String) -> KeychainLocation {
        KeychainLocation(service: service, addAttributes: [kSecUseKeychain as String: keychain],
                         queryAttributes: [kSecMatchSearchList as String: [keychain]])
    }
    #endif
}

/// Generic-password items of one `KeychainLocation`, keyed by account. Errors are `storageUnavailable`.
struct KeychainItems: Sendable {
    let location: KeychainLocation
    static let maxItemBytes = 256 * 1024

    private func base(_ account: String? = nil) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: location.service,
                                    kSecAttrSynchronizable as String: false]
        if let account { query[kSecAttrAccount as String] = account }
        return query
    }

    func get(_ account: String) throws -> Data? {
        var query = base(account).merging(location.queryAttributes) { $1 }
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data, data.count <= Self.maxItemBytes else {
            throw SentomaruError.storageUnavailable
        }
        return data
    }

    func set(_ account: String, _ data: Data) throws {
        let query = base(account).merging(location.queryAttributes) { $1 }
        let status = SecItemUpdate(query as CFDictionary, updateAttributes(data) as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw SentomaruError.storageUnavailable }
        guard SecItemAdd(addAttributes(account, data) as CFDictionary, nil) == errSecSuccess else {
            throw SentomaruError.storageUnavailable
        }
    }

    /// What `set` adds: the item, never synchronizable, readable after the first unlock and only on this device.
    func addAttributes(_ account: String, _ data: Data) -> [String: Any] {
        var add = base(account).merging(location.addAttributes) { $1 }
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return add
    }

    /// What `set` changes on an existing item (the accessibility class is rewritten too).
    func updateAttributes(_ data: Data) -> [String: Any] {
        [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
    }

    func delete(_ account: String) throws {
        let status = SecItemDelete(base(account).merging(location.queryAttributes) { $1 } as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SentomaruError.storageUnavailable }
    }

    func accounts() throws -> [String] {
        var query = base().merging(location.queryAttributes) { $1 }
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = out as? [[String: Any]] else { throw SentomaruError.storageUnavailable }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }
}

/// The installation record as one Keychain item (account = the scope identity), JSON-encoded.
public struct KeychainInstallationStore: InstallationStore {
    public static let defaultService = "br.com.ebees.sentomaru.installation"
    let items: KeychainItems
    let account: String

    /// Production store for `config` in the data protection Keychain.
    public init(config: SentomaruConfig, service: String = KeychainInstallationStore.defaultService) {
        self.init(location: .dataProtection(service: service), account: config.identity)
    }

    init(location: KeychainLocation, account: String) {
        self.items = KeychainItems(location: location)
        self.account = account
    }

    public func read() throws -> InstallationRecord? {
        guard let data = try items.get(account) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        guard let record = try? decoder.decode(InstallationRecord.self, from: data),
              record.version == InstallationRecord.currentVersion else { throw SentomaruError.keyInvalidated }
        return record
    }

    public func write(_ record: InstallationRecord?) throws {
        guard let record else { return try items.delete(account) }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(record) else { throw SentomaruError.storageUnavailable }
        try items.set(account, data)
    }
}
