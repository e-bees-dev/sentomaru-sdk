import Compression
import CryptoKit
import Foundation
import XCTest

/// Matrix of the shared vectors: a Swift reader of contracts/devsecops/sealed-v1-vectors.json, written from the contract
/// (cli-v1.md, "Formato selado v1" and "Leitura") and checked against the same positive and negative cases as the Kotlin reader, the
/// Dart plugin, the Python reference and the C# reader. Test-only: nothing in the iOS SDK reads sealed assets (the format is Android and
/// Flutter-on-Android today); this closes the matrix row so an iOS reader that ever exists already has a reference that agrees. Raw
/// DEFLATE comes from Apple's Compression (COMPRESSION_ZLIB is raw DEFLATE), capped at declared + 1 bytes, with the exact end of the
/// stream (COMPRESSION_STATUS_END and no input left) required.
final class SealedVectorsTests: XCTestCase {
    private static let dir = "assets/sentomaru/sealed/"
    private static let maxFile = 4 * 1024 * 1024
    private static let maxHeader = 5 + 16 + 12 + 16 + 32 + 512
    private static let maxEntry = 37 + maxFile + 4096
    private static let kFmt = Data(SHA256.hash(data: Data("Sentomaru sealed assets format v1 public constant".utf8)))

    private struct SealedError: Error, Equatable { let code: String }

    private static func hex(_ text: String) -> Data {
        var out = Data()
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            out.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private static func hexString(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    private static func nameOf(_ path: String) -> String {
        dir + hexString(Data(SHA256.hash(data: Data(path.utf8)))) + ".bin"
    }

    private static func hkdf(_ ikm: Data, _ salt: Data, _ info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: Data(info.utf8), outputByteCount: 32)
    }

    private func vectors() throws -> [String: Any] {
        let url = AppAttestVectorTests.repositoryRoot.appendingPathComponent("contracts/devsecops/sealed-v1-vectors.json")
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    /// The contract's reader over a {entry name: bytes} view of the installed base module (no plain fallback).
    private final class Reader {
        let entries: [String: Data]
        let package: String
        let versionCode: Int
        var aeadRuns = 0
        var inflateCaps: [Int] = []
        private var cached: (dek: Data, strings: String?)?

        init(_ entries: [String: Data], package: String, versionCode: Int) {
            self.entries = entries
            self.package = package
            self.versionCode = versionCode
        }

        private func open(_ key: SymmetricKey, nonce: Data, sealed: Data, aad: String) throws -> Data {
            aeadRuns += 1
            guard sealed.count >= 16 else { throw SealedError(code: "integrity") }
            do {
                let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: sealed.prefix(sealed.count - 16),
                                                tag: sealed.suffix(16))
                return try AES.GCM.open(box, using: key, authenticating: Data(aad.utf8))
            } catch { throw SealedError(code: "integrity") }
        }

        func header() throws -> (dek: Data, strings: String?) {
            if let cached { return cached }
            guard let data = entries[SealedVectorsTests.dir + "header.bin"] else { throw SealedError(code: "not-sealed") }
            let bytes = [UInt8](data)
            guard bytes.count >= 5, Array(bytes[0..<4]) == Array("SNTS".utf8), bytes[4] == 1 else { throw SealedError(code: "format-unsupported") }
            guard bytes.count >= 5 + 16 + 12 + 32 + 16, bytes.count <= SealedVectorsTests.maxHeader else { throw SealedError(code: "integrity") }
            let kek = SealedVectorsTests.hkdf(SealedVectorsTests.kFmt, Data(bytes[5..<21]), "sentomaru-sealed-v1|\(package)|\(versionCode)")
            let plain = try open(kek, nonce: Data(bytes[21..<33]), sealed: Data(bytes[33...]), aad: "header|v1|\(package)|\(versionCode)")
            guard let text = String(data: plain.dropFirst(32), encoding: .utf8) else { throw SealedError(code: "integrity") }
            let result = (dek: Data(plain.prefix(32)), strings: text.isEmpty ? nil : text)
            cached = result
            return result
        }

        func bytes(_ path: String) throws -> Data {
            let (dek, _) = try header()
            guard let data = entries[SealedVectorsTests.nameOf(path)] else { throw SealedError(code: "not-sealed") }
            let b = [UInt8](data)
            guard b.count >= 5, Array(b[0..<4]) == Array("SNTA".utf8), b[4] == 1 else { throw SealedError(code: "format-unsupported") }
            guard b.count >= 5 + 4 + 12 + 16, b.count <= SealedVectorsTests.maxEntry else { throw SealedError(code: "integrity") }
            let length = Int(b[5]) << 24 | Int(b[6]) << 16 | Int(b[7]) << 8 | Int(b[8])
            guard length <= SealedVectorsTests.maxFile else { throw SealedError(code: "integrity") }
            let key = SealedVectorsTests.hkdf(dek, Data(), "asset|\(path)")
            let deflated = try open(key, nonce: Data(b[9..<21]), sealed: Data(b[21...]), aad: "asset|v1|\(package)|\(versionCode)|\(path)")
            return try inflate(deflated, length: length)
        }

        private func inflate(_ deflated: Data, length: Int) throws -> Data {
            inflateCaps.append(length + 1)
            let capacity = length + 1
            var output = [UInt8](repeating: 0, count: max(capacity, 1))
            let input = [UInt8](deflated)
            let scratch = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
            defer { scratch.deallocate() }
            let seed = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!, dst_size: 0,
                                          src_ptr: UnsafePointer<UInt8>(bitPattern: 1)!, src_size: 0, state: nil)
            scratch.initialize(to: seed)
            guard compression_stream_init(scratch, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
                throw SealedError(code: "integrity")
            }
            defer { compression_stream_destroy(scratch) }
            // Fed one byte at a time (plus one sentinel past the data), the decoder has taken exactly the bytes it needed when it
            // reports END: bytes left over are trailing data, a sentinel taken means the stream was cut short.
            var produced = 0
            var consumed = 0
            var ended = false
            let fed = input + [0xFF]
            output.withUnsafeMutableBufferPointer { dst in
                scratch.pointee.dst_ptr = dst.baseAddress!
                scratch.pointee.dst_size = dst.count
                for byte in fed {
                    var one = byte
                    withUnsafePointer(to: &one) { pointer in
                        scratch.pointee.src_ptr = pointer
                        scratch.pointee.src_size = 1
                        let status = compression_stream_process(scratch, 0)
                        consumed += 1 - scratch.pointee.src_size
                        produced = dst.count - scratch.pointee.dst_size
                        ended = status == COMPRESSION_STATUS_END
                        if status == COMPRESSION_STATUS_ERROR { consumed = Int.max }
                    }
                    if ended || consumed == Int.max || scratch.pointee.dst_size == 0 { break }
                }
            }
            guard ended, consumed == input.count, produced == length else { throw SealedError(code: "integrity") }
            return Data(output.prefix(length))
        }

        func string(_ key: String) throws -> String? {
            let (_, strings) = try header()
            guard let path = strings else { throw SealedError(code: "not-sealed") }
            guard let object = try? JSONSerialization.jsonObject(with: try bytes(path)), let values = object as? [String: Any],
                  values.values.allSatisfy({ $0 is String }) else { throw SealedError(code: "integrity") }
            return values[key] as? String
        }
    }

    private func entries(of vector: [String: Any]) -> [String: Data] {
        let header = vector["header"] as! [String: Any]
        var out = [header["entry"] as! String: Self.hex(header["sealedHex"] as! String)]
        for file in vector["files"] as! [[String: Any]] { out[file["sealedEntry"] as! String] = Self.hex(file["sealedHex"] as! String) }
        return out
    }

    private func mutated(_ vector: [String: Any], _ spec: [String: Any]) -> [String: Data] {
        var out = entries(of: vector)
        guard let target = spec["target"] as? String else { return out }
        let name = target == "header" ? (vector["header"] as! [String: Any])["entry"] as! String : Self.nameOf(target)
        let op = spec["op"] as! [String: Any]
        var data = [UInt8](out[name]!)
        func index(_ raw: Int) -> Int { raw < 0 ? raw + data.count : raw }
        switch op["kind"] as! String {
        case "delete": out[name] = nil; return out
        case "move": out[Self.nameOf(op["to"] as! String)] = out.removeValue(forKey: name); return out
        case "xor": data[index(op["offset"] as! Int)] ^= UInt8(op["value"] as! Int)
        case "set":
            let patch = [UInt8](Self.hex(op["hex"] as! String))
            let at = index(op["offset"] as! Int)
            data.replaceSubrange(at..<min(at + patch.count, data.count), with: patch)
        case "truncate": data = Array(data.prefix(op["length"] as! Int))
        case "pad": data += [UInt8](repeating: 0, count: op["length"] as! Int)
        case "replace": data = [UInt8](Self.hex(op["hex"] as! String))
        default: XCTFail("unknown op")
        }
        out[name] = Data(data)
        return out
    }

    func testKFmtIsThePublishedConstantAndHkdfReproducesRfc5869() throws {
        let v = try vectors()
        XCTAssertEqual(Self.hexString(Self.kFmt), (v["kFmt"] as! [String: Any])["hex"] as? String)
        let cases = v["hkdfRfc5869"] as! [[String: Any]]
        XCTAssertEqual(cases.count, 3)
        for c in cases {
            let salt = Self.hex(c["saltHex"] as! String)
            let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Self.hex(c["ikmHex"] as! String)),
                                             salt: salt, info: Self.hex(c["infoHex"] as! String), outputByteCount: c["length"] as! Int)
            XCTAssertEqual(key.withUnsafeBytes { Self.hexString(Data($0)) }, c["okmHex"] as? String)
        }
    }

    func testEveryPositiveCaseOpensToItsPlaintextAndItsStrings() throws {
        var files = 0
        for vector in try vectors()["cases"] as! [[String: Any]] {
            let reader = Reader(entries(of: vector), package: vector["package"] as! String, versionCode: vector["versionCode"] as! Int)
            for file in vector["files"] as! [[String: Any]] {
                files += 1
                XCTAssertEqual(Self.hexString(try reader.bytes(file["path"] as! String)), file["plainHex"] as? String)
            }
            for lookup in vector["lookups"] as! [[String: Any]] {
                XCTAssertEqual(try reader.string(lookup["key"] as! String), lookup["value"] as? String)
            }
            if (vector["header"] as! [String: Any])["stringsPath"] is NSNull {
                XCTAssertThrowsError(try reader.string("qualquer")) { XCTAssertEqual(($0 as? SealedError)?.code, "not-sealed") }
            }
        }
        XCTAssertGreaterThanOrEqual(files, 4)
    }

    func testEveryNegativeCaseFailsWithTheListedErrorByTheRuleItNames() throws {
        let v = try vectors()
        let cases = Dictionary(uniqueKeysWithValues: (v["cases"] as! [[String: Any]]).map { ($0["name"] as! String, $0) })
        let negatives = v["negative"] as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(negatives.count, 31)
        for spec in negatives {
            let name = spec["name"] as! String
            let vector = cases[spec["case"] as! String]!
            let other = spec["as"] as? [String: Any]
            let reader = Reader(mutated(vector, spec), package: other?["package"] as? String ?? vector["package"] as! String,
                                versionCode: other?["versionCode"] as? Int ?? vector["versionCode"] as! Int)
            let probe = spec["probe"] as? String
            if probe != nil, spec["target"] as? String != "header" { _ = try reader.header() }
            let before = reader.aeadRuns
            do {
                if let read = spec["read"] as? [String: Any] { _ = try reader.string(read["string"] as! String) }
                else { _ = try reader.bytes(spec["read"] as! String) }
                XCTFail("\(name): no error")
            } catch let error as SealedError {
                XCTAssertEqual(error.code, spec["error"] as? String, name)
            } catch { XCTFail("\(name): \(error)") }
            if probe == "before-aead" { XCTAssertEqual(reader.aeadRuns, before, "\(name): AEAD ran before the size check") }
            if probe == "inflate-cap" { XCTAssertEqual(reader.inflateCaps, [101], name) }
        }
    }
}
