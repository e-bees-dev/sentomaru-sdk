using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Sentomaru.Hybrid.Tests;

/// <summary>
/// D-14 / matrix of the shared vectors: a C# reader of contracts/devsecops/sealed-v1-vectors.json, written from the contract
/// (cli-v1.md, "Formato selado v1" and "Leitura") and checked against the same positive and negative cases as the Kotlin SDK
/// reader, the Dart plugin and the Python reference. Test-only: nothing in the C# product reads sealed assets; this closes the matrix row
/// so a C# host (MAUI, Unity) that ever does has a reader that already agrees. Every positive case opens to its plaintext; every
/// negative case fails with the listed error and, where the vector names a probe, by the rule it names.
/// </summary>
public class SealedVectorsTests
{
    private static readonly JsonElement Vectors = Load();
    private const string SealedDir = "assets/sentomaru/sealed/";
    private const int MaxFile = 4 * 1024 * 1024;
    private const int MaxHeader = 5 + 16 + 12 + 16 + 32 + 512;
    private const int MaxEntry = 37 + MaxFile + 4096;
    private static readonly byte[] KFmt = Convert.FromHexString("d49d16621c97d973d3d27ade53b09e223c5a07297beb57df176fe4827a498921");

    private static JsonElement Load()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "contracts/devsecops/sealed-v1-vectors.json"))) dir = Path.GetDirectoryName(dir);
        return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!, "contracts/devsecops/sealed-v1-vectors.json"))).RootElement.Clone();
    }

    private sealed class SealedError(string code) : Exception(code) { public string Code { get; } = code; }

    /// <summary>The contract's reader over a {entry name: bytes} view of the installed base module (no plain fallback).</summary>
    private sealed class Reader(IReadOnlyDictionary<string, byte[]> entries, string package, int versionCode)
    {
        public int AeadRuns { get; private set; }
        public List<int> InflateCaps { get; } = [];
        private (byte[] Dek, string? Strings)? header;

        private static string NameOf(string path) => SealedDir + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(path))) + ".bin";

        private static byte[] Hkdf(byte[] ikm, byte[] salt, string info) =>
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt, Encoding.UTF8.GetBytes(info));

        private byte[] Open(byte[] key, byte[] nonce, byte[] sealedBytes, string aad)
        {
            AeadRuns++;
            var plain = new byte[sealedBytes.Length - 16];
            try
            {
                using var gcm = new AesGcm(key, 16);
                gcm.Decrypt(nonce, sealedBytes.AsSpan(0, plain.Length), sealedBytes.AsSpan(plain.Length), plain, Encoding.UTF8.GetBytes(aad));
            }
            catch (CryptographicException) { throw new SealedError("integrity"); }
            return plain;
        }

        public (byte[] Dek, string? Strings) Header()
        {
            if (header is { } cached) return cached;
            if (!entries.TryGetValue(SealedDir + "header.bin", out var data)) throw new SealedError("not-sealed");
            if (data.Length < 5 || !data.AsSpan(0, 4).SequenceEqual("SNTS"u8) || data[4] != 1) throw new SealedError("format-unsupported");
            if (data.Length < 5 + 16 + 12 + 32 + 16 || data.Length > MaxHeader) throw new SealedError("integrity");
            var kek = Hkdf(KFmt, data[5..21], $"sentomaru-sealed-v1|{package}|{versionCode}");
            var plain = Open(kek, data[21..33], data[33..], $"header|v1|{package}|{versionCode}");
            string text;
            try { text = new UTF8Encoding(false, true).GetString(plain, 32, plain.Length - 32); }
            catch (DecoderFallbackException) { throw new SealedError("integrity"); }
            return (header = (plain[..32], text.Length == 0 ? null : text)).Value;
        }

        public byte[] Bytes(string path)
        {
            var (dek, _) = Header();
            if (!entries.TryGetValue(NameOf(path), out var data)) throw new SealedError("not-sealed");
            if (data.Length < 5 || !data.AsSpan(0, 4).SequenceEqual("SNTA"u8) || data[4] != 1) throw new SealedError("format-unsupported");
            if (data.Length < 5 + 4 + 12 + 16 || data.Length > MaxEntry) throw new SealedError("integrity");
            var length = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(5, 4));
            if (length > MaxFile) throw new SealedError("integrity");
            var key = Hkdf(dek, [], $"asset|{path}");
            var deflated = Open(key, data[9..21], data[21..], $"asset|v1|{package}|{versionCode}|{path}");
            return Inflate(deflated, (int)length);
        }

        /// <summary>Raw DEFLATE, asking for at most declared + 1 bytes; the stream must end exactly at the final block with nothing after.</summary>
        private byte[] Inflate(byte[] deflated, int length)
        {
            // One sentinel byte past the data: a complete stream never asks for it, a truncated one does (position then passes the end).
            var source = new OneByteAtATime([.. deflated, 0xFF]);
            var plain = new byte[length + 1];
            int total = 0;
            InflateCaps.Add(length + 1);
            try
            {
                using var inflate = new DeflateStream(source, CompressionMode.Decompress);
                while (total < plain.Length)
                {
                    var read = inflate.Read(plain, total, plain.Length - total);
                    if (read == 0) break;
                    total += read;
                }
                if (total == length && inflate.Read(new byte[1], 0, 1) != 0) throw new SealedError("integrity");
            }
            catch (InvalidDataException) { throw new SealedError("integrity"); }
            // Fed one byte at a time, the inflater has taken exactly the bytes it needed: bytes left over are trailing data.
            if (total != length || source.Position != deflated.Length) throw new SealedError("integrity");
            return plain[..length];
        }

        public string? String(string key)
        {
            var (_, strings) = Header();
            if (strings is null) throw new SealedError("not-sealed");
            Dictionary<string, JsonElement>? values;
            try { values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(new UTF8Encoding(false, true).GetString(Bytes(strings))); }
            catch (Exception e) when (e is JsonException or DecoderFallbackException) { throw new SealedError("integrity"); }
            if (values is null || values.Values.Any(v => v.ValueKind != JsonValueKind.String)) throw new SealedError("integrity");
            return values.TryGetValue(key, out var found) ? found.GetString() : null;
        }
    }

    /// <summary>Serves its bytes one at a time, so the position afterwards is what the inflater consumed.</summary>
    private sealed class OneByteAtATime(byte[] data) : Stream
    {
        public override long Position { get; set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count == 0 || Position >= data.Length) return 0;
            buffer[offset] = data[Position++];
            return 1;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static string NameOf(string path) => SealedDir + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(path))) + ".bin";

    private static Dictionary<string, byte[]> EntriesOf(JsonElement vector)
    {
        var entries = new Dictionary<string, byte[]> { [vector.GetProperty("header").GetProperty("entry").GetString()!] = Convert.FromHexString(vector.GetProperty("header").GetProperty("sealedHex").GetString()!) };
        foreach (var file in vector.GetProperty("files").EnumerateArray())
            entries[file.GetProperty("sealedEntry").GetString()!] = Convert.FromHexString(file.GetProperty("sealedHex").GetString()!);
        return entries;
    }

    private static Dictionary<string, byte[]> Mutated(JsonElement vector, JsonElement spec)
    {
        var entries = EntriesOf(vector);
        if (spec.GetProperty("target").ValueKind == JsonValueKind.Null) return entries;
        var target = spec.GetProperty("target").GetString()!;
        var name = target == "header" ? vector.GetProperty("header").GetProperty("entry").GetString()! : NameOf(target);
        var op = spec.GetProperty("op");
        var data = entries[name].ToList();
        switch (op.GetProperty("kind").GetString())
        {
            case "delete": entries.Remove(name); return entries;
            case "move": entries[NameOf(op.GetProperty("to").GetString()!)] = entries[name]; entries.Remove(name); return entries;
            case "xor":
                var index = op.GetProperty("offset").GetInt32();
                if (index < 0) index += data.Count;   // the vectors count a negative offset from the end
                data[index] ^= (byte)op.GetProperty("value").GetInt32();
                break;
            case "set":
                var patch = Convert.FromHexString(op.GetProperty("hex").GetString()!);
                var at = op.GetProperty("offset").GetInt32();
                if (at < 0) at += data.Count;   // a slice assignment: the patch replaces patch.Length bytes at the offset (or what is left)
                data.RemoveRange(at, Math.Min(patch.Length, data.Count - at));
                data.InsertRange(at, patch);
                break;
            case "truncate": data = data.Take(op.GetProperty("length").GetInt32()).ToList(); break;
            case "pad": data.AddRange(new byte[op.GetProperty("length").GetInt32()]); break;
            case "replace": data = Convert.FromHexString(op.GetProperty("hex").GetString()!).ToList(); break;
            default: throw new InvalidOperationException(op.ToString());
        }
        entries[name] = data.ToArray();
        return entries;
    }

    [Fact]
    public void KFmtIsThePublishedConstantAndHkdfReproducesRfc5869()
    {
        Assert.Equal(Convert.ToHexStringLower(KFmt), Vectors.GetProperty("kFmt").GetProperty("hex").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes("Sentomaru sealed assets format v1 public constant"))),
            Vectors.GetProperty("kFmt").GetProperty("hex").GetString());
        var count = 0;
        foreach (var v in Vectors.GetProperty("hkdfRfc5869").EnumerateArray())
        {
            count++;
            var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, Convert.FromHexString(v.GetProperty("ikmHex").GetString()!), v.GetProperty("length").GetInt32(),
                Convert.FromHexString(v.GetProperty("saltHex").GetString()!), Convert.FromHexString(v.GetProperty("infoHex").GetString()!));
            Assert.Equal(v.GetProperty("okmHex").GetString(), Convert.ToHexStringLower(okm));
        }
        Assert.Equal(3, count);
    }

    [Fact]
    public void EveryPositiveCaseOpensToItsPlaintextAndItsStrings()
    {
        var files = 0;
        foreach (var vector in Vectors.GetProperty("cases").EnumerateArray())
        {
            var reader = new Reader(EntriesOf(vector), vector.GetProperty("package").GetString()!, vector.GetProperty("versionCode").GetInt32());
            foreach (var file in vector.GetProperty("files").EnumerateArray())
            {
                files++;
                Assert.Equal(file.GetProperty("plainHex").GetString(), Convert.ToHexStringLower(reader.Bytes(file.GetProperty("path").GetString()!)));
            }
            foreach (var lookup in vector.GetProperty("lookups").EnumerateArray())
            {
                var want = lookup.GetProperty("value");
                Assert.Equal(want.ValueKind == JsonValueKind.Null ? null : want.GetString(), reader.String(lookup.GetProperty("key").GetString()!));
            }
            if (vector.GetProperty("header").GetProperty("stringsPath").ValueKind == JsonValueKind.Null)
                Assert.Equal("not-sealed", Assert.Throws<SealedError>(() => reader.String("qualquer")).Code);
        }
        Assert.True(files >= 4);
    }

    [Fact]
    public void EveryNegativeCaseFailsWithTheListedErrorByTheRuleItNames()
    {
        var cases = Vectors.GetProperty("cases").EnumerateArray().ToDictionary(c => c.GetProperty("name").GetString()!);
        var count = 0;
        foreach (var spec in Vectors.GetProperty("negative").EnumerateArray())
        {
            count++;
            var name = spec.GetProperty("name").GetString()!;
            var vector = cases[spec.GetProperty("case").GetString()!];
            var package = vector.GetProperty("package").GetString()!;
            var versionCode = vector.GetProperty("versionCode").GetInt32();
            if (spec.TryGetProperty("as", out var other))
            {
                if (other.TryGetProperty("package", out var p)) package = p.GetString()!;
                if (other.TryGetProperty("versionCode", out var v)) versionCode = v.GetInt32();
            }
            var reader = new Reader(Mutated(vector, spec), package, versionCode);
            var probe = spec.TryGetProperty("probe", out var pr) && pr.ValueKind == JsonValueKind.String ? pr.GetString() : null;
            if (probe is not null && spec.GetProperty("target").GetString() != "header") reader.Header();  // opened (and cached) first; the probe watches the entry
            var before = reader.AeadRuns;
            var read = spec.GetProperty("read");
            var thrown = Record.Exception(() =>
            {
                if (read.ValueKind == JsonValueKind.Object) reader.String(read.GetProperty("string").GetString()!);
                else reader.Bytes(read.GetString()!);
            });
            var error = (thrown as SealedError) ?? throw new Xunit.Sdk.XunitException($"{name}: {thrown?.GetType().Name ?? "no error"} {thrown?.Message}");
            Assert.True(spec.GetProperty("error").GetString() == error.Code, $"{name}: {error.Code}");
            if (probe == "before-aead") Assert.True(reader.AeadRuns == before, $"{name}: AEAD ran before the size check");
            if (probe == "inflate-cap") Assert.Equal([101], reader.InflateCaps);
        }
        Assert.True(count >= 31);
    }
}
