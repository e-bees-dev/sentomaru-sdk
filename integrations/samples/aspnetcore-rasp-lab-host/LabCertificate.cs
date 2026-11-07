using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RaspLabHost;

/// <summary>
/// A self-signed TLS certificate made in memory at each start (no file, no password). The SDK only signs https targets, so the
/// host speaks TLS; the instrumented test is given this certificate's SHA-256 (public) and trusts only that one for this host.
/// </summary>
public static class LabCertificate
{
    public static X509Certificate2 Create(IEnumerable<string> names, TimeProvider clock)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=rasp-lab-host", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in names)
            if (System.Net.IPAddress.TryParse(name, out var ip)) san.AddIpAddress(ip); else san.AddDnsName(name);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var now = clock.GetUtcNow();
        using var made = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(2));
        // Round trip through PKCS#12 so Kestrel gets a certificate with an exportable-free private key on every platform.
        return X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx), null);
    }

    public static string Sha256(X509Certificate2 certificate) => Convert.ToHexStringLower(certificate.GetCertHash(HashAlgorithmName.SHA256));
}
